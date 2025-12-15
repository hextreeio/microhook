/*
 * Microhook Coverage - DRCov coverage generation for QEMU linux-user
 *
 * Copyright (c) 2025 Thomas 'stacksmashing' Roth <code@stacksmashing.net>
 *
 * Generates DRCov format coverage files compatible with tools like
 * Lighthouse for coverage visualization in IDA Pro, Binary Ninja, etc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "microhook-coverage.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <libgen.h>

/* Flush coverage to disk every N new blocks */
#define COVERAGE_FLUSH_INTERVAL 100

/* DRCov basic block entry structure (8 bytes) */
typedef struct {
    uint32_t start;     /* Offset from module base */
    uint16_t size;      /* Size of basic block */
    uint16_t mod_id;    /* Module ID (always 0 for single binary) */
} __attribute__((packed)) drcov_bb_entry_t;

/* Internal block record */
typedef struct {
    uint64_t pc;        /* Guest virtual address */
    uint32_t size;      /* Block size in bytes */
} bb_record_t;

/* Global state */
static bool g_coverage_enabled = false;
static char *g_output_filename = NULL;
static char *g_filename_template = NULL;  /* Original template with %d/%s */
static GHashTable *g_blocks = NULL;     /* Hash table for deduplication: pc -> bb_record_t* */
static GMutex g_lock;
static unsigned long g_new_block_count = 0;  /* Counter for periodic flush */

/* Binary information */
static char *g_binary_path = NULL;
static char *g_binary_name = NULL;        /* basename of binary */
static uint64_t g_start_code = 0;
static uint64_t g_end_code = 0;
static uint64_t g_entry = 0;

/* Forward declaration */
static void microhook_coverage_flush_unlocked(void);

/*
 * Expand format specifiers in filename template:
 *   %d - current date+time (YYYY-MM-DD-HH:MM:SS)
 *   %s - program name (basename)
 *
 * Returns newly allocated string, caller must free.
 */
static char *expand_filename_template(const char *template, const char *progname)
{
    GString *result = g_string_new(NULL);
    const char *p = template;
    
    /* Get current time */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char datetime[32];
    strftime(datetime, sizeof(datetime), "%Y-%m-%d-%H:%M:%S", tm_info);
    
    /* Default program name if not provided */
    const char *prog = progname ? progname : "unknown";
    
    while (*p) {
        if (*p == '%' && *(p + 1)) {
            switch (*(p + 1)) {
            case 'd':
                g_string_append(result, datetime);
                p += 2;
                continue;
            case 's':
                g_string_append(result, prog);
                p += 2;
                continue;
            case '%':
                /* Escaped % */
                g_string_append_c(result, '%');
                p += 2;
                continue;
            default:
                /* Unknown specifier, keep as-is */
                break;
            }
        }
        g_string_append_c(result, *p);
        p++;
    }
    
    return g_string_free(result, FALSE);
}

int microhook_coverage_init(const char *filename)
{
    if (g_coverage_enabled) {
        fprintf(stderr, "microhook-coverage: already initialized\n");
        return -1;
    }

    g_mutex_init(&g_lock);

    /* Store filename template (will be expanded when binary info is set) */
    if (filename && *filename) {
        g_filename_template = g_strdup(filename);
    } else {
        g_filename_template = g_strdup("coverage.drcov");
    }
    
    /* Initial expansion without program name (will be updated in set_binary_info) */
    g_output_filename = expand_filename_template(g_filename_template, NULL);

    /* Create hash table for block deduplication */
    g_blocks = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                     NULL, g_free);
    if (!g_blocks) {
        fprintf(stderr, "microhook-coverage: failed to create hash table\n");
        g_free(g_output_filename);
        g_free(g_filename_template);
        g_output_filename = NULL;
        g_filename_template = NULL;
        return -1;
    }

    g_new_block_count = 0;
    g_coverage_enabled = true;
    fprintf(stderr, "microhook-coverage: initialized\n");
    return 0;
}

void microhook_coverage_set_binary_info(const char *path,
                                       uint64_t start_code,
                                       uint64_t end_code,
                                       uint64_t entry)
{
    g_mutex_lock(&g_lock);

    g_free(g_binary_path);
    g_binary_path = path ? g_strdup(path) : NULL;
    g_start_code = start_code;
    g_end_code = end_code;
    g_entry = entry;
    
    /* Extract basename for %s substitution */
    g_free(g_binary_name);
    if (path) {
        char *path_copy = g_strdup(path);
        g_binary_name = g_strdup(basename(path_copy));
        g_free(path_copy);
    } else {
        g_binary_name = NULL;
    }
    
    /* Re-expand filename template now that we have the program name */
    if (g_filename_template) {
        g_free(g_output_filename);
        g_output_filename = expand_filename_template(g_filename_template, g_binary_name);
        fprintf(stderr, "microhook-coverage: output file: %s\n", g_output_filename);
    }

    g_mutex_unlock(&g_lock);
}

bool microhook_coverage_enabled(void)
{
    return g_coverage_enabled;
}

void microhook_coverage_record_block(uint64_t pc, uint32_t size)
{
    if (!g_coverage_enabled || !g_blocks) {
        return;
    }

    g_mutex_lock(&g_lock);

    /* Check if block already recorded */
    if (!g_hash_table_contains(g_blocks, &pc)) {
        /* Create new record */
        bb_record_t *record = g_new(bb_record_t, 1);
        record->pc = pc;
        record->size = size;

        /* Insert into hash table (key is pointer to pc field in record) */
        g_hash_table_insert(g_blocks, &record->pc, record);

        /* Increment counter and flush periodically */
        g_new_block_count++;
        if (g_new_block_count >= COVERAGE_FLUSH_INTERVAL) {
            microhook_coverage_flush_unlocked();
            g_new_block_count = 0;
        }
    }

    g_mutex_unlock(&g_lock);
}

/* Helper to write binary data */
static void write_bb_entry(FILE *fp, const drcov_bb_entry_t *entry)
{
    fwrite(entry, sizeof(drcov_bb_entry_t), 1, fp);
}

/* Callback for iterating blocks and writing to file */
typedef struct {
    FILE *fp;
    uint64_t base;
    unsigned long count;
} write_context_t;

static void write_block_cb(gpointer key, gpointer value, gpointer user_data)
{
    (void)key;
    bb_record_t *record = (bb_record_t *)value;
    write_context_t *ctx = (write_context_t *)user_data;

    /* Only include blocks within the binary's code range */
    if (record->pc >= ctx->base && record->pc < g_end_code) {
        drcov_bb_entry_t entry;
        entry.start = (uint32_t)(record->pc - ctx->base);
        entry.size = (uint16_t)(record->size > 0xFFFF ? 0xFFFF : record->size);
        entry.mod_id = 0;

        write_bb_entry(ctx->fp, &entry);
        ctx->count++;
    }
}

static void count_block_cb(gpointer key, gpointer value, gpointer user_data)
{
    (void)key;
    bb_record_t *record = (bb_record_t *)value;
    unsigned long *count = (unsigned long *)user_data;
    uint64_t base = g_start_code;

    /* Only count blocks within the binary's code range */
    if (record->pc >= base && record->pc < g_end_code) {
        (*count)++;
    }
}

/*
 * Write current coverage to file (must be called with g_lock held).
 * This overwrites the file each time with all accumulated coverage.
 */
static void microhook_coverage_flush_unlocked(void)
{
    if (!g_coverage_enabled || !g_blocks || !g_output_filename) {
        return;
    }

    FILE *fp = fopen(g_output_filename, "wb");
    if (!fp) {
        fprintf(stderr, "microhook-coverage: failed to open output file: %s\n",
                g_output_filename);
        return;
    }

    /* Count blocks that will be included */
    unsigned long block_count = 0;
    g_hash_table_foreach(g_blocks, count_block_cb, &block_count);

    /* Write DRCov header (version 2 format for compatibility) */
    fprintf(fp, "DRCOV VERSION: 2\n");
    fprintf(fp, "DRCOV FLAVOR: drcov-64\n");
    fprintf(fp, "Module Table: version 2, count 1\n");
    fprintf(fp, "Columns: id, base, end, entry, path\n");

    /* Write module entry */
    const char *path = g_binary_path ? g_binary_path : "unknown";
    fprintf(fp, "0, 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", %s\n",
            g_start_code, g_end_code, g_entry, path);

    /* Write BB table header */
    fprintf(fp, "BB Table: %lu bbs\n", block_count);

    /* Write basic block entries in binary format */
    if (block_count > 0) {
        write_context_t ctx = {
            .fp = fp,
            .base = g_start_code,
            .count = 0
        };
        g_hash_table_foreach(g_blocks, write_block_cb, &ctx);
    }

    fclose(fp);
}

void microhook_coverage_shutdown(void)
{
    if (!g_coverage_enabled) {
        return;
    }

    g_mutex_lock(&g_lock);

    /* Final flush */
    microhook_coverage_flush_unlocked();

    unsigned long block_count = 0;
    if (g_blocks) {
        g_hash_table_foreach(g_blocks, count_block_cb, &block_count);
    }
    fprintf(stderr, "microhook-coverage: wrote %lu blocks to %s\n",
            block_count, g_output_filename);

    /* Free resources */
    if (g_blocks) {
        g_hash_table_destroy(g_blocks);
        g_blocks = NULL;
    }

    g_free(g_output_filename);
    g_output_filename = NULL;
    
    g_free(g_filename_template);
    g_filename_template = NULL;

    g_free(g_binary_path);
    g_binary_path = NULL;
    
    g_free(g_binary_name);
    g_binary_name = NULL;

    g_coverage_enabled = false;

    g_mutex_unlock(&g_lock);
    g_mutex_clear(&g_lock);
}
