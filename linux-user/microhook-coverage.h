/*
 * Microhook Coverage - DRCov coverage generation for QEMU linux-user
 *
 * Copyright (c) 2024
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef MICROHOOK_COVERAGE_H
#define MICROHOOK_COVERAGE_H

#include "qemu/osdep.h"
#include <stdint.h>
#include <stdbool.h>

/*
 * Initialize the coverage subsystem.
 * filename: path to the output drcov file (NULL for default "coverage.drcov")
 * Returns 0 on success, -1 on failure.
 */
int microhook_coverage_init(const char *filename);

/*
 * Shutdown the coverage subsystem and write the drcov file.
 * This should be called at program exit.
 */
void microhook_coverage_shutdown(void);

/*
 * Check if coverage is enabled.
 */
bool microhook_coverage_enabled(void);

/*
 * Record a translated block for coverage.
 * pc: guest virtual address of the block start
 * size: size of the block in bytes
 *
 * This should be called from the translator when a block is translated.
 * The function is thread-safe and will deduplicate blocks.
 */
void microhook_coverage_record_block(uint64_t pc, uint32_t size);

/*
 * Set the binary information for the drcov module table.
 * path: path to the binary
 * start_code: start of code section (guest address)
 * end_code: end of code section (guest address)
 * entry: entry point (guest address)
 */
void microhook_coverage_set_binary_info(const char *path,
                                       uint64_t start_code,
                                       uint64_t end_code,
                                       uint64_t entry);

#endif /* MICROHOOK_COVERAGE_H */
