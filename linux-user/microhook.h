/*
 * Microhook - Python-based syscall hooking for QEMU linux-user
 *
 * Copyright (c) 2024
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef MICROHOOK_H
#define MICROHOOK_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "user/abitypes.h"

/*
 * Hook action - determines what happens after the Python hook returns
 */
typedef enum {
    MICROHOOK_CONTINUE,      /* Call original syscall with (possibly modified) args */
    MICROHOOK_SKIP,          /* Skip original syscall, use provided return value */
} MicrohookAction;

/*
 * Result from a Python syscall hook
 */
typedef struct {
    MicrohookAction action;
    abi_long args[8];       /* Possibly modified arguments */
    abi_long ret;           /* Return value (used when action == MICROHOOK_SKIP) */
} MicrohookResult;

/*
 * Initialize the microhook subsystem with a Python script
 * Returns 0 on success, -1 on failure
 */
int microhook_init(const char *script_path);

/*
 * Shutdown the microhook subsystem
 */
void microhook_shutdown(void);

/*
 * Check if microhook is enabled
 */
bool microhook_enabled(void);

/*
 * Called before a syscall is executed.
 * The Python script can:
 *   - Modify arguments (set result->args)
 *   - Skip the syscall entirely (set result->action = MICROHOOK_SKIP)
 *   - Let the syscall proceed (set result->action = MICROHOOK_CONTINUE)
 *
 * Returns true if a hook was called, false otherwise.
 */
bool microhook_pre_syscall(CPUArchState *cpu_env, int num,
                          abi_long arg1, abi_long arg2, abi_long arg3,
                          abi_long arg4, abi_long arg5, abi_long arg6,
                          abi_long arg7, abi_long arg8,
                          MicrohookResult *result);

/*
 * Called after a syscall is executed (if not skipped).
 * The Python script can modify the return value.
 *
 * Returns the (possibly modified) return value.
 */
abi_long microhook_post_syscall(CPUArchState *cpu_env, int num,
                               abi_long ret,
                               abi_long arg1, abi_long arg2, abi_long arg3,
                               abi_long arg4, abi_long arg5, abi_long arg6,
                               abi_long arg7, abi_long arg8);

#endif /* MICROHOOK_H */
