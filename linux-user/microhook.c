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

#include "qemu/osdep.h"
#include "microhook.h"
#include "qemu.h"

#define PY_SSIZE_T_CLEAN
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <Python.h>
#pragma GCC diagnostic pop

static bool g_microhook_enabled = false;
static PyObject *g_module = NULL;
static PyObject *g_pre_syscall_hooks = NULL;   /* dict: syscall_num -> callable */
static PyObject *g_post_syscall_hooks = NULL;  /* dict: syscall_num -> callable */

/* Constants exposed to Python */
#define MICROHOOK_ACTION_CONTINUE 0
#define MICROHOOK_ACTION_SKIP 1

/* Syscall name entry for the SYSCALLS dict */
struct microhook_syscall_entry {
    int nr;
    const char *name;
};

static const struct microhook_syscall_entry microhook_syscalls[] = {
#include "microhook.list"
};

/*
 * Look up a syscall number by name.
 * Returns the syscall number, or -1 if not found.
 */
static int lookup_syscall_by_name(const char *name)
{
    size_t num_syscalls = sizeof(microhook_syscalls) / sizeof(microhook_syscalls[0]);
    for (size_t i = 0; i < num_syscalls; i++) {
        if (strcmp(microhook_syscalls[i].name, name) == 0) {
            return microhook_syscalls[i].nr;
        }
    }
    return -1;
}

/*
 * Parse a syscall identifier from Python (either int or string).
 * Returns the syscall number, or -1 on error (with Python exception set).
 */
static int parse_syscall_identifier(PyObject *obj)
{
    if (PyLong_Check(obj)) {
        return (int)PyLong_AsLong(obj);
    } else if (PyUnicode_Check(obj)) {
        const char *name = PyUnicode_AsUTF8(obj);
        if (!name) {
            return -1;
        }
        int syscall_num = lookup_syscall_by_name(name);
        if (syscall_num < 0) {
            PyErr_Format(PyExc_ValueError, "unknown syscall name: '%s'", name);
            return -1;
        }
        return syscall_num;
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "syscall must be an int or string");
        return -1;
    }
}

/*
 * Python API: microhook.register_pre_hook(syscall, callback)
 *
 * Register a pre-syscall hook. syscall can be either:
 *   - An integer syscall number
 *   - A string syscall name (e.g., "open", "read", "write")
 *
 * The callback receives a context dict:
 *   callback(ctx) where ctx = {
 *       "num": int,           # syscall number
 *       "args": [arg0..arg7], # syscall arguments
 *       "ret": 0,             # return value (for skip mode)
 *       "cpu": {              # CPU register state (architecture-specific)
 *           "pc": int,        # program counter
 *           "sp": int,        # stack pointer
 *           "regs": [...],    # general purpose registers (varies by arch)
 *           ...               # other arch-specific registers
 *       }
 *   }
 *
 * The callback can modify ctx["args"] and ctx["ret"].
 *
 * Return value:
 *   - True:  Skip the original syscall, use ctx["ret"] as the return value
 *   - False: Execute the original syscall with (possibly modified) ctx["args"]
 */
static PyObject *py_register_pre_hook(PyObject *self, PyObject *args)
{
    PyObject *syscall_obj;
    PyObject *callback;

    if (!PyArg_ParseTuple(args, "OO", &syscall_obj, &callback)) {
        return NULL;
    }

    int syscall_num = parse_syscall_identifier(syscall_obj);
    if (syscall_num < 0 && PyErr_Occurred()) {
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    PyObject *key = PyLong_FromLong(syscall_num);
    if (!key) {
        return NULL;
    }

    Py_INCREF(callback);
    if (PyDict_SetItem(g_pre_syscall_hooks, key, callback) < 0) {
        Py_DECREF(key);
        Py_DECREF(callback);
        return NULL;
    }
    Py_DECREF(key);

    Py_RETURN_NONE;
}

/*
 * Python API: microhook.register_post_hook(syscall, callback)
 *
 * Register a post-syscall hook. syscall can be either:
 *   - An integer syscall number
 *   - A string syscall name (e.g., "open", "read", "write")
 *
 * The callback receives:
 *   callback(ctx, ret) where ctx = {
 *       "num": int,           # syscall number
 *       "args": [arg0..arg7], # syscall arguments
 *       "cpu": {              # CPU register state (architecture-specific)
 *           "pc": int,        # program counter
 *           "sp": int,        # stack pointer
 *           "regs": [...],    # general purpose registers (varies by arch)
 *           ...               # other arch-specific registers
 *       }
 *   }
 *   and ret is the syscall return value
 *
 * The callback should return the (possibly modified) return value.
 */
static PyObject *py_register_post_hook(PyObject *self, PyObject *args)
{
    PyObject *syscall_obj;
    PyObject *callback;

    if (!PyArg_ParseTuple(args, "OO", &syscall_obj, &callback)) {
        return NULL;
    }

    int syscall_num = parse_syscall_identifier(syscall_obj);
    if (syscall_num < 0 && PyErr_Occurred()) {
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    PyObject *key = PyLong_FromLong(syscall_num);
    if (!key) {
        return NULL;
    }

    Py_INCREF(callback);
    if (PyDict_SetItem(g_post_syscall_hooks, key, callback) < 0) {
        Py_DECREF(key);
        Py_DECREF(callback);
        return NULL;
    }
    Py_DECREF(key);

    Py_RETURN_NONE;
}

/*
 * Python API: microhook.unregister_pre_hook(syscall)
 *
 * syscall can be either an integer or a string syscall name.
 */
static PyObject *py_unregister_pre_hook(PyObject *self, PyObject *args)
{
    PyObject *syscall_obj;

    if (!PyArg_ParseTuple(args, "O", &syscall_obj)) {
        return NULL;
    }

    int syscall_num = parse_syscall_identifier(syscall_obj);
    if (syscall_num < 0 && PyErr_Occurred()) {
        return NULL;
    }

    PyObject *key = PyLong_FromLong(syscall_num);
    if (!key) {
        return NULL;
    }

    PyDict_DelItem(g_pre_syscall_hooks, key);
    PyErr_Clear(); /* Ignore KeyError if not found */
    Py_DECREF(key);

    Py_RETURN_NONE;
}

/*
 * Python API: microhook.unregister_post_hook(syscall)
 *
 * syscall can be either an integer or a string syscall name.
 */
static PyObject *py_unregister_post_hook(PyObject *self, PyObject *args)
{
    PyObject *syscall_obj;

    if (!PyArg_ParseTuple(args, "O", &syscall_obj)) {
        return NULL;
    }

    int syscall_num = parse_syscall_identifier(syscall_obj);
    if (syscall_num < 0 && PyErr_Occurred()) {
        return NULL;
    }

    PyObject *key = PyLong_FromLong(syscall_num);
    if (!key) {
        return NULL;
    }

    PyDict_DelItem(g_post_syscall_hooks, key);
    PyErr_Clear(); /* Ignore KeyError if not found */
    Py_DECREF(key);

    Py_RETURN_NONE;
}

/*
 * Python API: microhook.read_memory(addr, size) -> bytes
 *
 * Read guest memory at the given address.
 */
static PyObject *py_read_memory(PyObject *self, PyObject *args)
{
    unsigned long long addr;
    Py_ssize_t size;

    if (!PyArg_ParseTuple(args, "Kn", &addr, &size)) {
        return NULL;
    }

    if (size <= 0) {
        PyErr_SetString(PyExc_ValueError, "size must be positive");
        return NULL;
    }

    void *host_ptr = g2h_untagged(addr);
    if (!host_ptr) {
        PyErr_SetString(PyExc_MemoryError, "invalid guest address");
        return NULL;
    }

    return PyBytes_FromStringAndSize(host_ptr, size);
}

/*
 * Python API: microhook.write_memory(addr, data)
 *
 * Write data to guest memory at the given address.
 */
static PyObject *py_write_memory(PyObject *self, PyObject *args)
{
    unsigned long long addr;
    Py_buffer buffer;

    if (!PyArg_ParseTuple(args, "Ky*", &addr, &buffer)) {
        return NULL;
    }

    void *host_ptr = g2h_untagged(addr);
    if (!host_ptr) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_MemoryError, "invalid guest address");
        return NULL;
    }

    memcpy(host_ptr, buffer.buf, buffer.len);
    PyBuffer_Release(&buffer);

    Py_RETURN_NONE;
}

/*
 * Python API: microhook.read_string(addr) -> str
 *
 * Read a null-terminated string from guest memory.
 */
static PyObject *py_read_string(PyObject *self, PyObject *args)
{
    unsigned long long addr;

    if (!PyArg_ParseTuple(args, "K", &addr)) {
        return NULL;
    }

    char *host_ptr = g2h_untagged(addr);
    if (!host_ptr) {
        PyErr_SetString(PyExc_MemoryError, "invalid guest address");
        return NULL;
    }

    /* Safely get the string length */
    ssize_t len = target_strlen(addr);
    if (len < 0) {
        PyErr_SetString(PyExc_MemoryError, "invalid string address");
        return NULL;
    }

    return PyUnicode_FromStringAndSize(host_ptr, len);
}

static PyMethodDef microhook_methods[] = {
    {"register_pre_hook", py_register_pre_hook, METH_VARARGS,
     "Register a pre-syscall hook: register_pre_hook(syscall, callback)\n"
     "syscall can be an int or string name (e.g., 'open', 'read')"},
    {"register_post_hook", py_register_post_hook, METH_VARARGS,
     "Register a post-syscall hook: register_post_hook(syscall, callback)\n"
     "syscall can be an int or string name (e.g., 'open', 'read')"},
    {"unregister_pre_hook", py_unregister_pre_hook, METH_VARARGS,
     "Unregister a pre-syscall hook: unregister_pre_hook(syscall)\n"
     "syscall can be an int or string name"},
    {"unregister_post_hook", py_unregister_post_hook, METH_VARARGS,
     "Unregister a post-syscall hook: unregister_post_hook(syscall)\n"
     "syscall can be an int or string name"},
    {"read_memory", py_read_memory, METH_VARARGS,
     "Read guest memory: read_memory(addr, size) -> bytes"},
    {"write_memory", py_write_memory, METH_VARARGS,
     "Write guest memory: write_memory(addr, data)"},
    {"read_string", py_read_string, METH_VARARGS,
     "Read null-terminated string from guest memory: read_string(addr) -> str"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef microhook_module = {
    PyModuleDef_HEAD_INIT,
    "microhook",
    "QEMU Microhook syscall hooking module",
    -1,
    microhook_methods
};

/*
 * Build a Python dict containing CPU register state.
 * This is architecture-specific.
 */
static PyObject *build_cpu_context(CPUArchState *env)
{
    PyObject *cpu = PyDict_New();
    if (!cpu) {
        return NULL;
    }

    PyObject *regs = NULL;
    PyObject *pc = NULL;

#if defined(TARGET_ARM)
    /*
     * ARM / AArch64
     * 32-bit: regs[0-15], where regs[15] = PC, regs[13] = SP, regs[14] = LR
     * 64-bit: xregs[0-30], pc, sp (xregs[31] is zero register, SP is separate)
     */
    if (env->aarch64) {
        /* AArch64 mode */
        regs = PyList_New(31);
        if (!regs) goto error;
        for (int i = 0; i < 31; i++) {
            PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->xregs[i]));
        }
        PyDict_SetItemString(cpu, "xregs", regs);
        Py_DECREF(regs);

        pc = PyLong_FromUnsignedLongLong(env->pc);
        PyDict_SetItemString(cpu, "pc", pc);
        Py_DECREF(pc);

        /* SP in AArch64 is separate from xregs */
        PyObject *sp = PyLong_FromUnsignedLongLong(env->xregs[31]);
        PyDict_SetItemString(cpu, "sp", sp);
        Py_DECREF(sp);
    } else {
        /* AArch32 mode */
        regs = PyList_New(16);
        if (!regs) goto error;
        for (int i = 0; i < 16; i++) {
            PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLong(env->regs[i]));
        }
        PyDict_SetItemString(cpu, "regs", regs);
        Py_DECREF(regs);

        /* PC is regs[15] but also expose it directly */
        pc = PyLong_FromUnsignedLong(env->regs[15]);
        PyDict_SetItemString(cpu, "pc", pc);
        Py_DECREF(pc);

        /* SP is regs[13], LR is regs[14] */
        PyObject *sp = PyLong_FromUnsignedLong(env->regs[13]);
        PyDict_SetItemString(cpu, "sp", sp);
        Py_DECREF(sp);

        PyObject *lr = PyLong_FromUnsignedLong(env->regs[14]);
        PyDict_SetItemString(cpu, "lr", lr);
        Py_DECREF(lr);
    }

#elif defined(TARGET_ALPHA)
    /* Alpha: ir[0-30] (ir[31] is zero), pc */
    regs = PyList_New(31);
    if (!regs) goto error;
    for (int i = 0; i < 31; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->ir[i]));
    }
    PyDict_SetItemString(cpu, "regs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is ir[30] */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->ir[30]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_HEXAGON)
    /* Hexagon: gpr[0-63], PC is in gpr */
    regs = PyList_New(TOTAL_PER_THREAD_REGS);
    if (!regs) goto error;
    for (int i = 0; i < TOTAL_PER_THREAD_REGS; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->gpr[i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    /* PC and SP are at known GPR indices */
    pc = PyLong_FromUnsignedLongLong(env->gpr[HEX_REG_PC]);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    PyObject *sp = PyLong_FromUnsignedLongLong(env->gpr[HEX_REG_SP]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_HPPA)
    /* HPPA: gr[0-31], iaoq_f (PC) */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->gr[i]));
    }
    PyDict_SetItemString(cpu, "gr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->iaoq_f);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* Next PC */
    PyObject *npc = PyLong_FromUnsignedLongLong(env->iaoq_b);
    PyDict_SetItemString(cpu, "npc", npc);
    Py_DECREF(npc);

    /* SP is gr[30] */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->gr[30]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_I386)
    /* i386 / x86_64: regs[], eip */
    regs = PyList_New(CPU_NB_REGS);
    if (!regs) goto error;
    for (int i = 0; i < CPU_NB_REGS; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->regs[i]));
    }
    PyDict_SetItemString(cpu, "regs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->eip);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* Also expose common register names */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->regs[R_ESP]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_M68K)
    /* M68K: dregs[0-7], aregs[0-7], pc */
    PyObject *dregs = PyList_New(8);
    if (!dregs) goto error;
    for (int i = 0; i < 8; i++) {
        PyList_SET_ITEM(dregs, i, PyLong_FromUnsignedLong(env->dregs[i]));
    }
    PyDict_SetItemString(cpu, "dregs", dregs);
    Py_DECREF(dregs);

    PyObject *aregs = PyList_New(8);
    if (!aregs) goto error;
    for (int i = 0; i < 8; i++) {
        PyList_SET_ITEM(aregs, i, PyLong_FromUnsignedLong(env->aregs[i]));
    }
    PyDict_SetItemString(cpu, "aregs", aregs);
    Py_DECREF(aregs);

    pc = PyLong_FromUnsignedLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is aregs[7] */
    PyObject *sp = PyLong_FromUnsignedLong(env->aregs[7]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_MICROBLAZE)
    /* MicroBlaze: regs[0-31], pc */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLong(env->regs[i]));
    }
    PyDict_SetItemString(cpu, "regs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is regs[1] */
    PyObject *sp = PyLong_FromUnsignedLong(env->regs[1]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_MIPS) || defined(TARGET_MIPS64)
    /* MIPS: active_tc.gpr[0-31], active_tc.PC */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->active_tc.gpr[i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->active_tc.PC);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gpr[29] */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->active_tc.gpr[29]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_OPENRISC)
    /* OpenRISC: shadow_gpr[0][0-31] (current bank), pc */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLong(env->shadow_gpr[0][i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gpr[1] */
    PyObject *sp = PyLong_FromUnsignedLong(env->shadow_gpr[0][1]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_PPC) || defined(TARGET_PPC64)
    /* PowerPC: gpr[0-31], nip (next instruction pointer = PC) */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->gpr[i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->nip);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gpr[1], LR is in lr register */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->gpr[1]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

    PyObject *lr = PyLong_FromUnsignedLongLong(env->lr);
    PyDict_SetItemString(cpu, "lr", lr);
    Py_DECREF(lr);

#elif defined(TARGET_RISCV32) || defined(TARGET_RISCV64)
    /* RISC-V: gpr[0-31], pc */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->gpr[i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gpr[2] (x2) */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->gpr[2]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_S390X)
    /* S390X: regs[0-15], psw.addr (PC) */
    regs = PyList_New(16);
    if (!regs) goto error;
    for (int i = 0; i < 16; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->regs[i]));
    }
    PyDict_SetItemString(cpu, "regs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->psw.addr);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is regs[15] */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->regs[15]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_SH4)
    /* SH4: gregs[0-23], pc */
    regs = PyList_New(24);
    if (!regs) goto error;
    for (int i = 0; i < 24; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLong(env->gregs[i]));
    }
    PyDict_SetItemString(cpu, "gregs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gregs[15] */
    PyObject *sp = PyLong_FromUnsignedLong(env->gregs[15]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

    /* PR (procedure register / return address) */
    PyObject *pr = PyLong_FromUnsignedLong(env->pr);
    PyDict_SetItemString(cpu, "pr", pr);
    Py_DECREF(pr);

#elif defined(TARGET_SPARC) || defined(TARGET_SPARC64)
    /* SPARC: gregs[0-7], regwptr (window regs), pc, npc */
    PyObject *gregs = PyList_New(8);
    if (!gregs) goto error;
    for (int i = 0; i < 8; i++) {
        PyList_SET_ITEM(gregs, i, PyLong_FromUnsignedLongLong(env->gregs[i]));
    }
    PyDict_SetItemString(cpu, "gregs", gregs);
    Py_DECREF(gregs);

    pc = PyLong_FromUnsignedLongLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    PyObject *npc = PyLong_FromUnsignedLongLong(env->npc);
    PyDict_SetItemString(cpu, "npc", npc);
    Py_DECREF(npc);

    /* SP is in the register window (o6) */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->regwptr[WREG_SP]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_XTENSA)
    /* Xtensa: regs[0-15], phys_regs[], pc */
    regs = PyList_New(16);
    if (!regs) goto error;
    for (int i = 0; i < 16; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLong(env->regs[i]));
    }
    PyDict_SetItemString(cpu, "regs", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is a1 (regs[1]) */
    PyObject *sp = PyLong_FromUnsignedLong(env->regs[1]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#elif defined(TARGET_LOONGARCH64)
    /* LoongArch: gpr[0-31], pc */
    regs = PyList_New(32);
    if (!regs) goto error;
    for (int i = 0; i < 32; i++) {
        PyList_SET_ITEM(regs, i, PyLong_FromUnsignedLongLong(env->gpr[i]));
    }
    PyDict_SetItemString(cpu, "gpr", regs);
    Py_DECREF(regs);

    pc = PyLong_FromUnsignedLongLong(env->pc);
    PyDict_SetItemString(cpu, "pc", pc);
    Py_DECREF(pc);

    /* SP is gpr[3] */
    PyObject *sp = PyLong_FromUnsignedLongLong(env->gpr[3]);
    PyDict_SetItemString(cpu, "sp", sp);
    Py_DECREF(sp);

#else
    /* Unknown architecture - just provide empty dict */
    (void)env;
    (void)regs;
    (void)pc;
#endif

    return cpu;

error:
    Py_XDECREF(regs);
    Py_XDECREF(cpu);
    return NULL;
}

static PyObject *PyInit_microhook(void)
{
    PyObject *m = PyModule_Create(&microhook_module);
    if (!m) {
        return NULL;
    }

    /* Add constants */
    PyModule_AddIntConstant(m, "CONTINUE", MICROHOOK_ACTION_CONTINUE);
    PyModule_AddIntConstant(m, "SKIP", MICROHOOK_ACTION_SKIP);

    /* Create SYSCALLS dict mapping syscall number -> name */
    PyObject *syscalls_dict = PyDict_New();
    if (!syscalls_dict) {
        Py_DECREF(m);
        return NULL;
    }

    size_t num_syscalls = sizeof(microhook_syscalls) / sizeof(microhook_syscalls[0]);
    for (size_t i = 0; i < num_syscalls; i++) {
        PyObject *key = PyLong_FromLong(microhook_syscalls[i].nr);
        PyObject *value = PyUnicode_FromString(microhook_syscalls[i].name);
        if (!key || !value) {
            Py_XDECREF(key);
            Py_XDECREF(value);
            Py_DECREF(syscalls_dict);
            Py_DECREF(m);
            return NULL;
        }
        PyDict_SetItem(syscalls_dict, key, value);
        Py_DECREF(key);
        Py_DECREF(value);
    }

    if (PyModule_AddObject(m, "SYSCALLS", syscalls_dict) < 0) {
        Py_DECREF(syscalls_dict);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

int microhook_init(const char *script_path)
{
    FILE *fp;
    PyStatus status;
    PyConfig config;

    /* Register the microhook module before Py_Initialize */
    if (PyImport_AppendInittab("microhook", PyInit_microhook) == -1) {
        fprintf(stderr, "microhook: failed to register module\n");
        return -1;
    }

    /* Use PyConfig for proper initialization of embedded Python */
    PyConfig_InitPythonConfig(&config);

    /* Suppress the "Could not find platform independent/dependent libraries" warnings */
    config.pathconfig_warnings = 0;

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);

    if (PyStatus_Exception(status)) {
        fprintf(stderr, "microhook: failed to initialize Python: %s\n",
                status.err_msg ? status.err_msg : "unknown error");
        return -1;
    }

    if (!Py_IsInitialized()) {
        fprintf(stderr, "microhook: failed to initialize Python\n");
        return -1;
    }

    /* Create the hook dictionaries */
    g_pre_syscall_hooks = PyDict_New();
    g_post_syscall_hooks = PyDict_New();
    if (!g_pre_syscall_hooks || !g_post_syscall_hooks) {
        fprintf(stderr, "microhook: failed to create hook dictionaries\n");
        microhook_shutdown();
        return -1;
    }

    /* Import the microhook module so it's available */
    g_module = PyImport_ImportModule("microhook");
    if (!g_module) {
        fprintf(stderr, "microhook: failed to import microhook module\n");
        PyErr_Print();
        microhook_shutdown();
        return -1;
    }

    /* Add the script's directory to sys.path */
    char *script_dir = g_path_get_dirname(script_path);
    PyObject *sys_path = PySys_GetObject("path");
    if (sys_path && script_dir) {
        PyObject *dir_obj = PyUnicode_FromString(script_dir);
        if (dir_obj) {
            PyList_Insert(sys_path, 0, dir_obj);
            Py_DECREF(dir_obj);
        }
    }
    g_free(script_dir);

    /* Execute the user's script */
    fp = fopen(script_path, "r");
    if (!fp) {
        fprintf(stderr, "microhook: failed to open script '%s': %s\n",
                script_path, strerror(errno));
        microhook_shutdown();
        return -1;
    }

    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *main_dict = PyModule_GetDict(main_module);

    /* Make microhook module available in __main__ */
    PyDict_SetItemString(main_dict, "microhook", g_module);

    PyObject *result = PyRun_FileEx(fp, script_path, Py_file_input,
                                    main_dict, main_dict, 1);
    if (!result) {
        fprintf(stderr, "microhook: error executing script '%s':\n", script_path);
        PyErr_Print();
        microhook_shutdown();
        return -1;
    }
    Py_DECREF(result);

    g_microhook_enabled = true;
    fprintf(stderr, "microhook: loaded script '%s'\n", script_path);
    return 0;
}

void microhook_shutdown(void)
{
    if (g_microhook_enabled) {
        Py_XDECREF(g_pre_syscall_hooks);
        Py_XDECREF(g_post_syscall_hooks);
        Py_XDECREF(g_module);
        g_pre_syscall_hooks = NULL;
        g_post_syscall_hooks = NULL;
        g_module = NULL;
        g_microhook_enabled = false;

        if (Py_IsInitialized()) {
            Py_Finalize();
        }
    }
}

bool microhook_enabled(void)
{
    return g_microhook_enabled;
}

bool microhook_pre_syscall(CPUArchState *cpu_env, int num,
                          abi_long arg1, abi_long arg2, abi_long arg3,
                          abi_long arg4, abi_long arg5, abi_long arg6,
                          abi_long arg7, abi_long arg8,
                          MicrohookResult *result)
{
    if (!g_microhook_enabled || !g_pre_syscall_hooks) {
        return false;
    }

    /* Initialize result with defaults */
    result->action = MICROHOOK_CONTINUE;
    result->args[0] = arg1;
    result->args[1] = arg2;
    result->args[2] = arg3;
    result->args[3] = arg4;
    result->args[4] = arg5;
    result->args[5] = arg6;
    result->args[6] = arg7;
    result->args[7] = arg8;
    result->ret = 0;

    PyObject *key = PyLong_FromLong(num);
    if (!key) {
        PyErr_Clear();
        return false;
    }

    PyObject *callback = PyDict_GetItem(g_pre_syscall_hooks, key);
    Py_DECREF(key);

    if (!callback) {
        return false;
    }

    /* Build the context dict: {"num": int, "args": [arg0..arg7], "ret": 0} */
    PyObject *ctx = PyDict_New();
    if (!ctx) {
        PyErr_Print();
        return false;
    }

    PyObject *py_num = PyLong_FromLong(num);
    PyObject *py_args = PyList_New(8);
    PyObject *py_ret = PyLong_FromLongLong(0);

    if (!py_num || !py_args || !py_ret) {
        Py_XDECREF(py_num);
        Py_XDECREF(py_args);
        Py_XDECREF(py_ret);
        Py_DECREF(ctx);
        PyErr_Print();
        return false;
    }

    /* Fill args list */
    abi_long args_array[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
    for (int i = 0; i < 8; i++) {
        PyObject *item = PyLong_FromLongLong((long long)args_array[i]);
        if (!item) {
            Py_DECREF(py_num);
            Py_DECREF(py_args);
            Py_DECREF(py_ret);
            Py_DECREF(ctx);
            PyErr_Print();
            return false;
        }
        PyList_SET_ITEM(py_args, i, item);  /* Steals reference */
    }

    PyDict_SetItemString(ctx, "num", py_num);
    PyDict_SetItemString(ctx, "args", py_args);
    PyDict_SetItemString(ctx, "ret", py_ret);
    Py_DECREF(py_num);
    Py_DECREF(py_args);
    Py_DECREF(py_ret);

    /* Add CPU context */
    PyObject *cpu_ctx = build_cpu_context(cpu_env);
    if (cpu_ctx) {
        PyDict_SetItemString(ctx, "cpu", cpu_ctx);
        Py_DECREF(cpu_ctx);
    }

    /* Call the Python callback with the context dict */
    PyObject *py_result = PyObject_CallFunctionObjArgs(callback, ctx, NULL);
    if (!py_result) {
        fprintf(stderr, "microhook: error in pre-syscall hook for syscall %d:\n", num);
        PyErr_Print();
        Py_DECREF(ctx);
        return false;
    }

    /* Check return value: True = skip syscall, False = continue */
    int skip_syscall = PyObject_IsTrue(py_result);
    Py_DECREF(py_result);

    if (skip_syscall) {
        result->action = MICROHOOK_SKIP;
    }

    /* Extract possibly modified args from ctx["args"] */
    PyObject *modified_args = PyDict_GetItemString(ctx, "args");
    if (modified_args && PyList_Check(modified_args) && PyList_Size(modified_args) == 8) {
        for (int i = 0; i < 8; i++) {
            PyObject *item = PyList_GetItem(modified_args, i);
            if (item && PyLong_Check(item)) {
                result->args[i] = (abi_long)PyLong_AsLongLong(item);
            }
        }
    }

    /* Extract possibly modified ret from ctx["ret"] */
    PyObject *modified_ret = PyDict_GetItemString(ctx, "ret");
    if (modified_ret && PyLong_Check(modified_ret)) {
        result->ret = (abi_long)PyLong_AsLongLong(modified_ret);
    }

    Py_DECREF(ctx);
    return true;
}

abi_long microhook_post_syscall(CPUArchState *cpu_env, int num,
                               abi_long ret,
                               abi_long arg1, abi_long arg2, abi_long arg3,
                               abi_long arg4, abi_long arg5, abi_long arg6,
                               abi_long arg7, abi_long arg8)
{
    if (!g_microhook_enabled || !g_post_syscall_hooks) {
        return ret;
    }

    PyObject *key = PyLong_FromLong(num);
    if (!key) {
        PyErr_Clear();
        return ret;
    }

    PyObject *callback = PyDict_GetItem(g_post_syscall_hooks, key);
    Py_DECREF(key);

    if (!callback) {
        return ret;
    }

    /* Build the context dict: {"num": int, "args": [arg0..arg7]} */
    PyObject *ctx = PyDict_New();
    if (!ctx) {
        PyErr_Print();
        return ret;
    }

    PyObject *py_num = PyLong_FromLong(num);
    PyObject *py_args = PyList_New(8);
    PyObject *py_ret = PyLong_FromLongLong((long long)ret);

    if (!py_num || !py_args || !py_ret) {
        Py_XDECREF(py_num);
        Py_XDECREF(py_args);
        Py_XDECREF(py_ret);
        Py_DECREF(ctx);
        PyErr_Print();
        return ret;
    }

    /* Fill args list */
    abi_long args_array[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
    for (int i = 0; i < 8; i++) {
        PyObject *item = PyLong_FromLongLong((long long)args_array[i]);
        if (!item) {
            Py_DECREF(py_num);
            Py_DECREF(py_args);
            Py_DECREF(py_ret);
            Py_DECREF(ctx);
            PyErr_Print();
            return ret;
        }
        PyList_SET_ITEM(py_args, i, item);  /* Steals reference */
    }

    PyDict_SetItemString(ctx, "num", py_num);
    PyDict_SetItemString(ctx, "args", py_args);
    Py_DECREF(py_num);
    Py_DECREF(py_args);

    /* Add CPU context */
    PyObject *cpu_ctx = build_cpu_context(cpu_env);
    if (cpu_ctx) {
        PyDict_SetItemString(ctx, "cpu", cpu_ctx);
        Py_DECREF(cpu_ctx);
    }

    /* Call the Python callback with (ctx, ret) */
    PyObject *py_result = PyObject_CallFunctionObjArgs(callback, ctx, py_ret, NULL);
    Py_DECREF(py_ret);
    if (!py_result) {
        fprintf(stderr, "microhook: error in post-syscall hook for syscall %d:\n", num);
        PyErr_Print();
        Py_DECREF(ctx);
        return ret;
    }

    /* Use the return value from the callback */
    abi_long new_ret = ret;
    if (PyLong_Check(py_result)) {
        new_ret = (abi_long)PyLong_AsLongLong(py_result);
    }

    Py_DECREF(py_result);
    Py_DECREF(ctx);
    return new_ret;
}
