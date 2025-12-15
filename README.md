# Microhook - A small system-call hooking & coverage tool for QEMU user-mode.

Microhook provides:
- System-call hooking via very simple Python scripts
- Drcov coverage collection

Microhook is a fork of QEMU with minimal changes to upstream QEMU to make keeping up with upstream easy. All the hard work is done by QEMU, this just adds some useful features for firmware-emulation & reverse-engineering.

All QEMU user-mode architectures are supported.

**Note: QEMU user-mode only runs on Linux. Hence microhook can only run on Linux.**

# Building

## Statically

Static compilation is great for having a single binary that you can just drop into a rootfs and chroot into it. During static compilation Python 3.11 is fully embedded into the binary.

Check-out `Dockerfile` and `build_static.sh` to see how to statically build Microhook, or just download one of the releases.

## Dynamically

Start by installing the general QEMU dependencies, and then simply run:

```
./configure
make
make install
```

This will install the microhook-* tools.

# Systemcall Hooking

Microhook allows you to intercept and modify syscalls in QEMU linux-user mode using Python scripts.

## Usage

```bash
microhook-<arch> -hook your_script.py ./your_binary [args...]
```

## API Reference

### Registering Hooks

```python
import microhook

# Register a pre-syscall hook (called before syscall executes)
microhook.register_pre_hook(syscall, callback)

# Register a post-syscall hook (called after syscall executes)
microhook.register_post_hook(syscall, callback)

# Unregister hooks
microhook.unregister_pre_hook(syscall)
microhook.unregister_post_hook(syscall)
```

The `syscall` parameter can be either:
- An integer syscall number (e.g., `4003`)
- A string syscall name (e.g., `"read"`, `"write"`, `"open"`)

### Hook Callbacks

#### Pre-Hook Callbacks

Pre-hooks receive a **context dict** with syscall information:

```python
def my_pre_hook(ctx):
    # ctx = {
    #     "num": syscall_number,
    #     "args": [arg0..arg7],
    #     "ret": 0,
    #     "binary": "/path/to/binary",           # path to the executed binary
    #     "cpu": { "pc": ..., "sp": ..., ... }   # CPU register state
    # }
    
    # Access syscall info
    syscall_num = ctx["num"]
    first_arg = ctx["args"][0]
    
    # Access CPU registers (see "CPU Register Access" section below)
    pc = ctx["cpu"]["pc"]
    sp = ctx["cpu"]["sp"]
    
    # Modify arguments (will be used when syscall executes)
    ctx["args"][0] = new_value
    
    # To skip the syscall entirely:
    ctx["ret"] = -1  # Set the return value
    return True      # Return True to skip
    
    # To let the syscall execute normally:
    return False
```

**Return values:**
- `True` - Skip the original syscall; `ctx["ret"]` will be used as the return value
- `False` - Execute the original syscall with (possibly modified) `ctx["args"]`

#### Post-Hook Callbacks

Post-hooks receive a **context dict** and the **return value** as separate arguments:

```python
def my_post_hook(ctx, ret):
    # ctx = {
    #     "num": syscall_number,
    #     "args": [arg0..arg7],
    #     "binary": "/path/to/binary",           # path to the executed binary
    #     "cpu": { "pc": ..., "sp": ..., ... }   # CPU register state
    # }
    # ret = actual return value from the syscall
    
    # Inspect args
    fd = ctx["args"][0]
    
    # Access CPU registers
    pc = ctx["cpu"]["pc"]
    
    # Return the (possibly modified) return value
    return ret
```

**Return value:** The callback's return value becomes the syscall's return value.

### Memory Access

```python
# Read bytes from guest memory
data = microhook.read_memory(addr, size)  # -> bytes

# Write bytes to guest memory
microhook.write_memory(addr, data)

# Read a null-terminated string from guest memory
string = microhook.read_string(addr)  # -> str
```

### CPU Register Access

Both pre-hook and post-hook callbacks receive CPU register state in `ctx["cpu"]`. All architectures provide at least:

- `pc` - Program counter
- `sp` - Stack pointer

The following table shows the register layout for each supported architecture:

| Architecture | Registers | Notes |
|--------------|-----------|-------|
| **ARM (AArch32)** | `regs[0-15]`, `pc`, `sp`, `lr` | `regs[15]` = PC, `regs[13]` = SP, `regs[14]` = LR |
| **ARM (AArch64)** | `xregs[0-30]`, `pc`, `sp` | 64-bit registers, SP is separate from xregs |
| **Alpha** | `regs[0-30]`, `pc`, `sp` | `regs[30]` = SP |
| **Hexagon** | `gpr[0-63]`, `pc`, `sp` | PC and SP are at GPR indices |
| **HPPA** | `gr[0-31]`, `pc`, `npc`, `sp` | `npc` = next PC, `gr[30]` = SP |
| **i386/x86_64** | `regs[]`, `pc`, `sp` | `pc` = EIP/RIP |
| **M68K** | `dregs[0-7]`, `aregs[0-7]`, `pc`, `sp` | Data/Address regs, `aregs[7]` = SP |
| **MicroBlaze** | `regs[0-31]`, `pc`, `sp` | `regs[1]` = SP |
| **MIPS/MIPS64** | `gpr[0-31]`, `pc`, `sp` | `gpr[29]` = SP |
| **OpenRISC** | `gpr[0-31]`, `pc`, `sp` | `gpr[1]` = SP |
| **PowerPC/PPC64** | `gpr[0-31]`, `pc`, `sp`, `lr` | `gpr[1]` = SP, `pc` = NIP |
| **RISC-V** | `gpr[0-31]`, `pc`, `sp` | `gpr[2]` = SP (x2) |
| **S390X** | `regs[0-15]`, `pc`, `sp` | `regs[15]` = SP, `pc` = PSW address |
| **SH4** | `gregs[0-23]`, `pc`, `sp`, `pr` | `gregs[15]` = SP, `pr` = return addr |
| **SPARC/SPARC64** | `gregs[0-7]`, `pc`, `npc`, `sp` | Window registers, `npc` = next PC |
| **Xtensa** | `regs[0-15]`, `pc`, `sp` | `regs[1]` = SP |
| **LoongArch** | `gpr[0-31]`, `pc`, `sp` | `gpr[3]` = SP |


## Examples

### Logging Syscalls

```python
import microhook

def log_write(ctx):
    fd = ctx["args"][0]
    buf = ctx["args"][1]
    count = ctx["args"][2]
    
    data = microhook.read_memory(buf, min(count, 100))
    print(f"write(fd={fd}, count={count}): {data!r}")
    
    return False  # Continue with syscall

microhook.register_pre_hook("write", log_write)
```

### Blocking File Access

```python
import microhook

def block_passwd(ctx):
    filename_ptr = ctx["args"][0]
    filename = microhook.read_string(filename_ptr)
    
    if filename == "/etc/passwd":
        print("BLOCKED: /etc/passwd access denied")
        ctx["ret"] = -13  # -EACCES
        return True  # Skip syscall
    
    return False  # Allow syscall

microhook.register_pre_hook("open", block_passwd)
```

### Modifying Return Values

```python
import microhook

def fake_read(ctx, ret):
    buf = ctx["args"][1]
    
    if ret > 0:
        # Replace the data that was read
        microhook.write_memory(buf, b"MODIFIED DATA")
        return 13  # New byte count
    
    return ret

microhook.register_post_hook("read", fake_read)
```

### Modifying Arguments

```python
import microhook

def redirect_open(ctx):
    filename_ptr = ctx["args"][0]
    filename = microhook.read_string(filename_ptr)
    
    if filename == "/etc/secret":
        # Could allocate guest memory and write a new path,
        # then update ctx["args"][0] to point to it
        print(f"Would redirect {filename}")
    
    return False

microhook.register_pre_hook("open", redirect_open)
```

## Notes

- Syscall numbers are architecture-specific. Use `microhook.SYSCALLS` to look up names.
- The `args` list always contains 8 elements, even if the syscall uses fewer.
- Memory addresses in `ctx["args"]` are guest addresses; use `read_memory`/`write_memory` to access them.
- Errors in hook callbacks are printed to stderr but don't crash the emulation.

---

# Microhook Coverage - DRCov Code Coverage Generation

Microhook Coverage generates DRCov format coverage files during emulation, compatible with coverage visualization tools like [Lighthouse](https://github.com/gaasedelen/lighthouse) for IDA Pro, Binary Ninja, and Ghidra.

## Usage

```bash
microhook-<arch> -coverage <output_file> ./your_binary [args...]
```

Or using an environment variable:

```bash
QEMU_COVERAGE=output.drcov microhook-<arch> ./your_binary [args...]
```

## Output Filename Format Specifiers

The output filename supports format specifiers for dynamic naming:

| Specifier | Description | Example |
|-----------|-------------|---------|
| `%d` | Current date and time (`YYYY-MM-DD-HH:MM:SS`) | `2025-12-15-13:31:01` |
| `%s` | Program name (basename of binary) | `procd` |
| `%%` | Literal `%` character | `%` |

### Examples

```bash
# Simple filename
microhook-mipsel -coverage coverage.drcov ./myprogram

# With date/time stamp
microhook-mipsel -coverage 'coverage-%d.drcov' ./myprogram
# Output: coverage-2025-12-15-13:31:01.drcov

# With program name
microhook-mipsel -coverage '%s.drcov' /sbin/procd
# Output: procd.drcov

# Combined
microhook-mipsel -coverage 'TEST-%d-%s.drcov' /sbin/procd
# Output: TEST-2025-12-15-13:31:01-procd.drcov

# Organized by date
microhook-mipsel -coverage 'coverage/%d-%s.drcov' ./target
# Output: coverage/2025-12-15-13:31:01-target.drcov
```

## Features

### Automatic Periodic Flushing

Coverage data is automatically written to disk every 100 new basic blocks. This ensures that coverage data is preserved even if the target program crashes or is terminated unexpectedly.

### Block Deduplication

Each unique basic block is recorded only once, regardless of how many times it is executed. This keeps the coverage file compact.

### DRCov Format Compatibility

The output uses DRCov version 2 format, which is compatible with DRCov tools such as Lighthouse & bncov.

## Output File Format

The generated file follows the DRCov specification:

```
DRCOV VERSION: 2
DRCOV FLAVOR: drcov-64
Module Table: version 2, count 1
Columns: id, base, end, entry, path
0, 0x10000, 0x20000, 0x10100, /path/to/binary
BB Table: 1234 bbs
<binary basic block data>
```

Each basic block entry in the binary section is 8 bytes:
- 4 bytes: offset from module base
- 2 bytes: block size
- 2 bytes: module ID (always 0 for single binary)

## Using with Lighthouse

1. Generate coverage:
   ```bash
   microhook-mipsel -coverage program.drcov ./program
   ```

2. Open the target binary in IDA Pro, Binary Ninja, or Ghidra

3. Load Lighthouse and import the `.drcov` file

4. View the coverage highlighting in the disassembly

## Combining with Microhook

Coverage and syscall hooking can be used together:

```bash
microhook-mipsel -coverage output.drcov -hook hooks.py ./program
```

This allows you to both collect coverage data and intercept/modify syscalls in the same run.

## Notes

- Coverage is recorded at translation time, so all executed code paths are captured
- Only blocks within the main binary's code section are included in the output
- The coverage file is a complete snapshot each time it's written (not incremental)
- Use shell quoting for filenames with special characters: `-coverage 'file-%d.drcov'`
