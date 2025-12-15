if not have_linux_user
   subdir_done()
endif

linux_user_ss = ss.source_set()

common_user_inc += include_directories('include/host/' / host_arch)
common_user_inc += include_directories('include')

linux_user_ss.add(files(
  'elfload.c',
  'exit.c',
  'fd-trans.c',
  'linuxload.c',
  'main.c',
  'mmap.c',
  'signal.c',
  'strace.c',
  'syscall.c',
  'thunk.c',
  'microhook.c',
  'microhook-coverage.c',
  'uaccess.c',
  'uname.c',
))
linux_user_ss.add(rt)
linux_user_ss.add(libdw)

# Python embedding for Microhook (static linking)
python3_embed = dependency('python3-embed', required: true, static: get_option('prefer_static'))
linux_user_ss.add(python3_embed)

# Additional libraries needed for static Python
if get_option('prefer_static')
  linux_user_ss.add(cc.find_library('pthread', required: true))
  linux_user_ss.add(cc.find_library('dl', required: true))
  linux_user_ss.add(cc.find_library('util', required: true))
  linux_user_ss.add(cc.find_library('m', required: true))
  linux_user_ss.add(cc.find_library('z', required: false))
  linux_user_ss.add(cc.find_library('ffi', required: false))
endif

linux_user_ss.add(when: 'TARGET_HAS_BFLT', if_true: files('flatload.c'))
linux_user_ss.add(when: 'TARGET_I386', if_true: files('vm86.c'))
linux_user_ss.add(when: 'CONFIG_ARM_COMPATIBLE_SEMIHOSTING', if_true: files('semihost.c'))

if get_option('plugins')
  linux_user_ss.add(files('plugin-api.c'))
endif

syscall_nr_generators = {}

# Generate microhook.list from strace.list
microhook_list = custom_target('microhook.list',
  output: 'microhook.list',
  input: files('strace.list'),
  command: [python, files('gen-microhook-list.py'), '@INPUT@', '@OUTPUT@'])

# Add generated microhook.list as a dependency for microhook.c
linux_user_ss.add(microhook_list)

gen_vdso_exe = executable('gen-vdso', 'gen-vdso.c',
                          native: true, build_by_default: false)
gen_vdso = generator(gen_vdso_exe, output: '@BASENAME@.c.inc',
                     arguments: ['-o', '@OUTPUT@', '@EXTRA_ARGS@', '@INPUT@'])

subdir('aarch64')
subdir('alpha')
subdir('arm')
subdir('hexagon')
subdir('hppa')
subdir('i386')
subdir('loongarch64')
subdir('m68k')
subdir('microblaze')
subdir('mips64')
subdir('mips')
subdir('openrisc')
subdir('ppc')
subdir('riscv')
subdir('s390x')
subdir('sh4')
subdir('sparc')
subdir('x86_64')
subdir('xtensa')

specific_ss.add_all(when: 'CONFIG_LINUX_USER', if_true: linux_user_ss)
