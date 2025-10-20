cmake_minimum_required(VERSION 3.12)
project(libseccomp VERSION 2.5.4 LANGUAGES C)

# 明确设置版本变量
set(SECCOMP_VER_MAJOR 2)
set(SECCOMP_VER_MINOR 5)
set(SECCOMP_VER_MICRO 4)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 平台检测
if(ANDROID)
    add_definitions(-DHAVE_LINUX_SECCOMP_H=1 -DHAVE_SYS_PRCTL_H=1)
endif()

# 配置头文件
configure_file(include/configure.h.in configure.h @ONLY)
configure_file(include/seccomp.h.in seccomp.h @ONLY)

# 包含目录
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}
)

# 创建支持多平台的系统调用实现
set(GENERATED_SYSCALLS ${CMAKE_CURRENT_BINARY_DIR}/syscalls.c)
file(WRITE ${GENERATED_SYSCALLS} "
#include <seccomp.h>
#include <string.h>

/* 多平台系统调用号定义 */
#if defined(__aarch64__)
    /* AArch64 系统调用号 */
    #ifndef __NR_openat
    #define __NR_openat   56
    #endif
    #ifndef __NR_close
    #define __NR_close    57
    #endif
    #ifndef __NR_read
    #define __NR_read     63
    #endif
    #ifndef __NR_write
    #define __NR_write    64
    #endif
    #ifndef __NR_fstat
    #define __NR_fstat    80
    #endif
    #ifndef __NR_fcntl
    #define __NR_fcntl    25
    #endif
    #ifndef __NR_ioctl
    #define __NR_ioctl    29
    #endif

#elif defined(__arm__)
    /* ARM 32-bit 系统调用号 */
    #ifndef __NR_openat
    #define __NR_openat   322
    #endif
    #ifndef __NR_close
    #define __NR_close    6
    #endif
    #ifndef __NR_read
    #define __NR_read     3
    #endif
    #ifndef __NR_write
    #define __NR_write    4
    #endif
    #ifndef __NR_fstat
    #define __NR_fstat    108
    #endif
    #ifndef __NR_fcntl
    #define __NR_fcntl    55
    #endif
    #ifndef __NR_ioctl
    #define __NR_ioctl    54
    #endif

#elif defined(__i386__)
    /* x86 系统调用号 */
    #ifndef __NR_openat
    #define __NR_openat   295
    #endif
    #ifndef __NR_close
    #define __NR_close    6
    #endif
    #ifndef __NR_read
    #define __NR_read     3
    #endif
    #ifndef __NR_write
    #define __NR_write    4
    #endif
    #ifndef __NR_fstat
    #define __NR_fstat    108
    #endif
    #ifndef __NR_fcntl
    #define __NR_fcntl    55
    #endif
    #ifndef __NR_ioctl
    #define __NR_ioctl    54
    #endif

#elif defined(__x86_64__)
    /* x86_64 系统调用号 */
    #ifndef __NR_openat
    #define __NR_openat   257
    #endif
    #ifndef __NR_close
    #define __NR_close    3
    #endif
    #ifndef __NR_read
    #define __NR_read     0
    #endif
    #ifndef __NR_write
    #define __NR_write    1
    #endif
    #ifndef __NR_fstat
    #define __NR_fstat    5
    #endif
    #ifndef __NR_fcntl
    #define __NR_fcntl    72
    #endif
    #ifndef __NR_ioctl
    #define __NR_ioctl    16
    #endif

#else
    /* 默认使用 AArch64 */
    #ifndef __NR_openat
    #define __NR_openat   56
    #endif
    #ifndef __NR_close
    #define __NR_close    57
    #endif
    #ifndef __NR_read
    #define __NR_read     63
    #endif
    #ifndef __NR_write
    #define __NR_write    64
    #endif
    #ifndef __NR_fstat
    #define __NR_fstat    80
    #endif
    #ifndef __NR_fcntl
    #define __NR_fcntl    25
    #endif
    #ifndef __NR_ioctl
    #define __NR_ioctl    29
    #endif
#endif

/* 其他通用系统调用号 */
#ifndef __NR_mmap
#define __NR_mmap     222
#endif

#ifndef __NR_munmap
#define __NR_munmap   215
#endif

#ifndef __NR_brk
#define __NR_brk      214
#endif

#ifndef __NR_clone
#define __NR_clone    220
#endif

#ifndef __NR_execve
#define __NR_execve   221
#endif

#ifndef __NR_exit
#define __NR_exit     93
#endif

#ifndef __NR_exit_group
#define __NR_exit_group 94
#endif

/* 系统调用解析函数 */
const char *syscall_resolve_name(int num) {
    switch(num) {
        /* 文件操作 */
        case __NR_openat: return \"openat\";
        case __NR_close: return \"close\";
        case __NR_read: return \"read\";
        case __NR_write: return \"write\";
        case __NR_fstat: return \"fstat\";
        case __NR_fcntl: return \"fcntl\";
        case __NR_ioctl: return \"ioctl\";
        case __NR_mmap: return \"mmap\";
        case __NR_munmap: return \"munmap\";
        case __NR_brk: return \"brk\";

        /* 进程管理 */
        case __NR_clone: return \"clone\";
        case __NR_execve: return \"execve\";
        case __NR_exit: return \"exit\";
        case __NR_exit_group: return \"exit_group\";

        default: return NULL;
    }
}

int syscall_resolve_num(const char *name) {
    if (name == NULL) return -1;

    if (strcmp(name, \"openat\") == 0) return __NR_openat;
    if (strcmp(name, \"close\") == 0) return __NR_close;
    if (strcmp(name, \"read\") == 0) return __NR_read;
    if (strcmp(name, \"write\") == 0) return __NR_write;
    if (strcmp(name, \"fstat\") == 0) return __NR_fstat;
    if (strcmp(name, \"fcntl\") == 0) return __NR_fcntl;
    if (strcmp(name, \"ioctl\") == 0) return __NR_ioctl;
    if (strcmp(name, \"mmap\") == 0) return __NR_mmap;
    if (strcmp(name, \"munmap\") == 0) return __NR_munmap;
    if (strcmp(name, \"brk\") == 0) return __NR_brk;
    if (strcmp(name, \"clone\") == 0) return __NR_clone;
    if (strcmp(name, \"execve\") == 0) return __NR_execve;
    if (strcmp(name, \"exit\") == 0) return __NR_exit;
    if (strcmp(name, \"exit_group\") == 0) return __NR_exit_group;

    return -1;
}

const char *syscall_resolve_name_kver(int num, unsigned int kver) {
    return syscall_resolve_name(num);
}

int syscall_resolve_num_kver(const char *name, unsigned int kver) {
    return syscall_resolve_num(name);
}

int syscall_iterate(unsigned int arch, void *data,
                   int (*fn)(void *data, int num, const char *name)) {
    const struct {
        int num;
        const char *name;
    } syscalls[] = {
        {__NR_openat, \"openat\"},
        {__NR_close, \"close\"},
        {__NR_read, \"read\"},
        {__NR_write, \"write\"},
        {__NR_fstat, \"fstat\"},
        {__NR_fcntl, \"fcntl\"},
        {__NR_ioctl, \"ioctl\"},
        {__NR_mmap, \"mmap\"},
        {__NR_munmap, \"munmap\"},
        {__NR_brk, \"brk\"},
        {__NR_clone, \"clone\"},
        {__NR_execve, \"execve\"},
        {__NR_exit, \"exit\"},
        {__NR_exit_group, \"exit_group\"},
        {-1, NULL}
    };

    int i, rc;
    for (i = 0; syscalls[i].num != -1; i++) {
        rc = fn(data, syscalls[i].num, syscalls[i].name);
        if (rc != 0)
            return rc;
    }
    return 0;
}

/* ABI 函数 */
const char *abi_syscall_resolve_name_munge(const struct arch_def *arch, int num) {
    return syscall_resolve_name(num);
}

int abi_syscall_resolve_num_munge(const struct arch_def *arch, const char *name) {
    return syscall_resolve_num(name);
}

int abi_syscall_rewrite(const struct arch_def *arch, struct db_filter *db) {
    return 0;
}

int abi_rule_add(const struct arch_def *arch, struct db_filter *db,
                const struct scmp_arg_cmp *args, size_t arg_cnt, int action) {
    return 0;
}
")


# 通用源文件
set(LIBSECCOMP_COMMON_SOURCES
        src/api.c
        src/system.c
        src/helper.c
        src/gen_pfc.c
        src/gen_bpf.c
        src/hash.c
        src/db.c
        src/arch.c
        src/syscalls.c
        ${GENERATED_SYSCALLS}
)
# 架构特定源文件
set(LIBSECCOMP_ARCH_SOURCES
        src/arch-x86.c
        src/arch-x86_64.c
        src/arch-x32.c
        src/arch-arm.c
        src/arch-aarch64.c
        src/arch-mips.c
        src/arch-mips64.c
        src/arch-mips64n32.c
        src/arch-ppc.c
        src/arch-ppc64.c
        src/arch-s390.c
        src/arch-s390x.c
        src/arch-riscv64.c
        src/arch-parisc.c
        src/arch-parisc64.c
        src/arch-m68k.c
        src/arch-sh.c
        src/arch-loongarch64.c
)

# 合并所有源文件
set(LIBSECCOMP_ALL_SOURCES
        ${LIBSECCOMP_COMMON_SOURCES}
        ${LIBSECCOMP_ARCH_SOURCES}
)

# 创建库
add_library(seccomp STATIC ${LIBSECCOMP_ALL_SOURCES})
target_compile_definitions(seccomp PRIVATE HAVE_CONFIG_H)

# 导出接口
target_include_directories(seccomp PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

message(STATUS "libseccomp ready for use")