/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch ABI bridge for builds using the target kernel's real headers.
 *
 * Interface definitions adapted from KernelPatch, Copyright (C) 2023 bmax121:
 * https://github.com/bmax121/KernelPatch/tree/ef52c62b339bd2da51880922249bf4edef71b1cf
 *   kernel/include/kpmodule.h
 *   kernel/include/hook.h
 *   kernel/base/start.c
 *   kernel/base/symbol.c
 *
 * Do not add the KernelPatch Linux placeholder headers to the include path.
 * Do not merge the native-kernel and KernelPatch symbol namespaces: the KPM
 * loader resolves imports only from KernelPatch's export table. In particular,
 * its "kallsyms_lookup_name" and "printk" exports are pointer VARIABLES, whereas
 * the native kernel symbols with those names are FUNCTIONS. The C aliases
 * below preserve that distinction when native headers are also included.
 */
#ifndef RESUKISU_KP_API_H
#define RESUKISU_KP_API_H

#include <linux/compiler.h>
#include <linux/types.h>

#define KP_ABI_SOURCE_COMMIT "ef52c62b339bd2da51880922249bf4edef71b1cf"
#define KP_VERSION_CODE(major, minor, patch) \
    (((major) << 16) + ((minor) << 8) + (patch))

/* These are KernelPatch data exports, not native kernel function imports. */
extern unsigned long (*kp_kallsyms_lookup_name)(const char *name)
    __asm__("kallsyms_lookup_name");
extern u32 kp_kernel_version __asm__("kver");
extern u32 kp_version __asm__("kpver");

/* This export is a function. It searches KernelPatch exports only. */
extern unsigned long kp_symbol_lookup_name(const char *name)
    __asm__("symbol_lookup_name");

/* Native kernel calls must use a correctly typed pointer resolved this way. */
static inline unsigned long kp_native_symbol(const char *name)
{
    return kp_kallsyms_lookup_name ? kp_kallsyms_lookup_name(name) : 0;
}

/* The size limit includes the string's final NUL byte, as in upstream. */
#define KPM_INFO(name, info, limit) \
    _Static_assert(sizeof(info) <= (limit), "KPM metadata string too long"); \
    static const char __kpm_info_##name[] \
        __attribute__((used, section(".kpm.info"), aligned(1))) = #name "=" info

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024

#define KPM_NAME(value) KPM_INFO(name, value, KPM_NAME_LEN)
#define KPM_VERSION(value) KPM_INFO(version, value, KPM_VERSION_LEN)
#define KPM_LICENSE(value) KPM_INFO(license, value, KPM_LICENSE_LEN)
#define KPM_AUTHOR(value) KPM_INFO(author, value, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(value) KPM_INFO(description, value, KPM_DESCRIPTION_LEN)

typedef long (*mod_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*mod_ctl0call_t)(const char *args, char __user *out, int outlen);
typedef long (*mod_ctl1call_t)(void *arg1, void *arg2, void *arg3);
typedef long (*mod_exitcall_t)(void *reserved);
typedef long (*mod_eventcall_t)(const char *event, const char *args, void *reserved);

#define KPM_INIT(fn) \
    static mod_initcall_t __kpm_initcall_##fn \
        __attribute__((used, section(".kpm.init"))) = (fn)
#define KPM_CTL0(fn) \
    static mod_ctl0call_t __kpm_ctl0call_##fn \
        __attribute__((used, section(".kpm.ctl0"))) = (fn)
#define KPM_CTL1(fn) \
    static mod_ctl1call_t __kpm_ctl1call_##fn \
        __attribute__((used, section(".kpm.ctl1"))) = (fn)
#define KPM_EXIT(fn) \
    static mod_exitcall_t __kpm_exitcall_##fn \
        __attribute__((used, section(".kpm.exit"))) = (fn)
#define KPM_EVENT(fn) \
    static mod_eventcall_t __kpm_eventcall_##fn \
        __attribute__((used, section(".kpm.event"))) = (fn)

/* Upstream returns the NEGATIVE of these error values. */
typedef enum {
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
    HOOK_BAD_RELO = 4092,
    HOOK_TRANSIT_NO_MEM = 4091,
    HOOK_CHAIN_FULL = 4090,
} hook_err_t;

#define HOOK_LOCAL_DATA_NUM 8
typedef struct {
    union {
        struct {
            u64 data0, data1, data2, data3;
            u64 data4, data5, data6, data7;
        };
        u64 data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

/*
 * The same argument object and local slots are shared by ALL chain entries.
 * local and ret are not initialized by the dispatcher before before-callbacks.
 * Every callback that sets skip_origin must also set ret. Keep per-callback
 * state in the resident gateway context, not in these shared local slots.
 */
typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    u64 ret;
} __attribute__((aligned(8))) hook_fargs0_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    u64 ret;
    union {
        struct { u64 arg0, arg1, arg2, arg3; };
        u64 args[4];
    };
} __attribute__((aligned(8))) hook_fargs4_t;

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    u64 ret;
    union {
        struct {
            u64 arg0, arg1, arg2, arg3;
            u64 arg4, arg5, arg6, arg7;
        };
        u64 args[8];
    };
} __attribute__((aligned(8))) hook_fargs8_t;

typedef hook_fargs8_t hook_fargs5_t;
typedef hook_fargs8_t hook_fargs6_t;
typedef hook_fargs8_t hook_fargs7_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    u64 ret;
    union {
        struct {
            u64 arg0, arg1, arg2, arg3;
            u64 arg4, arg5, arg6, arg7;
            u64 arg8, arg9, arg10, arg11;
        };
        u64 args[12];
    };
} __attribute__((aligned(8))) hook_fargs12_t;

typedef hook_fargs12_t hook_fargs9_t;
typedef hook_fargs12_t hook_fargs10_t;
typedef hook_fargs12_t hook_fargs11_t;

#define KP_HOOK_CALLBACK(n) \
    typedef void (*hook_chain##n##_callback)(hook_fargs##n##_t *, void *)
KP_HOOK_CALLBACK(0);
KP_HOOK_CALLBACK(1);
KP_HOOK_CALLBACK(2);
KP_HOOK_CALLBACK(3);
KP_HOOK_CALLBACK(4);
KP_HOOK_CALLBACK(5);
KP_HOOK_CALLBACK(6);
KP_HOOK_CALLBACK(7);
KP_HOOK_CALLBACK(8);
KP_HOOK_CALLBACK(9);
KP_HOOK_CALLBACK(10);
KP_HOOK_CALLBACK(11);
KP_HOOK_CALLBACK(12);
#undef KP_HOOK_CALLBACK

extern hook_err_t kp_hook_wrap(void *function, s32 nargs, void *before,
                               void *after, void *context) __asm__("hook_wrap");

/*
 * Always pass remove = 0 for this module. Upstream's remove = 1 immediately
 * frees the trampoline, even when a CPU may still be executing inside it.
 */
extern void kp_hook_unwrap_remove(void *function, void *before, void *after,
                                  int remove) __asm__("hook_unwrap_remove");

/* Unlike Linux copy_to_user(), the result is the number of bytes COPIED. */
extern int kp_compat_copy_to_user(void __user *to, const void *from, int bytes)
    __asm__("compat_copy_to_user");

_Static_assert(sizeof(void *) == 8, "KernelPatch requires a 64-bit target");
_Static_assert(sizeof(hook_local_t) == 64, "KernelPatch local ABI changed");
_Static_assert(sizeof(hook_fargs0_t) == 88, "KernelPatch zero-argument ABI changed");
_Static_assert(sizeof(hook_fargs4_t) == 120, "KernelPatch four-argument ABI changed");
_Static_assert(sizeof(hook_fargs8_t) == 152, "KernelPatch eight-argument ABI changed");
_Static_assert(sizeof(hook_fargs12_t) == 184, "KernelPatch twelve-argument ABI changed");
_Static_assert(__builtin_offsetof(hook_fargs4_t, local) == 16,
               "KernelPatch local offset changed");
_Static_assert(__builtin_offsetof(hook_fargs4_t, ret) == 80,
               "KernelPatch return-value offset changed");
_Static_assert(__builtin_offsetof(hook_fargs4_t, arg0) == 88,
               "KernelPatch argument offset changed");

#endif
