/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch UAPI constants and command layout are adapted from
 * user/supercall.h and kernel/patch/include/uapi/scdefs.h:
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * https://github.com/bmax121/KernelPatch/tree/ef52c62b339bd2da51880922249bf4edef71b1cf
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(__linux__) || defined(__ILP32__)
#error "rskctl supports only 64-bit AArch64 Linux/Android; syscall 45 is architecture-specific"
#endif
_Static_assert(sizeof(long) == 8, "64-bit syscall argument ABI is required");

#define KP_SYSCALL 45L
#define KP_VERSION 0x00000d09UL
#define KP_HELLO 0x1000U
#define KP_GET_VERSION 0x1008U
#define KP_LOAD 0x1020U
#define KP_UNLOAD 0x1021U
#define KP_CONTROL 0x1022U
#define KP_HELLO_MAGIC 0x11581158L
#define KP_KEY_CAPACITY 64U
#define KP_ARGUMENT_CAPACITY 1024U
#define MODULE_NAME "selimirror"

static char superkey[KP_KEY_CAPACITY];

static void wipe(void *memory, size_t size)
{
    volatile unsigned char *p = memory;
    while (size--)
        *p++ = 0;
}

static void wipe_key(void)
{
    wipe(superkey, sizeof(superkey));
}

static void usage(FILE *stream)
{
    fputs("Usage: rskctl [--key-fd N] COMMAND\n"
          "  load /absolute/module.kpm capture|policy=/absolute/clean-policy\n"
          "  status | on | off | unload\n"
          "  --help\n\n"
          "Read a 1..63 byte superkey from descriptor N (default: stdin).\n"
          "Input ends at a newline or EOF; NUL and CR bytes are rejected.\n"
          "Terminal input is refused; use a protected file or pipe.\n"
          "The key is never accepted through command arguments or environment.\n"
          "Example: rskctl --key-fd 3 status 3</path/to/protected-key-file\n\n"
          "Requires KernelPatch 0.13.9 (ef52c62) and the matching module.\n"
          "Commands set protocol bit 63 so an unhandled syscall 45 has a\n"
          "negative truncate length and cannot resize a file.\n", stream);
}

static int parse_fd(const char *text, int *fd)
{
    unsigned int value = 0;
    if (!text[0])
        return -1;
    for (; *text; ++text) {
        unsigned int digit = (unsigned char)*text - (unsigned int)'0';
        if (digit > 9 || value > ((unsigned int)INT_MAX - digit) / 10)
            return -1;
        value = value * 10 + digit;
    }
    *fd = (int)value;
    return 0;
}

static int read_key(int fd)
{
    size_t length = 0;
    unsigned char byte = 0;
    int result = -1;

    if (isatty(fd)) {
        fputs("Refusing terminal key input; use a protected file or pipe.\n", stderr);
        return -1;
    }
    for (;;) {
        ssize_t count = read(fd, &byte, 1);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Cannot read key descriptor: %s\n", strerror(errno));
            break;
        }
        if (!count || byte == '\n') {
            if (!length) {
                fputs("The key is empty.\n", stderr);
                break;
            }
            superkey[length] = '\0';
            result = 0;
            break;
        }
        if (!byte || byte == '\r') {
            fputs("The key contains a NUL or CR byte.\n", stderr);
            break;
        }
        if (length == sizeof(superkey) - 1) {
            fputs("The key exceeds 63 bytes.\n", stderr);
            break;
        }
        superkey[length++] = (char)byte;
    }
    wipe(&byte, sizeof(byte));
    return result;
}

static long kp_call(unsigned int command, const void *arg1, const void *arg2,
                    void *arg3, long arg4)
{
    /*
     * Pinned KP kernel/patch/common/supercall.c before() decodes only low16;
     * its upper version/magic checks are commented out. Keep that layout,
     * but set bit63 for EVERY call, including hello/authentication failure.
     * The pinned Xiaomi kernel (bd65f57), fs/open.c do_sys_truncate(), checks
     * length < 0 BEFORE user_path_at(). If KP is absent or does not handle
     * the request, syscall45 therefore returns EINVAL without resolving a
     * pathname or resizing any file. Future KP protocols are unsupported.
     */
    uint64_t packed = (UINT64_C(1) << 63) | ((uint64_t)KP_VERSION << 32)
                    | (UINT64_C(0x1158) << 16) | (command & 0xffffU);
    return syscall(KP_SYSCALL, superkey, (long)packed,
                   arg1, arg2, arg3, arg4);
}

static int syscall_error(const char *operation, long result)
{
    /* libc syscall() translates -errno to -1 and sets errno. */
    if (result == -1) {
        int error = errno;
        fprintf(stderr, "%s failed: %s (errno %d).\n",
                operation, strerror(error), error);
        return -1;
    }
    if (result < 0) {
        fprintf(stderr, "%s returned an unexpected negative result.\n", operation);
        return -1;
    }
    return 0;
}

static int authenticate(void)
{
    long result = kp_call(KP_HELLO, NULL, NULL, NULL, 0);
    if (syscall_error("KernelPatch hello", result))
        return -1;
    if (result != KP_HELLO_MAGIC) {
        fputs("KernelPatch hello was not recognized; no module command was sent.\n", stderr);
        return -1;
    }
    result = kp_call(KP_GET_VERSION, NULL, NULL, NULL, 0);
    if (syscall_error("KernelPatch version query", result))
        return -1;
    if ((unsigned long)result != KP_VERSION) {
        fprintf(stderr, "Requires KernelPatch 0.13.9 (0x%08lx); got 0x%08lx.\n",
                KP_VERSION, (unsigned long)result);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char output[4096] = { 0 };
    const char *action, *module_path = NULL, *load_args = NULL;
    int first = 1, key_fd = STDIN_FILENO;
    long result;

    if (first < argc && !strcmp(argv[first], "--key-fd")) {
        if (first + 1 == argc || parse_fd(argv[first + 1], &key_fd)) {
            fputs("--key-fd requires a nonnegative decimal file descriptor.\n", stderr);
            return 2;
        }
        first += 2;
    }
    if (first < argc && !strcmp(argv[first], "--help") && first + 1 == argc) {
        usage(stdout);
        return 0;
    }
    if (first == argc) {
        usage(stderr);
        return 2;
    }
    action = argv[first];
    if (!strcmp(action, "load")) {
        if (argc - first != 3) {
            usage(stderr);
            return 2;
        }
        module_path = argv[first + 1];
        load_args = argv[first + 2];
        if (module_path[0] != '/' || strlen(module_path) >= KP_ARGUMENT_CAPACITY ||
            strlen(load_args) >= KP_ARGUMENT_CAPACITY ||
            (strcmp(load_args, "capture") && strncmp(load_args, "policy=/", 8))) {
            fputs("load requires an absolute module path and capture or policy=/absolute/path; "
                  "each argument must be shorter than 1024 bytes.\n", stderr);
            return 2;
        }
    } else if (argc - first != 1 ||
               (strcmp(action, "status") && strcmp(action, "on") &&
                strcmp(action, "off") && strcmp(action, "unload"))) {
        usage(stderr);
        return 2;
    }

    if (atexit(wipe_key)) {
        fputs("Cannot register key cleanup.\n", stderr);
        return 1;
    }
    if (read_key(key_fd) || authenticate())
        return 1;

    if (module_path)
        result = kp_call(KP_LOAD, module_path, load_args, NULL, 0);
    else if (!strcmp(action, "unload"))
        result = kp_call(KP_UNLOAD, MODULE_NAME, NULL, NULL, 0);
    else
        result = kp_call(KP_CONTROL, MODULE_NAME, action, output, sizeof(output));
    if (syscall_error(action, result))
        return 1;
    if (result != 0) {
        fputs("Module command returned an unexpected nonzero result.\n", stderr);
        return 1;
    }
    if (!module_path && strcmp(action, "unload")) {
        if (!memchr(output, '\0', sizeof(output))) {
            fputs("Module reply is not terminated within the userspace buffer.\n", stderr);
            return 1;
        }
        if (fputs(output, stdout) == EOF)
            return 1;
    } else {
        if (puts(module_path ? "Module loaded." : "Module unloaded.") == EOF)
            return 1;
    }
    return 0;
}
