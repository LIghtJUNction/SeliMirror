/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RESUKISU_GATEWAY_H
#define RESUKISU_GATEWAY_H

/* Shared constants also used by the relocation-free assembly template. */
#define KP_GATE_STRIDE 192
#define KP_GATE_STATE_OFFSET 128
#define KP_GATE_HANDLER_OFFSET 136
#define KP_GATE_CONTEXT_OFFSET 144

#ifndef __ASSEMBLY__
#include <linux/types.h>

#define KP_GATE_CLOSED (1ULL << 63)
#define KP_GATE_ACTIVE_MASK (KP_GATE_CLOSED - 1)

typedef void (*kp_gate_handler_t)(void *args, void *context);

/* Resolve every operation through kp_native_symbol(), not KP's export table. */
struct kp_gate_ops {
    void *(*module_alloc)(unsigned long bytes);
    void (*vfree)(const void *address);
    void (*flush_icache_range)(unsigned long start, unsigned long end);
    void (*kick_all_cpus_sync)(void);
    void (*msleep)(unsigned int milliseconds);
};

struct kp_gate_pool {
    unsigned char *base;
    unsigned long bytes;
    unsigned int used;
    bool published;
    bool closed;
    struct kp_gate_ops ops;
};

/*
 * Call from a sleepable context, with lifecycle operations serialized.
 * The pool object must initially be zeroed. One target PAGE_SIZE allocation
 * holds PAGE_SIZE / KP_GATE_STRIDE callbacks (21 for a 4096-byte page).
 */
int kp_gate_pool_init(struct kp_gate_pool *pool, const struct kp_gate_ops *ops,
                     unsigned long bytes);
void *kp_gate_create(struct kp_gate_pool *pool, kp_gate_handler_t handler,
                     void *context);

/*
 * Call BEFORE passing any entry address to hook_wrap, even if that attempt
 * later returns an error. Once exposed, the executable page is retained until
 * reboot because upstream does not provide dispatcher quiescence.
 */
void kp_gate_mark_published(struct kp_gate_pool *pool);

/* close_all is nonblocking. drain closes the pool and sleeps until its handlers
 * have returned to resident code. Never call drain/release from KPM_CTL0 or
 * inside a callback. The supported loader must run KPM_EXIT outside RCU.
 */
void kp_gate_close_all(struct kp_gate_pool *pool);
void kp_gate_drain(struct kp_gate_pool *pool);

/*
 * Close and drain, erase module handler/context pointers, free only a page
 * that was never published, and reset the pool object. Repeated calls are OK.
 * Detach hook slots with hook_unwrap_remove(..., 0) after close/drain and
 * before this call. The retained gateways remain safe for stale dispatchers.
 */
void kp_gate_pool_release(struct kp_gate_pool *pool);

#endif /* !__ASSEMBLY__ */
#endif
