/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include "gateway.h"

extern const unsigned char kp_gate_template_start[];
extern const unsigned char kp_gate_template_end[];

/* This layout must match the embedded assembly state, not a kernel struct. */
struct kp_gate_state {
    u64 count;
    unsigned long handler;
    unsigned long context;
};

_Static_assert(sizeof(unsigned long) == 8, "gateway requires AArch64 pointers");
_Static_assert(sizeof(struct kp_gate_state) == 24, "gateway state ABI changed");
_Static_assert(KP_GATE_HANDLER_OFFSET == KP_GATE_STATE_OFFSET + 8,
               "gateway handler offset changed");
_Static_assert(KP_GATE_CONTEXT_OFFSET == KP_GATE_STATE_OFFSET + 16,
               "gateway context offset changed");
_Static_assert(KP_GATE_STATE_OFFSET + sizeof(struct kp_gate_state) <= KP_GATE_STRIDE,
               "gateway state exceeds its slot");

static struct kp_gate_state *gate_state(struct kp_gate_pool *pool,
                                        unsigned int index)
{
    return (struct kp_gate_state *)(pool->base + (unsigned long)index * KP_GATE_STRIDE +
                                   KP_GATE_STATE_OFFSET);
}

int kp_gate_pool_init(struct kp_gate_pool *pool, const struct kp_gate_ops *ops,
                     unsigned long bytes)
{
    if (!pool || !ops || !ops->module_alloc || !ops->vfree ||
        !ops->flush_icache_range || !ops->kick_all_cpus_sync || !ops->msleep)
        return -EINVAL;
    if (pool->base)
        return -EBUSY;
    if (bytes < KP_GATE_STRIDE || bytes / KP_GATE_STRIDE > (unsigned int)-1)
        return -EINVAL;
    if ((unsigned long)(kp_gate_template_end - kp_gate_template_start) !=
        KP_GATE_STRIDE)
        return -ENOEXEC;

    pool->base = ops->module_alloc(bytes);
    if (!pool->base)
        return -ENOMEM;
    /* Native module_alloc is page aligned. Refuse a broken allocator. */
    if ((unsigned long)pool->base & 63UL) {
        ops->vfree(pool->base);
        pool->base = 0;
        return -EINVAL;
    }
    pool->bytes = bytes;
    pool->used = 0;
    pool->published = false;
    pool->closed = false;
    pool->ops.module_alloc = ops->module_alloc;
    pool->ops.vfree = ops->vfree;
    pool->ops.flush_icache_range = ops->flush_icache_range;
    pool->ops.kick_all_cpus_sync = ops->kick_all_cpus_sync;
    pool->ops.msleep = ops->msleep;
    return 0;
}

void *kp_gate_create(struct kp_gate_pool *pool, kp_gate_handler_t handler,
                     void *context)
{
    struct kp_gate_state *state;
    unsigned char *entry;
    unsigned int i;

    if (!pool || !pool->base || pool->closed || !handler ||
        pool->used >= pool->bytes / KP_GATE_STRIDE)
        return 0;

    entry = pool->base + (unsigned long)pool->used * KP_GATE_STRIDE;
    /* Volatile byte writes avoid an unresolved compiler-generated memcpy. */
    for (i = 0; i < KP_GATE_STRIDE; ++i)
        ((volatile unsigned char *)entry)[i] = kp_gate_template_start[i];
    state = gate_state(pool, pool->used);
    state->handler = (unsigned long)handler;
    state->context = (unsigned long)context;
    __atomic_store_n(&state->count, 0, __ATOMIC_RELEASE);
    pool->ops.flush_icache_range((unsigned long)entry,
                                 (unsigned long)entry + KP_GATE_STRIDE);
    /* Match the target flush_icache_range wrapper: remote CPUs must also
     * undergo a context synchronization event before the code is published.
     */
    pool->ops.kick_all_cpus_sync();
    ++pool->used;
    return entry;
}

void kp_gate_mark_published(struct kp_gate_pool *pool)
{
    if (pool && pool->base)
        pool->published = true;
}

void kp_gate_close_all(struct kp_gate_pool *pool)
{
    unsigned int i;

    if (!pool || !pool->base)
        return;
    pool->closed = true;
    for (i = 0; i < pool->used; ++i)
        __atomic_fetch_or(&gate_state(pool, i)->count, KP_GATE_CLOSED,
                          __ATOMIC_ACQ_REL);
}

void kp_gate_drain(struct kp_gate_pool *pool)
{
    unsigned int i;
    bool busy;

    if (!pool || !pool->base)
        return;
    kp_gate_close_all(pool);
    do {
        busy = false;
        for (i = 0; i < pool->used; ++i) {
            if (__atomic_load_n(&gate_state(pool, i)->count, __ATOMIC_ACQUIRE) &
                KP_GATE_ACTIVE_MASK) {
                busy = true;
                break;
            }
        }
        if (busy)
            pool->ops.msleep(1);
    } while (busy);
}

void kp_gate_pool_release(struct kp_gate_pool *pool)
{
    unsigned int i;

    if (!pool || !pool->base)
        return;
    kp_gate_drain(pool);
    for (i = 0; i < pool->used; ++i) {
        struct kp_gate_state *state = gate_state(pool, i);

        __atomic_store_n(&state->handler, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&state->context, 0, __ATOMIC_RELEASE);
    }
    if (!pool->published)
        pool->ops.vfree(pool->base);
    pool->base = 0;
    pool->bytes = 0;
    pool->used = 0;
    pool->published = false;
    pool->closed = true;
    pool->ops.module_alloc = 0;
    pool->ops.vfree = 0;
    pool->ops.flush_icache_range = 0;
    pool->ops.kick_all_cpus_sync = 0;
    pool->ops.msleep = 0;
}
