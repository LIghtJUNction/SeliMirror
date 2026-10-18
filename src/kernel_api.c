/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <generated/utsrelease.h>

#include "security.h"
#include "core.h"
#include "kernel_api.h"
#include "kp_api.h"
#include "kp_offsets.h"

struct rsk_kernel_api rsk_api;

static int release_matches(const char *banner)
{
	const char prefix[] = "Linux version ";
	const char expected[] = UTS_RELEASE;
	unsigned int i;

	if (!banner)
		return 0;
	for (i = 0; i < sizeof(prefix) - 1; i++)
		if (banner[i] != prefix[i])
			return 0;
	banner += sizeof(prefix) - 1;
	for (i = 0; i < sizeof(expected) - 1; i++)
		if (banner[i] != expected[i])
			return 0;
	return banner[i] == ' ';
}

int rsk_api_init(void)
{
	const struct rsk_kp_task_offsets *task_offsets;
	const struct rsk_kp_cred_offsets *cred_offsets;

	/* ABI is audited against this KP release, not inferred from Linux age. */
	if (kp_version != KP_VERSION_CODE(0, 13, 9))
		return -EPROTONOSUPPORT;

#define RSK_RESOLVE(field, name) do { \
	rsk_api.field = (typeof(rsk_api.field))kp_native_symbol(name); \
	if (!rsk_api.field) { \
		if (rsk_api.printk) \
			rsk_api.printk("\0013selimirror: missing symbol %s\n", name); \
		return -ENOENT; \
	} \
} while (0)

	RSK_RESOLVE(printk, "printk");
	RSK_RESOLVE(linux_banner, "linux_banner");
	if (!release_matches(rsk_api.linux_banner)) {
		rsk_api.printk("\0013selimirror: requires kernel release %s\n",
			       UTS_RELEASE);
		return -EPROTONOSUPPORT;
	}
	RSK_RESOLVE(live_state, "selinux_state");
	RSK_RESOLVE(kmalloc, "__kmalloc");
	RSK_RESOLVE(kfree, "kfree");
	RSK_RESOLVE(vmalloc, "vmalloc");
	RSK_RESOLVE(vmalloc_user, "vmalloc_user");
	RSK_RESOLVE(vfree, "vfree");
	RSK_RESOLVE(vmalloc_to_page, "vmalloc_to_page");
	RSK_RESOLVE(memset, "memset");
	RSK_RESOLVE(memcpy, "memcpy");
	RSK_RESOLVE(snprintf, "snprintf");
	RSK_RESOLVE(policydb_read, "policydb_read");
	RSK_RESOLVE(policydb_destroy, "policydb_destroy");
	RSK_RESOLVE(policydb_load_isids, "policydb_load_isids");
	RSK_RESOLVE(sidtab_destroy, "sidtab_destroy");
	RSK_RESOLVE(context_to_sid, "security_context_to_sid");
	RSK_RESOLVE(sid_to_context, "security_sid_to_context");
	RSK_RESOLVE(compute_av_user, "security_compute_av_user");
	RSK_RESOLVE(avc_has_perm, "avc_has_perm");
	RSK_RESOLVE(filp_open, "filp_open");
	RSK_RESOLVE(filp_close, "filp_close");
	RSK_RESOLVE(kernel_read, "kernel_read");
	RSK_RESOLVE(module_alloc, "module_alloc");
	RSK_RESOLVE(flush_icache_range, "__flush_icache_range");
	RSK_RESOLVE(kick_all_cpus_sync, "kick_all_cpus_sync");
	RSK_RESOLVE(msleep, "msleep");
	RSK_RESOLVE(synchronize_rcu, "synchronize_rcu");
#undef RSK_RESOLVE

	task_offsets = (void *)kp_symbol_lookup_name("task_struct_offset");
	cred_offsets = (void *)kp_symbol_lookup_name("cred_offset");
	if (!task_offsets || !cred_offsets ||
	    task_offsets->cred != __builtin_offsetof(struct task_struct, cred) ||
	    cred_offsets->uid != __builtin_offsetof(struct cred, uid) ||
	    cred_offsets->security != __builtin_offsetof(struct cred, security)) {
		rsk_api.printk("\0013selimirror: task/cred layout differs from build config\n");
		return -EPROTONOSUPPORT;
	}

	/* A pre-kernel-init load is too early. pre-exec-init is supported. */
	if (!rsk_api.live_state->ss || !rsk_api.live_state->avc ||
	    rsk_api.live_state->disabled)
		return -EAGAIN;
	return 0;
}
