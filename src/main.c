/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/security.h>

#include "security.h"
#include "objsec.h"
#include "av_permissions.h"
#include "flask.h"
#include "core.h"
#include "gateway.h"
#include "kernel_api.h"
#include "kp_api.h"
#include "policy.h"
#include "build_profile.h"

#define RSK_MAX_POLICY_SIZE (32UL * 1024 * 1024)
#define RSK_MAX_HOOKS 5

KPM_NAME("selimirror");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Module contributors");
KPM_DESCRIPTION("ReSukiSU SELinux query-policy port for Xiaomi MIUI 4.14.268; experimental");

enum capture_stage { CAPTURE_WAITING, CAPTURE_CLAIMED, CAPTURE_READY, CAPTURE_FAILED };

struct hook_slot {
	const char *name;
	void *function;
	int nargs;
	void *before;
	void *after;
};

struct status_image {
	u32 version, sequence, enforcing, policyload, deny_unknown;
};

static struct kp_gate_pool gates;
static struct hook_slot slots[RSK_MAX_HOOKS];
static unsigned int installed_hooks;
static int init_succeeded;
static struct rsk_policy *baseline;
static void *status_memory;
static struct page *status_page;
static int status_published;
static int requested_enabled;
static int snapshot_stage;
static int snapshot_error;
static int capture_mode;
static void *capture_cookie;
static unsigned long baseline_bytes;
static unsigned long long query_count[4];

static struct rsk_policy *active_policy(void)
{
	if (!__atomic_load_n(&requested_enabled, __ATOMIC_ACQUIRE))
		return NULL;
	return __atomic_load_n(&baseline, __ATOMIC_ACQUIRE);
}

static int app_caller(void)
{
	return rsk_is_app(__kuid_val(current_uid()));
}

static int query_permission(void *context, enum rsk_permission permission)
{
	const struct task_security_struct *security = current_cred()->security;
	u32 sid = security->sid;

	(void)context;
	if (permission == RSK_SET_CURRENT)
		return rsk_api.avc_has_perm(rsk_api.live_state, sid, sid,
					    SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
	return rsk_api.avc_has_perm(rsk_api.live_state, sid, SECINITSID_SECURITY,
				    SECCLASS_SECURITY,
				    permission == RSK_CHECK_CONTEXT ?
				    SECURITY__CHECK_CONTEXT : SECURITY__COMPUTE_AV, NULL);
}

static int private_context(void *context, const char *text, size_t length, u32 *sid)
{
	return rsk_policy_context_to_sid(context, text, length, sid);
}

static int live_context(void *context, const char *text, size_t length, u32 *sid)
{
	(void)context;
	if (length > (u32)~0U)
		return -E2BIG;
	return rsk_api.context_to_sid(rsk_api.live_state, text, (u32)length, sid, GFP_KERNEL);
}

static int canonical_context(void *context, u32 sid, char **text, u32 *length)
{
	return rsk_policy_sid_to_context(context, sid, text, length);
}

static void release_context(void *context, void *allocation)
{
	(void)context;
	rsk_api.kfree(allocation);
}

static void copy_context(void *context, void *destination, const void *source, size_t length)
{
	(void)context;
	(rsk_api.memcpy)(destination, source, length);
}

static void compute_access(void *context, u32 ssid, u32 tsid, u16 tclass,
			   struct rsk_avd *result)
{
	struct av_decision avd = { 0 };

	rsk_policy_compute_av(context, ssid, tsid, tclass, &avd);
	result->allowed = avd.allowed;
	result->auditallow = avd.auditallow;
	result->auditdeny = avd.auditdeny;
	result->seqno = avd.seqno;
	result->flags = avd.flags;
}

static int format_access(void *context, char *buffer, size_t capacity,
			 const struct rsk_avd *avd)
{
	(void)context;
	return rsk_api.snprintf(buffer, capacity, "%x %x %x %x %u %x",
		avd->allowed, 0xffffffffU, avd->auditallow, avd->auditdeny,
		avd->seqno, avd->flags);
}

static struct rsk_query_ops query_ops(struct rsk_policy *policy)
{
	struct rsk_query_ops ops = {
		.context = policy,
		.permission = query_permission,
		.private_context = private_context,
		.live_context = live_context,
		.canonical = canonical_context,
		.release = release_context,
		.copy = copy_context,
		.compute_av = compute_access,
		.format_av = format_access,
	};
	return ops;
}

static void context_before(void *arguments, void *unused)
{
	hook_fargs3_t *args = arguments;
	struct rsk_policy *policy = active_policy();
	struct rsk_query_ops ops;

	(void)unused;
	if (!policy || !app_caller() || args->skip_origin)
		return;
	ops = query_ops(policy);
	__atomic_fetch_add(&query_count[0], 1, __ATOMIC_RELAXED);
	args->ret = (u64)rsk_query_context(&ops, (char *)args->arg1,
		(size_t)args->arg2, SIMPLE_TRANSACTION_LIMIT);
	args->skip_origin = 1;
}

static void access_before(void *arguments, void *unused)
{
	hook_fargs3_t *args = arguments;
	struct rsk_policy *policy = active_policy();
	struct rsk_query_ops ops;

	(void)unused;
	if (!policy || !app_caller() || args->skip_origin)
		return;
	ops = query_ops(policy);
	__atomic_fetch_add(&query_count[1], 1, __ATOMIC_RELAXED);
	args->ret = (u64)rsk_query_access(&ops, (char *)args->arg1,
		(size_t)args->arg2, SIMPLE_TRANSACTION_LIMIT);
	args->skip_origin = 1;
}

static void current_before(void *arguments, void *unused)
{
	hook_fargs3_t *args = arguments;
	struct rsk_policy *policy = active_policy();
	struct rsk_query_ops ops;
	size_t length = (size_t)args->arg2;
	int error;

	(void)unused;
	if (!policy || !app_caller() || args->skip_origin ||
	    !rsk_equal((const char *)args->arg0, "current"))
		return;
	ops = query_ops(policy);
	__atomic_fetch_add(&query_count[2], 1, __ATOMIC_RELAXED);
	error = rsk_precheck_current(&ops, (char *)args->arg1, &length);
	args->arg2 = length;
	if (error) {
		args->ret = (u64)(long)error;
		args->skip_origin = 1;
	}
	/* Native selinux_setprocattr handles the real SID, credentials, ptrace,
	 * dynamic transition, and bounded-transition checks after this point.
	 */
}

static void status_before(void *arguments, void *unused)
{
	hook_fargs1_t *args = arguments;

	(void)unused;
	if (!active_policy() || !app_caller() || args->skip_origin ||
	    (void *)args->arg0 != rsk_api.live_state)
		return;
	__atomic_fetch_add(&query_count[3], 1, __ATOMIC_RELAXED);
	/* Native open owns a raw page pointer, and native read/mmap retain it.
	 * There is no release callback; once returned, keep this page to reboot.
	 */
	__atomic_store_n(&status_published, 1, __ATOMIC_RELEASE);
	args->ret = (unsigned long)status_page;
	args->skip_origin = 1;
}

static void publish_policy(struct rsk_policy *policy, unsigned long bytes)
{
	struct status_image *status = status_memory;

	status->version = 1;
	status->sequence = 0;
	status->enforcing = 1;
	status->policyload = 0;
	status->deny_unknown = rsk_policy_deny_unknown(policy);
	__atomic_store_n(&baseline_bytes, bytes, __ATOMIC_RELEASE);
	__atomic_store_n(&snapshot_error, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&baseline, policy, __ATOMIC_RELEASE);
	__atomic_store_n(&snapshot_stage, CAPTURE_READY, __ATOMIC_RELEASE);
}

static void capture_before(void *arguments, void *unused)
{
	hook_fargs3_t *args = arguments;
	int expected = CAPTURE_WAITING;

	(void)unused;
	if ((void *)args->arg0 != rsk_api.live_state || args->skip_origin ||
	    READ_ONCE(rsk_api.live_state->initialized))
		return;
	if (__atomic_compare_exchange_n(&snapshot_stage, &expected, CAPTURE_CLAIMED,
		false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		__atomic_store_n(&capture_cookie, arguments, __ATOMIC_RELEASE);
}

static void capture_after(void *arguments, void *unused)
{
	hook_fargs3_t *args = arguments;
	struct rsk_policy *policy;
	int error;

	(void)unused;
	if (__atomic_load_n(&capture_cookie, __ATOMIC_ACQUIRE) != arguments)
		return;
	__atomic_store_n(&capture_cookie, NULL, __ATOMIC_RELEASE);
	if ((int)args->ret) {
		__atomic_store_n(&snapshot_error, (int)args->ret, __ATOMIC_RELEASE);
		__atomic_store_n(&snapshot_stage, CAPTURE_WAITING, __ATOMIC_RELEASE);
		return;
	}
	if (!READ_ONCE(rsk_api.live_state->initialized))
		policy = ERR_PTR(-EPROTO);
	else if (!args->arg1 || !args->arg2 || args->arg2 > RSK_MAX_POLICY_SIZE)
		policy = ERR_PTR(-EFBIG);
	else
		policy = rsk_policy_create((void *)args->arg1, (size_t)args->arg2);
	if (IS_ERR(policy)) {
		error = PTR_ERR(policy);
		__atomic_store_n(&snapshot_error, error, __ATOMIC_RELEASE);
		__atomic_store_n(&snapshot_stage, CAPTURE_FAILED, __ATOMIC_RELEASE);
		rsk_api.printk("\0013selimirror: initial policy snapshot failed: %d\n", error);
		return;
	}
	publish_policy(policy, (unsigned long)args->arg2);
	rsk_api.printk("\0016selimirror: initial input policy captured (%lu bytes)\n",
		       __atomic_load_n(&baseline_bytes, __ATOMIC_RELAXED));
}

static struct rsk_policy *read_policy_file(const char *path, unsigned long *bytes)
{
	struct file *file;
	struct rsk_policy *policy;
	void *blob = NULL;
	loff_t size, position = 0;
	ssize_t result;
	char extra;
	int error;

	/* A live policy dump after rooting is not a known-clean baseline. */
	if (rsk_equal(path, "/sys/fs/selinux/policy"))
		return ERR_PTR(-EINVAL);
	file = rsk_api.filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(file))
		return ERR_CAST(file);
	if (!S_ISREG(file_inode(file)->i_mode)) {
		error = -EINVAL;
		goto close_file;
	}
	size = i_size_read(file_inode(file));
	if (size <= 0 || size > RSK_MAX_POLICY_SIZE) {
		error = -EFBIG;
		goto close_file;
	}
	blob = rsk_api.vmalloc((unsigned long)size);
	if (!blob) {
		error = -ENOMEM;
		goto close_file;
	}
	while (position < size) {
		loff_t old_position = position;

		result = rsk_api.kernel_read(file, (char *)blob + position,
			(size_t)(size - position), &position);
		if (result <= 0 || position != old_position + result) {
			error = result < 0 ? (int)result : -EIO;
			goto close_file;
		}
	}
	result = rsk_api.kernel_read(file, &extra, 1, &position);
	if (result) {
		error = result < 0 ? (int)result : -EFBIG;
		goto close_file;
	}
	error = rsk_api.filp_close(file, NULL);
	if (error) {
		rsk_api.vfree(blob);
		return ERR_PTR(error);
	}
	policy = rsk_policy_create(blob, (size_t)size);
	rsk_api.vfree(blob);
	if (!IS_ERR(policy))
		*bytes = (unsigned long)size;
	return policy;

close_file:
	if (blob)
		rsk_api.vfree(blob);
	(void)rsk_api.filp_close(file, NULL);
	return ERR_PTR(error);
}

static int prepare_slot(unsigned int index, const char *name, int nargs,
			kp_gate_handler_t before, kp_gate_handler_t after)
{
	struct hook_slot *slot = &slots[index];

	slot->name = name;
	slot->function = (void *)kp_native_symbol(name);
	slot->nargs = nargs;
	if (!slot->function) {
		rsk_api.printk("\0013selimirror: missing hook %s\n", name);
		return -ENOENT;
	}
	if (before) {
		slot->before = kp_gate_create(&gates, before, NULL);
		if (!slot->before)
			return -ENOMEM;
	}
	if (after) {
		slot->after = kp_gate_create(&gates, after, NULL);
		if (!slot->after)
			return -ENOMEM;
	}
	return 0;
}

static long rsk_exit(void *reserved)
{
	struct rsk_policy *policy;

	(void)reserved;
	__atomic_store_n(&requested_enabled, 0, __ATOMIC_RELEASE);
	/* The loader unlinks before exit but drains RCU too late, and its
	 * SDK synchronize_rcu wrapper is broken on this 4.14 kernel. Use the
	 * real kernel function to finish any earlier control call ourselves.
	 */
	if (init_succeeded) {
		rsk_api.synchronize_rcu();
		init_succeeded = 0;
		__atomic_store_n(&requested_enabled, 0, __ATOMIC_RELEASE);
	}
	/* Closed resident gateways are safe even when a dispatcher has already
	 * fetched their addresses. Drain before freeing any module-owned state.
	 */
	kp_gate_close_all(&gates);
	kp_gate_drain(&gates);
	while (installed_hooks) {
		struct hook_slot *slot = &slots[--installed_hooks];

		kp_hook_unwrap_remove(slot->function, slot->before, slot->after, 0);
	}
	kp_gate_pool_release(&gates);
	policy = __atomic_exchange_n(&baseline, NULL, __ATOMIC_ACQ_REL);
	if (policy)
		rsk_policy_destroy(policy);
	if (status_memory && !__atomic_load_n(&status_published, __ATOMIC_ACQUIRE))
		rsk_api.vfree(status_memory);
	status_memory = NULL;
	status_page = NULL;
	return 0;
}

static long rsk_init(const char *arguments, const char *event, void *reserved)
{
	struct kp_gate_ops gate_ops;
	struct rsk_policy *policy = NULL;
	unsigned int count, i;
	const char *path = NULL;
	int error;

	(void)reserved;
	if (!arguments || !arguments[0] || rsk_equal(arguments, "capture"))
		capture_mode = 1;
	else if (arguments[0] == 'p' && arguments[1] == 'o' &&
		 arguments[2] == 'l' && arguments[3] == 'i' &&
		 arguments[4] == 'c' && arguments[5] == 'y' &&
		 arguments[6] == '=' && arguments[7] == '/')
		path = arguments + 7;
	else
		return -EINVAL;

	error = rsk_api_init();
	if (error)
		return error;
	if (capture_mode && READ_ONCE(rsk_api.live_state->initialized)) {
		rsk_api.printk("\0013selimirror: too late for capture; use pre-exec-init or policy=/absolute/clean-policy\n");
		return -EAGAIN;
	}
	if (path) {
		if (!READ_ONCE(rsk_api.live_state->initialized))
			return -EAGAIN;
		policy = read_policy_file(path, &baseline_bytes);
		if (IS_ERR(policy))
			return PTR_ERR(policy);
	}
	status_memory = rsk_api.vmalloc_user(PAGE_SIZE);
	if (!status_memory) {
		error = -ENOMEM;
		goto free_unpublished_policy;
	}
	status_page = rsk_api.vmalloc_to_page(status_memory);
	if (!status_page) {
		error = -EFAULT;
		goto free_unpublished_policy;
	}
	if (policy) {
		publish_policy(policy, baseline_bytes);
		policy = NULL;
	}
	gate_ops.module_alloc = rsk_api.module_alloc;
	gate_ops.vfree = rsk_api.vfree;
	gate_ops.flush_icache_range = rsk_api.flush_icache_range;
	gate_ops.kick_all_cpus_sync = rsk_api.kick_all_cpus_sync;
	gate_ops.msleep = rsk_api.msleep;
	error = kp_gate_pool_init(&gates, &gate_ops, PAGE_SIZE);
	if (error)
		goto rollback;
	error = prepare_slot(0, "sel_write_context", 3, context_before, NULL);
	if (error)
		goto rollback;
	error = prepare_slot(1, "sel_write_access", 3, access_before, NULL);
	if (error)
		goto rollback;
	error = prepare_slot(2, "selinux_setprocattr", 3, current_before, NULL);
	if (error)
		goto rollback;
	error = prepare_slot(3, "selinux_kernel_status_page", 1, status_before, NULL);
	if (error)
		goto rollback;
	count = 4;
	if (capture_mode) {
		error = prepare_slot(4, "security_load_policy", 3, capture_before, capture_after);
		if (error)
			goto rollback;
		count++;
	}
	for (i = 0; i < count; i++) {
		struct hook_slot *slot = &slots[i];

		kp_gate_mark_published(&gates);
		error = (int)kp_hook_wrap(slot->function, slot->nargs,
					 slot->before, slot->after, NULL);
		if (error) {
			rsk_api.printk("\0013selimirror: hook %s failed: %d\n", slot->name, error);
			goto rollback;
		}
		installed_hooks++;
	}
	__atomic_store_n(&requested_enabled, 1, __ATOMIC_RELEASE);
	init_succeeded = 1;
	rsk_api.printk("\0016selimirror: %s; event=%s; config=%s\n",
		capture_mode ? "armed for initial policy" : "baseline loaded",
		event ? event : "(none)", RSK_CONFIG_SHA256);
	return 0;

free_unpublished_policy:
	if (policy)
		rsk_policy_destroy(policy);
rollback:
	rsk_exit(NULL);
	return error;
}

static long rsk_control(const char *arguments, char __user *output, int capacity)
{
	char message[448];
	const char *state;
	int length, stage, command = -1, enabled;

	if (!output || capacity <= 0)
		return -EINVAL;
	if (arguments && rsk_equal(arguments, "on")) {
		if (!__atomic_load_n(&baseline, __ATOMIC_ACQUIRE))
			return -EAGAIN;
		command = 1;
	} else if (arguments && rsk_equal(arguments, "off")) {
		command = 0;
	} else if (arguments && arguments[0] && !rsk_equal(arguments, "status")) {
		return -EINVAL;
	}
	stage = __atomic_load_n(&snapshot_stage, __ATOMIC_ACQUIRE);
	enabled = command >= 0 ? command :
		__atomic_load_n(&requested_enabled, __ATOMIC_ACQUIRE);
	state = stage == CAPTURE_FAILED ? "error" :
		stage != CAPTURE_READY ? "armed" :
		enabled ? "on" : "off";
	length = rsk_api.snprintf(message, sizeof(message),
		"state=%s source=%s bytes=%lu error=%d hooks=%u "
		"context=%llu access=%llu current=%llu status=%llu "
		"target=%s config=%s\n", state, capture_mode ? "initial-input" : "file",
		__atomic_load_n(&baseline_bytes, __ATOMIC_ACQUIRE),
		__atomic_load_n(&snapshot_error, __ATOMIC_ACQUIRE),
		installed_hooks,
		__atomic_load_n(&query_count[0], __ATOMIC_RELAXED),
		__atomic_load_n(&query_count[1], __ATOMIC_RELAXED),
		__atomic_load_n(&query_count[2], __ATOMIC_RELAXED),
		__atomic_load_n(&query_count[3], __ATOMIC_RELAXED),
		RSK_KERNEL_RELEASE, RSK_CONFIG_SHA256);
	if (length < 0 || length >= sizeof(message) || capacity <= length)
		return -ENOSPC;
	if (kp_compat_copy_to_user(output, message, length + 1) != length + 1)
		return -EFAULT;
	if (command >= 0)
		__atomic_store_n(&requested_enabled, command, __ATOMIC_RELEASE);
	return 0;
}

KPM_INIT(rsk_init);
KPM_CTL0(rsk_control);
KPM_EXIT(rsk_exit);
