/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Private SELinux query state for the pinned Xiaomi miui 4.14.268 kernel.
 * This deliberately uses that kernel's headers: it has both the state API
 * and pointer-based SID table backports, plus an 8-byte queued rwlock.
 */
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>

#include "security.h"
#include "ss/services.h"
#include "ss/sidtab.h"

#include "kernel_api.h"
#include "policy.h"

/*
 * Only the three query service APIs below may use this state. Its AVC,
 * class mapping, status page, and status mutex are intentionally unused.
 * Never pass it to security_load_policy() or selinux_ss_init(): those
 * functions also change global kernel state in the target kernel.
 */
struct rsk_policy {
	struct selinux_state state;
	struct selinux_ss ss;
	struct sidtab sidtab;
};

struct rsk_policy *rsk_policy_create(const void *blob, size_t len)
{
	struct policy_file file = { .data = (char *)blob, .len = len };
	struct rsk_policy *policy;
	int error;

	if (!blob || !len)
		return ERR_PTR(-EINVAL);

	policy = rsk_api.vmalloc(sizeof(*policy));
	if (!policy)
		return ERR_PTR(-ENOMEM);
	(rsk_api.memset)(policy, 0, sizeof(*policy));

	/* sidtab size and rwlock layout come from the prepared target config. */
	rwlock_init(&policy->ss.policy_rwlock);
	policy->state.ss = &policy->ss;
	policy->ss.sidtab = &policy->sidtab;

	error = rsk_api.policydb_read(&policy->ss.policydb, &file);
	if (error)
		goto free_state;
	/* policydb_read() does not set the original binary length. */
	policy->ss.policydb.len = len;

	error = rsk_api.policydb_load_isids(&policy->ss.policydb,
					  &policy->sidtab);
	if (error)
		goto destroy_policydb;

	/* Match ReSukiSU's stable userspace access-decision sequence number. */
	policy->ss.latest_granting = 1;
	enforcing_set(&policy->state, true);
	policy->state.android_netlink_route =
		policy->ss.policydb.android_netlink_route;
	policy->state.android_netlink_getneigh =
		policy->ss.policydb.android_netlink_getneigh;
	policy->state.initialized = true;
	return policy;

destroy_policydb:
	/* policydb_load_isids() already destroys its SID table on failure. */
	rsk_api.policydb_destroy(&policy->ss.policydb);
free_state:
	/* policydb_read() already frees partial policy contents on failure. */
	rsk_api.vfree(policy);
	return ERR_PTR(error);
}

void rsk_policy_destroy(struct rsk_policy *policy)
{
	if (IS_ERR_OR_NULL(policy))
		return;

	/* The owner must stop new queries and drain existing ones first. */
	rsk_api.sidtab_destroy(&policy->sidtab);
	rsk_api.policydb_destroy(&policy->ss.policydb);
	rsk_api.vfree(policy);
}

int rsk_policy_context_to_sid(struct rsk_policy *policy, const char *context,
			      size_t len, u32 *sid)
{
	/* The native service takes u32, while transaction sizes use size_t. */
	if (len > (u32)~0U)
		return -E2BIG;

	return rsk_api.context_to_sid(&policy->state, context, (u32)len,
				      sid, GFP_KERNEL);
}

int rsk_policy_sid_to_context(struct rsk_policy *policy, u32 sid,
			      char **context, u32 *len)
{
	return rsk_api.sid_to_context(&policy->state, sid, context, len);
}

void rsk_policy_compute_av(struct rsk_policy *policy, u32 ssid, u32 tsid,
			   u16 tclass, struct av_decision *avd)
{
	rsk_api.compute_av_user(&policy->state, ssid, tsid, tclass, avd);
}

bool rsk_policy_deny_unknown(const struct rsk_policy *policy)
{
	return !policy->ss.policydb.allow_unknown;
}
