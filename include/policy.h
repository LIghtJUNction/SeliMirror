/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RSK_POLICY_H
#define RSK_POLICY_H

#include <linux/types.h>

struct av_decision;
struct rsk_policy;

/*
 * Parse an independent policy. The input can be released after this returns.
 * Returns ERR_PTR(-errno) on failure. Calls can allocate and must be sleepable.
 * The caller must keep the object alive until all queries have completed.
 */
struct rsk_policy *rsk_policy_create(const void *blob, size_t len);
void rsk_policy_destroy(struct rsk_policy *policy);

/* SIDs returned here belong only to this private policy, never to live tasks. */
int rsk_policy_context_to_sid(struct rsk_policy *policy, const char *context,
			      size_t len, u32 *sid);

/* On success, *context must be freed with the kernel's kfree implementation. */
int rsk_policy_sid_to_context(struct rsk_policy *policy, u32 sid,
			      char **context, u32 *len);

/* tclass is a policy class number, as supplied to selinuxfs/access. */
void rsk_policy_compute_av(struct rsk_policy *policy, u32 ssid, u32 tsid,
			   u16 tclass, struct av_decision *avd);
bool rsk_policy_deny_unknown(const struct rsk_policy *policy);

#endif
