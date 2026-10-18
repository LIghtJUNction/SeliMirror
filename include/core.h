/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RSK_CORE_H
#define RSK_CORE_H

#ifdef RSK_HOST_TEST
#include <stddef.h>
#else
#include <linux/types.h>
#endif

enum rsk_permission {
	RSK_CHECK_CONTEXT,
	RSK_COMPUTE_AV,
	RSK_SET_CURRENT,
};

struct rsk_span {
	size_t offset;
	size_t length;
};

struct rsk_access_request {
	struct rsk_span source;
	struct rsk_span target;
	unsigned short tclass;
};

struct rsk_avd {
	unsigned int allowed, auditallow, auditdeny, seqno, flags;
};

struct rsk_query_ops {
	void *context;
	int (*permission)(void *, enum rsk_permission);
	int (*private_context)(void *, const char *, size_t, unsigned int *);
	int (*live_context)(void *, const char *, size_t, unsigned int *);
	int (*canonical)(void *, unsigned int, char **, unsigned int *);
	void (*release)(void *, void *);
	void (*copy)(void *, void *, const void *, size_t);
	void (*compute_av)(void *, unsigned int, unsigned int,
			   unsigned short, struct rsk_avd *);
	int (*format_av)(void *, char *, size_t, const struct rsk_avd *);
};

int rsk_is_app(unsigned int real_uid);
int rsk_equal(const char *a, const char *b);
int rsk_parse_access(const char *input, size_t length,
		     struct rsk_access_request *request);
long rsk_query_context(const struct rsk_query_ops *, char *, size_t, size_t);
long rsk_query_access(const struct rsk_query_ops *, char *, size_t, size_t);
/* Modifies one trailing newline only after the native SETCURRENT check. */
int rsk_precheck_current(const struct rsk_query_ops *, char *, size_t *);

#endif
