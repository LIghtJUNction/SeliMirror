/* SPDX-License-Identifier: GPL-2.0-only */
/* Query behavior derived from ReSukiSU/BakaSU, pinned in UPSTREAM.md. */
#include "core.h"

#ifdef RSK_HOST_TEST
#include <errno.h>
#else
#include <linux/errno.h>
#endif

int rsk_is_app(unsigned int real_uid)
{
	return real_uid >= 10000U;
}

int rsk_equal(const char *a, const char *b)
{
	if (!a || !b)
		return a == b;
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* The target kernel's lib/ctype.c also treats 0xa0 as whitespace. */
static int rsk_space(unsigned char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r') || c == 0xa0;
}

static size_t skip_space(const char *input, size_t length, size_t offset)
{
	while (offset < length && rsk_space((unsigned char)input[offset]))
		offset++;
	return offset;
}

static int parse_span(const char *input, size_t length, size_t *offset,
		      struct rsk_span *span)
{
	*offset = skip_space(input, length, *offset);
	span->offset = *offset;
	while (*offset < length && input[*offset] &&
	       !rsk_space((unsigned char)input[*offset]))
		(*offset)++;
	span->length = *offset - span->offset;
	return span->length ? 0 : -EINVAL;
}

int rsk_parse_access(const char *input, size_t length,
		     struct rsk_access_request *request)
{
	size_t pos = 0;
	unsigned short tclass = 0;

	if (!input || !request ||
	    parse_span(input, length, &pos, &request->source) ||
	    parse_span(input, length, &pos, &request->target))
		return -EINVAL;
	pos = skip_space(input, length, pos);
	/* Match the kernel's sscanf("%s %s %hu"): no sign, decimal prefix,
	 * truncation to u16, and no requirement to consume trailing input.
	 */
	if (pos == length || input[pos] < '0' || input[pos] > '9')
		return -EINVAL;
	do {
		tclass = (unsigned short)(tclass * 10U + (unsigned int)(input[pos] - '0'));
		pos++;
	} while (pos < length && input[pos] >= '0' && input[pos] <= '9');
	request->tclass = tclass;
	return 0;
}

static int clean_context(const struct rsk_query_ops *ops, const char *context,
			 size_t length, unsigned int *sid)
{
	unsigned int live_sid;
	int error = ops->private_context(ops->context, context, length, sid);

	/* As upstream, ordinary queries ignore a live lookup error. Do not
	 * register contexts rejected by the baseline in the live SID table.
	 */
	if (!error)
		(void)ops->live_context(ops->context, context, length, &live_sid);
	return error;
}

long rsk_query_context(const struct rsk_query_ops *ops, char *buffer,
		       size_t length, size_t capacity)
{
	char *canonical = NULL;
	unsigned int sid, canonical_length = 0;
	long result;

	result = ops->permission(ops->context, RSK_CHECK_CONTEXT);
	if (result)
		return result;
	result = clean_context(ops, buffer, length, &sid);
	if (result)
		return result;
	result = ops->canonical(ops->context, sid, &canonical, &canonical_length);
	if (!result) {
		if (canonical_length > capacity)
			result = -ERANGE;
		else {
			ops->copy(ops->context, buffer, canonical, canonical_length);
			result = canonical_length;
		}
	}
	ops->release(ops->context, canonical);
	return result;
}

long rsk_query_access(const struct rsk_query_ops *ops, char *buffer,
		      size_t length, size_t capacity)
{
	struct rsk_access_request request;
	struct rsk_avd avd = { 0, 0, 0, 0, 0 };
	unsigned int ssid, tsid;
	int result;

	result = ops->permission(ops->context, RSK_COMPUTE_AV);
	if (result)
		return result;
	result = rsk_parse_access(buffer, length, &request);
	if (result)
		return result;
	result = clean_context(ops, buffer + request.source.offset,
			       request.source.length, &ssid);
	if (result)
		return result;
	result = clean_context(ops, buffer + request.target.offset,
			       request.target.length, &tsid);
	if (result)
		return result;
	ops->compute_av(ops->context, ssid, tsid, request.tclass, &avd);
	avd.seqno = 1;
	result = ops->format_av(ops->context, buffer, capacity, &avd);
	if (result >= 0 && (size_t)result >= capacity)
		return -ERANGE;
	return result;
}

int rsk_precheck_current(const struct rsk_query_ops *ops, char *value,
			 size_t *length)
{
	unsigned int sid;
	int result = ops->permission(ops->context, RSK_SET_CURRENT);

	if (result)
		return result;
	if (*length && value[0] && value[0] != '\n') {
		if (value[*length - 1] == '\n') {
			value[*length - 1] = '\0';
			--*length;
		}
		return ops->private_context(ops->context, value, *length, &sid);
	}
	/* The original setprocattr handler performs live SID lookup and all
	 * real transition checks, including the empty-context error path.
	 */
	return 0;
}
