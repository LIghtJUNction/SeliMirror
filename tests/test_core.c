/* SPDX-License-Identifier: GPL-2.0-only */
/* Host checks for the production parser and query ordering in src/core.c. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"

static unsigned int checks;
static const char *test_name;

#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, \
			test_name, #condition); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

struct fake_backend {
	char events[64];
	size_t event_count;
	int permission_error;
	enum rsk_permission permission;
	int private_errors[2];
	int live_errors[2];
	unsigned int private_calls, live_calls;
	char private_text[2][64], live_text[2][64];
	size_t private_lengths[2], live_lengths[2];
	int canonical_error;
	char canonical_text[64];
	unsigned int canonical_length, canonical_sid;
	unsigned int releases, copies;
	unsigned int computed_ssid, computed_tsid;
	unsigned short computed_class;
	struct rsk_avd decision, formatted_decision;
	size_t format_capacity;
	int format_error;
};

static void event(struct fake_backend *fake, char value)
{
	CHECK(fake->event_count + 1 < sizeof(fake->events));
	fake->events[fake->event_count++] = value;
	fake->events[fake->event_count] = '\0';
}

static int fake_permission(void *context, enum rsk_permission permission)
{
	struct fake_backend *fake = context;

	event(fake, 'p');
	fake->permission = permission;
	return fake->permission_error;
}

static void save_context(char *output, size_t capacity, const char *input,
			 size_t length)
{
	CHECK(length < capacity);
	memcpy(output, input, length);
	output[length] = '\0';
}

static int fake_private(void *context, const char *text, size_t length,
			unsigned int *sid)
{
	struct fake_backend *fake = context;
	unsigned int call = fake->private_calls++;

	event(fake, 'b');
	CHECK(call < 2);
	save_context(fake->private_text[call], sizeof(fake->private_text[call]),
		     text, length);
	fake->private_lengths[call] = length;
	if (fake->private_errors[call])
		return fake->private_errors[call];
	*sid = 101U + call;
	return 0;
}

static int fake_live(void *context, const char *text, size_t length,
		     unsigned int *sid)
{
	struct fake_backend *fake = context;
	unsigned int call = fake->live_calls++;

	event(fake, 'l');
	CHECK(call < 2);
	save_context(fake->live_text[call], sizeof(fake->live_text[call]),
		     text, length);
	fake->live_lengths[call] = length;
	if (fake->live_errors[call])
		return fake->live_errors[call];
	*sid = 901U + call;
	return 0;
}

static int fake_canonical(void *context, unsigned int sid, char **text,
			  unsigned int *length)
{
	struct fake_backend *fake = context;

	event(fake, 'c');
	fake->canonical_sid = sid;
	if (fake->canonical_error)
		return fake->canonical_error;
	CHECK(fake->canonical_length <= sizeof(fake->canonical_text));
	*text = malloc(fake->canonical_length);
	CHECK(*text != NULL);
	memcpy(*text, fake->canonical_text, fake->canonical_length);
	*length = fake->canonical_length;
	return 0;
}

static void fake_release(void *context, void *allocation)
{
	struct fake_backend *fake = context;

	event(fake, 'r');
	fake->releases++;
	free(allocation);
}

static void fake_copy(void *context, void *destination, const void *source,
		      size_t length)
{
	struct fake_backend *fake = context;

	event(fake, 'm');
	fake->copies++;
	memcpy(destination, source, length);
}

static void fake_compute(void *context, unsigned int ssid, unsigned int tsid,
			 unsigned short tclass, struct rsk_avd *result)
{
	struct fake_backend *fake = context;

	event(fake, 'a');
	fake->computed_ssid = ssid;
	fake->computed_tsid = tsid;
	fake->computed_class = tclass;
	*result = fake->decision;
}

static int fake_format(void *context, char *buffer, size_t capacity,
		       const struct rsk_avd *decision)
{
	struct fake_backend *fake = context;

	event(fake, 'f');
	fake->formatted_decision = *decision;
	fake->format_capacity = capacity;
	if (fake->format_error)
		return fake->format_error;
	return snprintf(buffer, capacity, "%x %x %x %x %u %x",
		decision->allowed, 0xffffffffU, decision->auditallow,
		decision->auditdeny, decision->seqno, decision->flags);
}

static struct rsk_query_ops setup(struct fake_backend *fake)
{
	struct rsk_query_ops ops = {
		.context = fake,
		.permission = fake_permission,
		.private_context = fake_private,
		.live_context = fake_live,
		.canonical = fake_canonical,
		.release = fake_release,
		.copy = fake_copy,
		.compute_av = fake_compute,
		.format_av = fake_format,
	};

	memset(fake, 0, sizeof(*fake));
	memcpy(fake->canonical_text, "u:r:stock:s0", sizeof("u:r:stock:s0"));
	fake->canonical_length = sizeof("u:r:stock:s0");
	fake->decision.allowed = 0xffffffffU;
	fake->decision.auditallow = 0xffffffffU;
	fake->decision.auditdeny = 0xffffffffU;
	fake->decision.seqno = 987654U;
	fake->decision.flags = 0xffffffffU;
	return ops;
}

static void check_events(const struct fake_backend *fake, const char *expected)
{
	CHECK(strcmp(fake->events, expected) == 0);
}

static void test_parser(void)
{
	struct parse_case {
		const char *input;
		size_t length;
		int expected;
		unsigned short tclass;
	};
#define CASE(text, error, number) { text, sizeof(text) - 1, error, number }
	static const struct parse_case cases[] = {
		CASE("A B 1", 0, 1),
		CASE(" A\tB\n00012 ", 0, 12),
		CASE("A B 0", 0, 0),
		CASE("A B 65535", 0, 65535),
		CASE("A B 65536", 0, 0),
		CASE("A B 65537", 0, 1),
		CASE("A B 18446744073709551615", 0, 65535),
		CASE("A B 18446744073709551616", 0, 0),
		CASE("A B 18446744073709551617", 0, 1),
		CASE("A B 340282366920938463463374607431768211455", 0, 65535),
		CASE("A B 340282366920938463463374607431768211456", 0, 0),
		CASE("A B 12tail", 0, 12),
		CASE("A B 0x10", 0, 0),
		CASE("A B 077", 0, 77),
		CASE("A B 1 extra", 0, 1),
		CASE("A B 1\0ignored", 0, 1),
		CASE("\xa0" "A\xa0" "B\xa0" "3", 0, 3),
		CASE("\t\n\v\f\r A B 4", 0, 4),
		CASE("", -EINVAL, 0),
		CASE(" ", -EINVAL, 0),
		CASE("A", -EINVAL, 0),
		CASE("A B", -EINVAL, 0),
		CASE("A B x", -EINVAL, 0),
		CASE("A B +1", -EINVAL, 0),
		CASE("A B -1", -EINVAL, 0),
		CASE("A B \xff", -EINVAL, 0),
		CASE("A\0 B 1", -EINVAL, 0),
		CASE("A B\0 1", -EINVAL, 0),
		CASE("A B \0 1", -EINVAL, 0),
		CASE("A B \x85" "1", -EINVAL, 0),
	};
#undef CASE
	struct rsk_access_request request;
	size_t i;

	test_name = "bounded access parser, target-kernel conversion cases";
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct parse_case *item = &cases[i];
		/* No implicit trailing NUL: ASan detects reads past the length. */
		char *bounded = malloc(item->length ? item->length : 1);

		CHECK(bounded != NULL);
		memcpy(bounded, item->input, item->length);
		CHECK(rsk_parse_access(bounded, item->length, &request) == item->expected);
		if (!item->expected) {
			CHECK(request.tclass == item->tclass);
			CHECK(request.source.length == 1);
			CHECK(request.target.length == 1);
			CHECK(request.source.offset < item->length);
			CHECK(request.target.offset < item->length);
			CHECK(bounded[request.source.offset] == 'A');
			CHECK(bounded[request.target.offset] == 'B');
		}
		CHECK(memcmp(bounded, item->input, item->length) == 0);
		free(bounded);
	}
	CHECK(rsk_parse_access(NULL, 0, &request) == -EINVAL);
	CHECK(rsk_parse_access("A B 1", 5, NULL) == -EINVAL);
	CHECK(rsk_parse_access("A B 1", 4, &request) == -EINVAL);
	CHECK(rsk_parse_access("alpha beta 5", 12, &request) == 0);
	CHECK(request.source.length == 5 && request.target.length == 4);
	CHECK(request.source.offset == 0 && request.target.offset == 6);
	{
		/* Largest input for the target's 4 KiB simple transaction page. */
		const size_t maximum = 4087;
		char *bounded = malloc(maximum);

		CHECK(bounded != NULL);
		memset(bounded, 'A', maximum);
		memcpy(bounded + maximum - 4, " B 1", 4);
		CHECK(rsk_parse_access(bounded, maximum, &request) == 0);
		CHECK(request.source.length == maximum - 4);
		CHECK(request.target.offset == maximum - 3 && request.target.length == 1);
		CHECK(request.tclass == 1);
		memset(bounded, '9', maximum);
		memcpy(bounded, "A B ", 4);
		CHECK(rsk_parse_access(bounded, maximum, &request) == 0);
		CHECK(request.tclass == 65535);
		free(bounded);
	}
}

static void test_context_queries(void)
{
	struct fake_backend fake;
	struct rsk_query_ops ops;
	char buffer[96];
	long result;
	size_t capacity;

	test_name = "context response uses transaction capacity and private SID";
	ops = setup(&fake);
	memset(buffer, 0x5a, sizeof(buffer));
	buffer[0] = 'X';
	capacity = fake.canonical_length;
	result = rsk_query_context(&ops, buffer, 1, capacity);
	CHECK(result == fake.canonical_length && result > 1);
	CHECK(memcmp(buffer, fake.canonical_text, capacity) == 0);
	CHECK((unsigned char)buffer[capacity] == 0x5a);
	CHECK(buffer[result - 1] == '\0');
	CHECK(fake.permission == RSK_CHECK_CONTEXT);
	CHECK(fake.canonical_sid == 101);
	CHECK(fake.private_lengths[0] == 1 && fake.live_lengths[0] == 1);
	CHECK(fake.releases == 1 && fake.copies == 1);
	check_events(&fake, "pblcmr");

	test_name = "context ignores live lookup failure after private acceptance";
	ops = setup(&fake);
	fake.live_errors[0] = -EINVAL;
	memcpy(buffer, "X", 2);
	CHECK(rsk_query_context(&ops, buffer, 1, sizeof(buffer)) == fake.canonical_length);
	CHECK(fake.canonical_sid == 101);
	check_events(&fake, "pblcmr");

	test_name = "context permission denial precedes any parsing";
	ops = setup(&fake);
	fake.permission_error = -EACCES;
	CHECK(rsk_query_context(&ops, NULL, 0, 0) == -EACCES);
	check_events(&fake, "p");

	test_name = "rejected private context does not reach live SID table";
	ops = setup(&fake);
	fake.private_errors[0] = -EINVAL;
	memcpy(buffer, "new_root_type", sizeof("new_root_type"));
	CHECK(rsk_query_context(&ops, buffer, strlen(buffer), sizeof(buffer)) == -EINVAL);
	CHECK(fake.live_calls == 0 && fake.copies == 0);
	CHECK(strcmp(buffer, "new_root_type") == 0);
	check_events(&fake, "pb");

	test_name = "private allocation failure retains its error";
	ops = setup(&fake);
	fake.private_errors[0] = -ENOMEM;
	CHECK(rsk_query_context(&ops, "X", 1, 2) == -ENOMEM);
	check_events(&fake, "pb");

	test_name = "canonical conversion error releases its optional result";
	ops = setup(&fake);
	fake.canonical_error = -ENOMEM;
	CHECK(rsk_query_context(&ops, "X", 1, 2) == -ENOMEM);
	CHECK(fake.releases == 1 && fake.copies == 0);
	check_events(&fake, "pblcr");

	test_name = "context response one byte over capacity is not copied";
	ops = setup(&fake);
	memset(buffer, 0x5a, sizeof(buffer));
	buffer[0] = 'X';
	CHECK(rsk_query_context(&ops, buffer, 1, fake.canonical_length - 1) == -ERANGE);
	CHECK(buffer[0] == 'X' && (unsigned char)buffer[1] == 0x5a);
	CHECK(fake.copies == 0 && fake.releases == 1);
	check_events(&fake, "pblcr");
}

static void test_access_queries(void)
{
	static const char expected[] =
		"ffffffff ffffffff ffffffff ffffffff 1 ffffffff";
	struct fake_backend fake;
	struct rsk_query_ops ops;
	char buffer[96];
	long result;
	size_t capacity;

	test_name = "access response exceeds input and preserves all six fields";
	ops = setup(&fake);
	memset(buffer, 0x5a, sizeof(buffer));
	memcpy(buffer, "A B 1", 5);
	capacity = sizeof(expected);
	result = rsk_query_access(&ops, buffer, 5, capacity);
	CHECK(result == (long)strlen(expected) && result > 5);
	CHECK(strcmp(buffer, expected) == 0);
	CHECK((unsigned char)buffer[capacity] == 0x5a);
	CHECK(fake.format_capacity == capacity);
	CHECK(fake.formatted_decision.seqno == 1);
	CHECK(fake.permission == RSK_COMPUTE_AV);
	CHECK(fake.computed_ssid == 101 && fake.computed_tsid == 102);
	CHECK(fake.computed_class == 1);
	CHECK(fake.private_lengths[0] == 1 && fake.private_lengths[1] == 1);
	CHECK(strcmp(fake.private_text[0], "A") == 0);
	CHECK(strcmp(fake.private_text[1], "B") == 0);
	CHECK(fake.live_lengths[0] == 1 && fake.live_lengths[1] == 1);
	check_events(&fake, "pblblaf");

	test_name = "access permission denial precedes malformed input";
	ops = setup(&fake);
	fake.permission_error = -EACCES;
	CHECK(rsk_query_access(&ops, NULL, 0, 0) == -EACCES);
	check_events(&fake, "p");

	test_name = "access malformed request has no SID side effects";
	ops = setup(&fake);
	CHECK(rsk_query_access(&ops, "A B -1", 6, 7) == -EINVAL);
	check_events(&fake, "p");

	test_name = "access rejected source prevents all live lookup";
	ops = setup(&fake);
	fake.private_errors[0] = -EINVAL;
	CHECK(rsk_query_access(&ops, "A B 1", 5, 6) == -EINVAL);
	CHECK(fake.live_calls == 0);
	check_events(&fake, "pb");

	test_name = "access rejected target may follow an accepted live source";
	ops = setup(&fake);
	fake.private_errors[1] = -EINVAL;
	CHECK(rsk_query_access(&ops, "A B 1", 5, 6) == -EINVAL);
	CHECK(fake.private_calls == 2 && fake.live_calls == 1);
	CHECK(strcmp(fake.live_text[0], "A") == 0);
	check_events(&fake, "pblb");

	test_name = "access ignores live errors and passes class zero to policy";
	ops = setup(&fake);
	fake.live_errors[0] = -ENOMEM;
	fake.live_errors[1] = -EINVAL;
	memcpy(buffer, "A B 65536", sizeof("A B 65536"));
	CHECK(rsk_query_access(&ops, buffer, strlen(buffer), sizeof(buffer)) > 0);
	CHECK(fake.computed_class == 0);
	CHECK(fake.computed_ssid == 101 && fake.computed_tsid == 102);
	check_events(&fake, "pblblaf");

	test_name = "access short response buffer returns range error without overflow";
	ops = setup(&fake);
	memset(buffer, 0x5a, sizeof(buffer));
	memcpy(buffer, "A B 1", 5);
	capacity = strlen(expected);
	CHECK(rsk_query_access(&ops, buffer, 5, capacity) == -ERANGE);
	CHECK(buffer[capacity - 1] == '\0');
	CHECK((unsigned char)buffer[capacity] == 0x5a);
	CHECK(fake.format_capacity == capacity);

	test_name = "zero output capacity cannot report a successful access response";
	ops = setup(&fake);
	memcpy(buffer, "A B 1", 6);
	CHECK(rsk_query_access(&ops, buffer, 5, 0) == -ERANGE);
	CHECK(memcmp(buffer, "A B 1", 6) == 0);

	test_name = "access formatting error is propagated";
	ops = setup(&fake);
	fake.format_error = -EIO;
	CHECK(rsk_query_access(&ops, "A B 1", 5, 6) == -EIO);
	check_events(&fake, "pblblaf");
}

static void test_current_precheck(void)
{
	struct fake_backend fake;
	struct rsk_query_ops ops;
	char value[16];
	size_t length;

	test_name = "current checks private context and delegates all live work";
	ops = setup(&fake);
	memcpy(value, "C\n", 3);
	length = 2;
	CHECK(rsk_precheck_current(&ops, value, &length) == 0);
	CHECK(fake.permission == RSK_SET_CURRENT);
	CHECK(length == 1 && value[0] == 'C' && value[1] == '\0');
	CHECK(fake.private_lengths[0] == 1);
	CHECK(fake.live_calls == 0 && fake.copies == 0 && fake.releases == 0);
	check_events(&fake, "pb");
	/* These are the actual buffer/length passed to the native handler.
	 * It sees no trailing newline and must retain this one-byte length.
	 */
	CHECK(value[length - 1] != '\n');

	test_name = "current without trailing newline retains its full length";
	ops = setup(&fake);
	memcpy(value, "C", 2);
	length = 1;
	CHECK(rsk_precheck_current(&ops, value, &length) == 0);
	CHECK(length == 1 && fake.private_lengths[0] == 1);
	check_events(&fake, "pb");

	test_name = "current NUL included in length reaches native policy intact";
	ops = setup(&fake);
	memcpy(value, "C", 2);
	length = 2;
	CHECK(rsk_precheck_current(&ops, value, &length) == 0);
	CHECK(length == 2 && fake.private_lengths[0] == 2);
	CHECK(fake.private_text[0][1] == '\0');

	test_name = "current permission error happens before newline mutation";
	ops = setup(&fake);
	fake.permission_error = -EACCES;
	memcpy(value, "C\n", 3);
	length = 2;
	CHECK(rsk_precheck_current(&ops, value, &length) == -EACCES);
	CHECK(length == 2 && memcmp(value, "C\n", 3) == 0);
	check_events(&fake, "p");

	test_name = "current private rejection must stop native delegation";
	ops = setup(&fake);
	fake.private_errors[0] = -EINVAL;
	memcpy(value, "C\n\n", 4);
	length = 3;
	CHECK(rsk_precheck_current(&ops, value, &length) == -EINVAL);
	CHECK(length == 2 && memcmp(value, "C\n\0", 3) == 0);
	CHECK(fake.private_lengths[0] == 2 && fake.live_calls == 0);
	check_events(&fake, "pb");

	test_name = "empty current delegates native empty-context and allocation errors";
	ops = setup(&fake);
	length = 0;
	CHECK(rsk_precheck_current(&ops, NULL, &length) == 0);
	CHECK(length == 0);
	check_events(&fake, "p");

	test_name = "newline-leading current delegates without private conversion";
	ops = setup(&fake);
	memcpy(value, "\nC", 3);
	length = 2;
	CHECK(rsk_precheck_current(&ops, value, &length) == 0);
	CHECK(length == 2 && memcmp(value, "\nC", 3) == 0);
	check_events(&fake, "p");

	test_name = "NUL-leading current delegates without private conversion";
	ops = setup(&fake);
	memcpy(value, "\0C", 3);
	length = 2;
	CHECK(rsk_precheck_current(&ops, value, &length) == 0);
	CHECK(length == 2 && memcmp(value, "\0C", 3) == 0);
	check_events(&fake, "p");
}

static void test_uid_and_attribute_gate(void)
{
	test_name = "raw real UID and exact current attribute selection";
	CHECK(rsk_is_app(0) == 0);
	CHECK(rsk_is_app(9999) == 0);
	CHECK(rsk_is_app(10000) != 0);
	CHECK(rsk_is_app(99999) != 0);
	CHECK(rsk_is_app(100001) != 0);
	CHECK(rsk_is_app(UINT_MAX) != 0);
	CHECK(rsk_equal("current", "current") != 0);
	CHECK(rsk_equal("exec", "current") == 0);
	CHECK(rsk_equal("fscreate", "current") == 0);
	CHECK(rsk_equal("Current", "current") == 0);
	CHECK(rsk_equal("current_extra", "current") == 0);
	CHECK(rsk_equal("curren", "current") == 0);
	CHECK(rsk_equal(NULL, "current") == 0);
	CHECK(rsk_equal("current", NULL) == 0);
	CHECK(rsk_equal(NULL, NULL) != 0);
	CHECK(rsk_equal("", "") != 0);
}

int main(void)
{
	test_parser();
	test_context_queries();
	test_access_queries();
	test_current_precheck();
	test_uid_and_attribute_gate();
	printf("core tests: %u assertions passed\n", checks);
	return EXIT_SUCCESS;
}
