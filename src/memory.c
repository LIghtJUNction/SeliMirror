/* SPDX-License-Identifier: GPL-2.0-only */
/* Compiler-generated block copies must not become unresolved KPM imports. */
typedef __SIZE_TYPE__ size_t;

void *memcpy(void *destination, const void *source, size_t length)
{
	volatile unsigned char *out = destination;
	const volatile unsigned char *in = source;
	size_t i;

	for (i = 0; i < length; i++)
		out[i] = in[i];
	return destination;
}

void *memset(void *destination, int value, size_t length)
{
	volatile unsigned char *out = destination;
	size_t i;

	for (i = 0; i < length; i++)
		out[i] = (unsigned char)value;
	return destination;
}

void *memmove(void *destination, const void *source, size_t length)
{
	volatile unsigned char *out = destination;
	const volatile unsigned char *in = source;
	size_t i;

	if ((unsigned long)out <= (unsigned long)in) {
		for (i = 0; i < length; i++)
			out[i] = in[i];
	} else {
		for (i = length; i; i--)
			out[i - 1] = in[i - 1];
	}
	return destination;
}
