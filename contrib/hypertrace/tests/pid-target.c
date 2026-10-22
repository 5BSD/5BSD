/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Target for pid-placement.py.  Built with -O2 -fno-jump-tables so that
 * ht_tail ends in a tail-call jump and ht_branch has several exits; the
 * process is created stopped and never runs these functions.
 */
#include <stdlib.h>

__attribute__((noinline)) int
ht_leaf(int x)
{
	return (x * 3 + 1);
}

__attribute__((noinline)) int
ht_branch(int x)
{
	if (x > 5)
		return (x - 1);
	if (x < -5)
		return (ht_leaf(x) * 2);
	return (ht_leaf(x) + 2);
}

__attribute__((noinline)) int
ht_tail(int x)
{
	return (ht_leaf(x + 1));
}

/*
 * Contains bytes the x86 length decoder refuses (rdpkru, never executed);
 * libdtrace must then treat the function conservatively.
 */
__attribute__((noinline)) int
ht_unknown(int x)
{
	if (x == 77)
		__asm__ volatile(".byte 0x0f, 0x01, 0xee" ::: "eax", "edx");
	return (x + 1);
}

/* Distinct argument and return types for the CTF argument-type check. */
__attribute__((noinline)) short
ht_types(long a, const char *b, unsigned short c)
{
	return ((short)(a + (b != NULL) + c));
}

int ht_switch(int);	/* pid-target-switch.c, built with jump tables */

int
main(int argc, char **argv)
{
	return (ht_branch(argc) + ht_tail(argc) + ht_unknown(argc) +
	    ht_switch(argc) + ht_types(argc, argv[0], 3) == 12345 ? 1 : 0);
}
