/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise unmodified C and assembly members from the pilot archive. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
	const char unterminated[4] = { 'a', 'b', 'c', 'd' };
	div_t positive, negative;

	positive = div(17, 5);
	negative = div(-17, 5);
	if (positive.quot != 3 || positive.rem != 2 ||
	    negative.quot != -3 || negative.rem != -2 ||
	    strnlen("", 8) != 0 || strnlen("hello", 0) != 0 ||
	    strnlen("hello", 3) != 3 || strnlen("hello", 8) != 5 ||
	    strnlen(unterminated, sizeof(unterminated)) != 4)
		return (1);
	puts("archive-runtime: ok");
	return (0);
}
