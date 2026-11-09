/*
 * SPDX-License-Identifier: CDDL-1.0
 * Integer constant expressions fold in 64 bits: a result that does not fit
 * the type of its operands keeps its value and takes the type an integer
 * literal of that value has.  Results that fit keep their type, and the
 * complement of an unsigned constant stays within its type.
 */

#pragma D option quiet

BEGIN
{
	this->a = (1 << 63) - 7;
	printf("%d\n", (1 << 63) - 7);
	printf("%d\n", this->a);
	printf("%d\n", (long long)((1 << 63) - 7));
	printf("%d %d\n", 1 + 2, -2147483647 - 1);
	printf("%d\n", -(-2147483647 - 1));
	printf("%u %u %u\n", ~0u, ~0u - 1, ~0u >> 1);
	printf("%d %u\n", ~0, ~0x80000000 + 0);
	printf("%d %d\n", sizeof (1 + 2), sizeof ((1 << 63) - 7));
	exit(0);
}
