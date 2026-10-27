/* SPDX-License-Identifier: BSD-2-Clause */
/* Direct calls exercise archive members, including amd64 assembly conversions. */
extern __int128 __divti3(__int128, __int128);
extern __int128 __modti3(__int128, __int128);
extern unsigned __int128 __udivti3(unsigned __int128, unsigned __int128);
extern unsigned __int128 __umodti3(unsigned __int128, unsigned __int128);
extern double __floatundidf(unsigned long long);
extern float __floatundisf(unsigned long long);
extern long double __floatundixf(unsigned long long);

#ifndef BSD_TEST_ENTRY
#define BSD_TEST_ENTRY main
#endif

int
BSD_TEST_ENTRY(void)
{
	volatile unsigned long long high = 1ULL << 63;
	unsigned __int128 n = ((unsigned __int128)1 << 100) + 17;
	unsigned __int128 q = __udivti3(n, 3);
	unsigned __int128 r = __umodti3(n, 3);

	if (q * 3 + r != n || r >= 3)
		return (1);
	if (__divti3(-100, 7) != -14 || __modti3(-100, 7) != -2)
		return (2);
	if (__floatundidf(high) != 0x1p63 ||
	    __floatundisf(high) != 0x1p63f ||
	    __floatundixf(high) != 0x1p63L)
		return (3);
	if (__floatundisf(16777217) != 16777216.0f ||
	    __floatundidf(~0ULL) != 0x1p64)
		return (4);
	return (0);
}
