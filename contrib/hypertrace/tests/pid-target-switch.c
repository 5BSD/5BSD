/* SPDX-License-Identifier: BSD-2-Clause */
/* Built with jump tables enabled: each case calls a different function, so
 * the switch dispatches through an indirect jump, which is not a return. */
int ht_leaf(int);
int ht_branch(int);
int ht_tail(int);
int ht_unknown(int);

__attribute__((noinline)) int
ht_switch(int x)
{
	switch (x) {
	case 0: return (ht_leaf(x) ^ 0x55);
	case 1: return (ht_branch(x) - 9);
	case 2: return (ht_tail(x) << 2);
	case 3: return (ht_unknown(x) | 0x100);
	case 4: return (ht_leaf(x * x) + ht_tail(x));
	case 5: return (ht_branch(x) * ht_unknown(x));
	case 6: return (ht_tail(x) / 3);
	default: return (-1);
	}
}
