/* SPDX-License-Identifier: BSD-2-Clause */
/* Call sites naming a probe or provider that usdt-link.d does not define. */
extern void BAD_SYMBOL(void);

void
ul_bad(void)
{
	BAD_SYMBOL();
}
