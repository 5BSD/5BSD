/* SPDX-License-Identifier: BSD-2-Clause */
/* The test fails distinctly if an attributed image loads this injected DSO. */
#include <unistd.h>

static void __attribute__((constructor))
injected(void)
{
	_exit(91);
}
