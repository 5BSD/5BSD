// SPDX-License-Identifier: BSD-2-Clause
// C++ call sites for usdt-link.py (mangled function names).  Never executed.
#include "usdt-link.h"

namespace ulns {
int
go(int x)
{
	if (ULINKB_GO_ENABLED())
		ULINKB_GO(x + 1);
	ULINKB_GO(x);
	return (x);
}
}
