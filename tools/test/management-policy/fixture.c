/* SPDX-License-Identifier: BSD-2-Clause */
#include <libservice.h>
#include <unistd.h>

int
main(void)
{
	struct service_context *ctx;

	if (service_acquire(&ctx) != 0 || service_enter_capability_mode(ctx) != 0 ||
	    service_ready(ctx) != 0)
		return (1);
	for (;;)
		pause();
}
