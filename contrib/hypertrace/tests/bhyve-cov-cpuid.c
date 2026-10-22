/* SPDX-License-Identifier: BSD-2-Clause */
/* CPUID vendor leaf for the bhyvectl test build (see bhyve-cov-cpuid.h). */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

void bhyve_cov_do_cpuid(u_int ax, u_int *p);

void
bhyve_cov_do_cpuid(u_int ax, u_int *p)
{
	const char *vendor = getenv("BHYVECTL_TEST_VENDOR");
	const char *id;

	memset(p, 0, 4 * sizeof(*p));
	if (ax != 0)
		return;
	if (vendor == NULL || strcmp(vendor, "intel") == 0)
		id = "GenuineIntel";
	else if (strcmp(vendor, "hygon") == 0)
		id = "HygonGenuine";
	else if (strcmp(vendor, "amd") == 0)
		id = "AuthenticAMD";
	else
		id = "UnknownVendr";
	/* EBX, EDX, ECX hold the vendor string in that order. */
	memcpy(&p[1], id, 4);
	memcpy(&p[3], id + 4, 4);
	memcpy(&p[2], id + 8, 4);
}
