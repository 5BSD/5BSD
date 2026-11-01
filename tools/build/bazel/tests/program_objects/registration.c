/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif

extern int program_registration_count;

/* No externally referenced symbol can extract this object from an archive. */
static void __attribute__((constructor))
register_program_service(void)
{
	program_registration_count++;
#ifdef WITH_DTRACE
	DTRACE_PROBE1(programregistration, registered, program_registration_count);
#endif
}
