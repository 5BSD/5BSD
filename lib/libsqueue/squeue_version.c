/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libsqueue is otherwise a header-only interface (see squeue.h); this unit
 * provides the shared-object version accessors so applications can link
 * -lsqueue and query the library version.
 */
#include <squeue.h>

#define	SQUEUE_VERSION_MAJOR	1
#define	SQUEUE_VERSION_MINOR	0

int
squeue_major_version(void)
{

	return (SQUEUE_VERSION_MAJOR);
}

int
squeue_minor_version(void)
{

	return (SQUEUE_VERSION_MINOR);
}
