/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Save the exact ENABLE DOF that a non-linking consumer (lockstat,
 * plockstat) builds, for the kernel-side DOF tests (coverage-kernel.py).
 *
 * This includes the typing agent's tool-dof-shim.c unchanged.  The shim
 * reports from shim_ioctl() with one printf() while the DOF is in scope as
 * `dof`; that printf() first writes the DOF to $TOOLDOF_OUT.  Not
 * production code.
 */
#include <stdio.h>
#include <stdlib.h>

static void tooldof_save(const void *);
#define	printf(...)	(tooldof_save(dof), printf(__VA_ARGS__))
#include "../tool-dof-shim.c"
#undef printf

static void
tooldof_save(const void *p)
{
	const dof_hdr_t *dof = p;
	const char *path = getenv("TOOLDOF_OUT");
	FILE *f;

	if (path == NULL || (f = fopen(path, "w")) == NULL)
		return;
	(void)fwrite(dof, 1, dof->dofh_filesz, f);
	(void)fclose(f);
}
