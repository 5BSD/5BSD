/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Compile a corpus of D programs to DOF with the worktree's libdtrace
 * (opened NODEV|NOSYS: no device, no module loading).  The kernel-source
 * harness enables the resulting DOF through the real dtrace(4) ioctl path.
 * Corpus format: "@name [flags]" lines followed by the program text.
 * usage: dofgen CORPUS OUTDIR
 */
#include <sys/wait.h>
#include <dtrace.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
emit(const char *dir, const char *name, const char *opts, const char *src)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	dof_hdr_t *dof;
	char path[1024], opt[256], *o, *v, *save = NULL;
	FILE *f;
	int err, vprog = 0, vsrc = 0;

	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);
	if (dtp == NULL) {
		fprintf(stderr, "%s: dtrace_open: %s\n", name,
		    dtrace_errmsg(NULL, err));
		return (1);
	}
	(void)dtrace_setopt(dtp, "bufsize", "64k");
	(void)dtrace_setopt(dtp, "aggsize", "64k");
	snprintf(opt, sizeof(opt), "%s", opts);
	for (o = strtok_r(opt, " ", &save); o != NULL;
	    o = strtok_r(NULL, " ", &save)) {
		/* "vprog": emit the guest-side forwarding program that
		 * dtrace(1) sends to a VM (dtrace_vprog_from, hypercalls). */
		if (strcmp(o, "vprog") == 0) {
			vprog = 1;
			continue;
		}
		/* "vsrc": emit the host-side source program as it stands after
		 * dtrace_vprog_from() rewrote it (immstack -> printimmstack). */
		if (strcmp(o, "vsrc") == 0) {
			vsrc = 1;
			continue;
		}
		v = strchr(o, '=');
		if (v != NULL)
			*v++ = '\0';
		if (dtrace_setopt(dtp, o, v) != 0) {
			fprintf(stderr, "%s: option %s: %s\n", name, o,
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			return (1);
		}
	}
	pgp = dtrace_program_strcompile(dtp, src, DTRACE_PROBESPEC_NAME,
	    DTRACE_C_ZDEFS, 0, NULL);
	if (pgp == NULL) {
		fprintf(stderr, "%s: compile: %s\n", name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (1);
	}
	/* As dtrace(1) does before dtrace_program_exec(): resolve the
	 * compiler's relocation pseudo-instructions. */
	{
		hypertrace_errmsg_t msg;
		int lerr;

		fprintf(stderr, "link %s\n", name);
		lerr = hypertrace_link(dtp, pgp, msg);

		if (lerr != 0) {
			fprintf(stderr, "%s: link: %d %s\n", name, lerr, msg);
			return (1);
		}
	}
	if (vprog || vsrc) {
		/* PGP_KIND_HYPERCALLS (dt_program.h) is 0. */
		dtrace_prog_t *vp = dtrace_vprog_from(dtp, pgp, 0);

		if (vprog)
			pgp = vp;
		if (vp == NULL) {
			fprintf(stderr, "%s: vprog: %s\n", name,
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			return (1);
		}
	}
	dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP);
	if (dof == NULL) {
		fprintf(stderr, "%s: dof: %s\n", name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (1);
	}
	snprintf(path, sizeof(path), "%s/%s.dof", dir, name);
	f = fopen(path, "w");
	if (f == NULL || fwrite(dof, 1, dof->dofh_filesz, f) != dof->dofh_filesz ||
	    fclose(f) != 0) {
		fprintf(stderr, "%s: write %s\n", name, path);
		return (1);
	}
	dtrace_dof_destroy(dtp, dof);
	dtrace_close(dtp);
	return (0);
}

int
main(int argc, char **argv)
{
	FILE *f;
	char line[4096], name[128] = "", opts[256] = "";
	char *src = NULL;
	size_t len = 0;
	int failures = 0, n = 0;

	if (argc != 3)
		return (2);
	if ((f = fopen(argv[1], "r")) == NULL)
		return (2);
	src = calloc(1, 1 << 20);
	for (;;) {
		char *l = fgets(line, sizeof(line), f);

		if (l == NULL || line[0] == '@') {
			if (name[0] != '\0') {
				/* One process per program: the HyperTrace linker keeps
				 * process-global state across dtrace handles. */
				pid_t pid = fork();
				int status = 1;

				if (pid == 0)
					_exit(emit(argv[2], name, opts, src));
				if (pid > 0)
					(void)waitpid(pid, &status, 0);
				if (status != 0)
					fprintf(stderr, "%s: failed (status %#x)\n",
					    name, status);
				failures += status != 0;
				n++;
			}
			if (l == NULL)
				break;
			name[0] = opts[0] = '\0';
			sscanf(line + 1, "%127s %255[^\n]", name, opts);
			len = 0;
			src[0] = '\0';
			continue;
		}
		if (line[0] == '#' && line[1] == ' ')
			continue;
		memcpy(src + len, line, strlen(line) + 1);
		len += strlen(line);
	}
	printf("dofgen: %d programs, %d failures\n", n, failures);
	return (failures != 0);
}
