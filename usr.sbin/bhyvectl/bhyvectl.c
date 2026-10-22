/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2026 Hans Rosenfeld
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/nv.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <libgen.h>
#include <libutil.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <libutil.h>

#include <machine/cpufunc.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <vmmapi.h>

#include "ipc.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#include "migration_credentials.h"
#include "migration_handoff.h"
#include "migration_session.h"
#endif

#include "bhyvectl.h"

#define	MB	(1UL << 20)
#define	GB	(1UL << 30)

static const char *progname;

static int get_stats, getcap, setcap, capval;
static int force_reset, force_poweroff;
static const char *capname;
static int create, destroy, get_memmap, get_memseg;
static int get_active_cpus, get_debug_cpus, get_suspended_cpus;
static uint64_t memsize;
static int run;
static int get_cpu_topology;
static int get_vm_pid;
#ifdef BHYVE_SNAPSHOT
static int vm_suspend_opt;
#endif

static int get_all;

enum {
	VMNAME = OPT_START,	/* avoid collision with return values from getopt */
	VCPU,
	SET_MEM,
	SET_CAP,
	CAPNAME,
#ifdef BHYVE_SNAPSHOT
	SET_CHECKPOINT_FILE,
	SET_SUSPEND_FILE,
	RECOVER_FD,
	RECOVER_CERT,
	RECOVER_KEY,
	RECOVER_TRUST,
	RECOVER_PIN,
	MIGRATE_FD,
	MIGRATE_REPAIR,
	MIGRATE_PLAINTEXT_UNIX,
	MIGRATE_RESOLVE,
	MIGRATE_SOURCE_RETIRED,
	MIGRATE_ACKNOWLEDGE_LOSS,
	MIGRATE_JOURNAL,
#endif
	SET_RUNDIR,
	OPT_LAST,
};

_Static_assert(OPT_LAST < OPT_START_MD,
    "OPT_LAST must be less than OPT_START_MD");

static void
print_cpus(const char *banner, const cpuset_t *cpus)
{
	int i, first;

	first = 1;
	printf("%s:\t", banner);
	if (!CPU_EMPTY(cpus)) {
		for (i = 0; i < CPU_SETSIZE; i++) {
			if (CPU_ISSET(i, cpus)) {
				printf("%s%d", first ? " " : ", ", i);
				first = 0;
			}
		}
	} else
		printf(" (none)");
	printf("\n");
}

static struct option *
setup_options(void)
{
	const struct option common_opts[] = {
		{ "vm",		REQ_ARG,	0,	VMNAME },
		{ "cpu",	REQ_ARG,	0,	VCPU },
		{ "set-mem",	REQ_ARG,	0,	SET_MEM },
		{ "capname",	REQ_ARG,	0,	CAPNAME },
		{ "setcap",	REQ_ARG,	0,	SET_CAP },
		{ "getcap",	NO_ARG,		&getcap,	1 },
		{ "get-stats",	NO_ARG,		&get_stats,	1 },
		{ "get-memmap",	NO_ARG,		&get_memmap,	1 },
		{ "get-memseg", NO_ARG,		&get_memseg,	1 },
		{ "get-all",		NO_ARG,	&get_all,		1 },
		{ "run",		NO_ARG,	&run,			1 },
		{ "create",		NO_ARG,	&create,		1 },
		{ "destroy",		NO_ARG,	&destroy,		1 },
		{ "force-reset",	NO_ARG,	&force_reset,		1 },
		{ "force-poweroff", 	NO_ARG,	&force_poweroff, 	1 },
		{ "get-active-cpus", 	NO_ARG,	&get_active_cpus, 	1 },
		{ "get-debug-cpus",	NO_ARG,	&get_debug_cpus,	1 },
		{ "get-suspended-cpus", NO_ARG,	&get_suspended_cpus, 	1 },
		{ "get-cpu-topology",	NO_ARG, &get_cpu_topology,	1 },
		{ "get-vm-pid",		NO_ARG, &get_vm_pid,		1 },
#ifdef BHYVE_SNAPSHOT
		{ "migrate-fd", REQ_ARG, 0, MIGRATE_FD },
		{ "migrate-recover-fd", REQ_ARG, 0, RECOVER_FD },
		{ "migrate-certificate-fd", REQ_ARG, 0, RECOVER_CERT },
		{ "migrate-key-fd", REQ_ARG, 0, RECOVER_KEY },
		{ "migrate-trust-fd", REQ_ARG, 0, RECOVER_TRUST },
		{ "migrate-peer-sha256", REQ_ARG, 0, RECOVER_PIN },
		{ "migrate-repair", NO_ARG, 0, MIGRATE_REPAIR },
		{ "migrate-plaintext-unix", NO_ARG, 0, MIGRATE_PLAINTEXT_UNIX },
		{ "migrate-resolve", REQ_ARG, 0, MIGRATE_RESOLVE },
		{ "migrate-source-retired", NO_ARG, 0, MIGRATE_SOURCE_RETIRED },
		{ "migrate-acknowledge-loss", NO_ARG, 0, MIGRATE_ACKNOWLEDGE_LOSS },
		{ "migrate-journal", REQ_ARG, 0, MIGRATE_JOURNAL },
		{ "checkpoint", 	REQ_ARG, 0,	SET_CHECKPOINT_FILE},
		{ "suspend", 		REQ_ARG, 0,	SET_SUSPEND_FILE},
#endif
		{ "rundir", 		REQ_ARG, 0,	SET_RUNDIR},
	};

	return (bhyvectl_opts(common_opts, nitems(common_opts)));
}

void
usage(const struct option *opts)
{
	static const char *set_desc[] = {
	    [VCPU] = "vcpu_number",
	    [SET_MEM] = "memory in units of MB",
	    [SET_CAP] = "0|1",
	    [CAPNAME] = "capname",
#ifdef BHYVE_SNAPSHOT
	    [SET_CHECKPOINT_FILE] = "filename",
	    [SET_SUSPEND_FILE] = "filename",
	    [MIGRATE_RESOLVE] = "resume|discard",
	    [MIGRATE_JOURNAL] = "journal-file",
#endif
	    [SET_RUNDIR] = "path",
	};
	(void)fprintf(stderr, "Usage: %s --vm=<vmname>\n", progname);
	for (const struct option *o = opts; o->name; o++) {
		if (strcmp(o->name, "vm") == 0)
			continue;
		if (o->has_arg == REQ_ARG) {
			(void)fprintf(stderr, "       [--%s=<%s>]\n", o->name,
			    o->val >= OPT_START_MD ? bhyvectl_opt_desc(o->val) :
			    set_desc[o->val]);
		} else {
			(void)fprintf(stderr, "       [--%s]\n", o->name);
		}
	}
	exit(1);
}

static int
show_memmap(struct vmctx *ctx)
{
	char name[SPECNAMELEN + 1], numbuf[8];
	vm_ooffset_t segoff;
	vm_paddr_t gpa;
	size_t maplen, seglen;
	const char *delim;
	int error, flags, prot, segid;

	printf("Address     Length      Segment     Offset      ");
	printf("Prot  Flags\n");

	gpa = 0;
	while (1) {
		error = vm_mmap_getnext(ctx, &gpa, &segid, &segoff, &maplen,
		    &prot, &flags);
		if (error)
			return (errno == ENOENT ? 0 : error);

		error = vm_get_memseg(ctx, segid, &seglen, name, sizeof(name));
		if (error)
			return (error);

		printf("%-12lX", gpa);
		humanize_number(numbuf, sizeof(numbuf), maplen, "B",
		    HN_AUTOSCALE, HN_NOSPACE);
		printf("%-12s", numbuf);

		printf("%-12s", name[0] ? name : "sysmem");
		printf("%-12lX", segoff);
		printf("%c%c%c   ", prot & PROT_READ ? 'R' : '-',
		    prot & PROT_WRITE ? 'W' : '-',
		    prot & PROT_EXEC ? 'X' : '-');

		/* Separate flag names with '/'; a NUL character must not be
		 * printed before the first one. */
		delim = "";
		if (flags & VM_MEMMAP_F_WIRED) {
			printf("%swired", delim);
			delim = "/";
		}
#ifdef __amd64__
		if (flags & VM_MEMMAP_F_IOMMU) {
			printf("%siommu", delim);
			delim = "/";
		}
#endif
		printf("\n");

		gpa += maplen;
	}
}

static int
show_memseg(struct vmctx *ctx)
{
	char name[SPECNAMELEN + 1], numbuf[8];
	size_t seglen;
	int error, segid;

	printf("ID  Length      Name\n");

	segid = 0;
	while (1) {
		error = vm_get_memseg(ctx, segid, &seglen, name, sizeof(name));
		if (error)
			return (errno == EINVAL ? 0 : error);

		if (seglen) {
			printf("%-4d", segid);
			humanize_number(numbuf, sizeof(numbuf), seglen, "B",
			    HN_AUTOSCALE, HN_NOSPACE);
			printf("%-12s", numbuf);
			printf("%s", name[0] ? name : "sysmem");
			printf("\n");
		}
		segid++;
	}
}

static int __unused
ipc_send_message(const char *vmname, nvlist_t *request, const char *rundir,
    nvlist_t **replyp)
{
	int err = 0, pathlen, socket_fd;
	struct sockaddr_un addr;
	const char* errmsg;
	nvlist_t *reply = NULL;

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		perror("Error creating bhyvectl socket");
		err = errno;
		goto done;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	pathlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s",
	    rundir, vmname);
	if (pathlen < 0 || (size_t)pathlen >= sizeof(addr.sun_path)) {
		fprintf(stderr, "bhyve IPC socket path is too long\n");
		err = ENAMETOOLONG;
		goto done;
	}
	addr.sun_family = AF_UNIX;
	addr.sun_len = SUN_LEN(&addr);

	if (connect(socket_fd, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		perror("connect() failed");
		err = errno;
		goto done;
	}

	reply = nvlist_xfer(socket_fd, request, 0);
	request = NULL;
	if (reply == NULL) {
		perror("nvlist_xfer() failed");
		err = errno;
		goto done;
	}
	if (nvlist_exists_string(reply, "error")) {
		errmsg = nvlist_get_string(reply, "error");
		fprintf(stderr, "%s: IPC command failed: %s\n",
		    __func__, errmsg);
		err = -1;
	} else if (replyp != NULL) {
		*replyp = reply;
		reply = NULL;
	}
done:
	if (request != NULL)
		nvlist_destroy(request);
	if (reply != NULL)
		nvlist_destroy(reply);

	if (socket_fd >= 0)
		close(socket_fd);
	return (err);
}

static int
vm_pid_request(const char *vmname, const char *rundir, pid_t *pid)
{
	nvlist_t *nvl, *reply;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "get_vm_pid");
	error = ipc_send_message(vmname, nvl, rundir, &reply);
	if (error == -1)
		error = EOPNOTSUPP;
	else if (error == ENOENT || error == ECONNREFUSED)
		error = ESRCH;
	if (error == 0) {
		if (nvlist_exists_number(reply, "pid"))
			*pid = (pid_t)nvlist_get_number(reply, "pid");
		else
			error = EPROTO;
		nvlist_destroy(reply);
	}
	if (error != 0)
		errno = error;
	return (error);
}

#ifdef BHYVE_SNAPSHOT
static int
open_directory(const char *file)
{
	char *path;
	int fd;

	if ((path = strdup(file)) == NULL)
		return (-1);

	dirname(path);
	fd = open(path, O_DIRECTORY);
	free(path);

	return (fd);
}

static int
snapshot_request(const char *vmname, char *file, bool suspend, const char *rundir)
{
	nvlist_t *nvl;
	int fd;

	if ((fd = open_directory(file)) < 0)
		return (errno);

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "checkpoint");
	nvlist_add_string(nvl, "filename", basename(file));
	nvlist_add_bool(nvl, "suspend", suspend);
	nvlist_move_descriptor(nvl, "fddir", fd);

	return (ipc_send_message(vmname, nvl, rundir, NULL));
}
#endif

#ifdef BHYVE_SNAPSHOT
/* Both operations address the source controller over IPC. Recovery must not
 * open a kernel VM: RELEASE or its ACK can be lost after source destruction. */
static int
migration_control_request(const char *vmname, const char *rundir,
    const char *values[5], bool recover, bool plaintext_unix)
{
	struct migration_tls_credentials credentials;
	const char *parse_error;
	nvlist_t *request, *reply = NULL;
	bool enabled;
	int error, fd;

	if (values[0] == NULL)
		return (EINVAL);
	fd = strtonum(values[0], 0, INT_MAX, &parse_error);
	if (parse_error != NULL)
		return (EINVAL);
	/*
	 * Migration is mutually authenticated TLS.  The only exception is an
	 * explicit same-host plaintext AF_UNIX socket, which the source checks
	 * again (migration_channel_policy()); recovery always needs TLS.
	 */
	if (plaintext_unix) {
		if (recover || values[1] != NULL || values[2] != NULL ||
		    values[3] != NULL || values[4] != NULL)
			return (EINVAL);
		enabled = false;
	} else {
		error = migration_credentials_config(values[1], values[2],
		    values[3], values[4], &credentials, &enabled);
		if (error != 0 || !enabled)
			return (error != 0 ? error : EINVAL);
	}
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", recover ? "migrate_recover" : "migrate");
	nvlist_add_descriptor(request, "fd", fd);
	if (enabled) {
		nvlist_add_descriptor(request, "tls_certificate_fd",
		    credentials.certificate_fd);
		nvlist_add_descriptor(request, "tls_private_key_fd",
		    credentials.private_key_fd);
		nvlist_add_descriptor(request, "tls_trust_fd",
		    credentials.trust_fd);
		nvlist_add_string(request, "tls_peer_sha256", values[4]);
	} else
		nvlist_add_bool(request, "plaintext_unix", true);
	error = nvlist_error(request);
	if (error != 0) {
		nvlist_destroy(request);
		return (error);
	}
	error = ipc_send_message(vmname, request, rundir, &reply);
	if (error == 0 && (reply == NULL ||
	    !nvlist_exists_bool(reply, "source_runnable") ||
	    nvlist_get_bool(reply, "source_runnable")))
		error = EPROTO;
	if (error == 0 && recover &&
	    (!nvlist_exists_bool(reply, "confirmed") ||
	    !nvlist_get_bool(reply, "confirmed")))
		error = EPROTO;
	if (error == 0 && !recover &&
	    (!nvlist_exists_number(reply, "phase") ||
	    nvlist_get_number(reply, "phase") != MIGRATION_PHASE_COMPLETED ||
	    !nvlist_exists_number(reply, "reason") ||
	    nvlist_get_number(reply, "reason") != MIGRATION_REASON_NONE))
		error = EPROTO;
	if (reply != NULL)
		nvlist_destroy(reply);
	return (error);
}
#endif

#ifdef BHYVE_SNAPSHOT
/* Retry a failed pre-COMMIT rollback through the source controller. Success
 * needs an explicit repaired, runnable reply; the controller refuses once
 * retirement began, and this command never opens the kernel VM. */
static int
migration_repair_request(const char *vmname, const char *rundir)
{
	nvlist_t *request, *reply = NULL;
	int error;

	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "migrate_repair");
	error = nvlist_error(request);
	if (error != 0) {
		nvlist_destroy(request);
		return (error);
	}
	error = ipc_send_message(vmname, request, rundir, &reply);
	if (error == 0 && (reply == NULL ||
	    !nvlist_exists_bool(reply, "repaired") ||
	    !nvlist_get_bool(reply, "repaired") ||
	    !nvlist_exists_bool(reply, "source_runnable") ||
	    !nvlist_get_bool(reply, "source_runnable")))
		error = EPROTO;
	if (reply != NULL)
		nvlist_destroy(reply);
	return (error);
}

/*
 * Resolve an inbound migration that the destination retained after COMMIT.
 * The operator's confirmation flag travels with the action: "resume" needs
 * source_retired, "discard" needs acknowledge_loss; each is refused with
 * EINVAL here before anything is sent.  Success needs an explicit
 * resolved=true reply with nothing left retained.
 */
static int
migration_resolve_request(const char *vmname, const char *rundir,
    const char *action, bool source_retired, bool acknowledge_loss)
{
	nvlist_t *request, *reply = NULL;
	bool resume;
	int error;

	if (action == NULL)
		return (EINVAL);
	resume = strcmp(action, "resume") == 0;
	if (!resume && strcmp(action, "discard") != 0)
		return (EINVAL);
	if (resume ? (!source_retired || acknowledge_loss) :
	    (!acknowledge_loss || source_retired))
		return (EINVAL);
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "migrate_resolve");
	nvlist_add_string(request, "action", action);
	nvlist_add_bool(request, resume ? "source_retired" : "acknowledge_loss",
	    true);
	error = nvlist_error(request);
	if (error != 0) {
		nvlist_destroy(request);
		return (error);
	}
	error = ipc_send_message(vmname, request, rundir, &reply);
	if (error == 0 && (reply == NULL ||
	    !nvlist_exists_bool(reply, "resolved") ||
	    !nvlist_get_bool(reply, "resolved") ||
	    !nvlist_exists_bool(reply, "retained") ||
	    nvlist_get_bool(reply, "retained")))
		error = EPROTO;
	if (error == EPROTO && reply != NULL &&
	    nvlist_exists_number(reply, "error_code") &&
	    nvlist_get_number(reply, "error_code") != 0 &&
	    nvlist_get_number(reply, "error_code") <= INT_MAX)
		error = (int)nvlist_get_number(reply, "error_code");
	if (reply != NULL)
		nvlist_destroy(reply);
	return (error);
}

static const char *
migration_journal_phase_name(uint16_t phase)
{
	switch (phase) {
	case MIGRATION_REC_SOURCE_INTENT: return ("source-intent");
	case MIGRATION_REC_SOURCE_RETIRED: return ("source-retired");
	case MIGRATION_REC_SOURCE_RELEASED: return ("source-released");
	case MIGRATION_REC_SOURCE_CONFIRMED: return ("source-confirmed");
	case MIGRATION_REC_DEST_STAGED: return ("destination-staged");
	case MIGRATION_REC_DEST_RELEASED: return ("destination-released");
	case MIGRATION_REC_DEST_RUNNING: return ("destination-running");
	}
	return ("unknown");
}

/*
 * Print one ordinary-mode handoff journal (migration_handoff.h), one line per
 * entry.  The file name carries the side and the attempt challenge; the
 * journal is validated exactly as the writer validates it, so a damaged
 * journal is reported, never partially shown.  Nothing is sent to a VM.
 */
static int
migration_journal_print(const char *path, FILE *out)
{
	struct migration_handoff_entry entries[MIGRATION_HANDOFF_MAX];
	uint8_t challenge[32], role;
	char dir[PATH_MAX], *slash;
	const char *name;
	size_t count, i;
	int dirfd, error;

	if (path == NULL || strlen(path) >= sizeof(dir))
		return (ENAMETOOLONG);
	strlcpy(dir, path, sizeof(dir));
	slash = strrchr(dir, '/');
	if (slash != NULL) {
		name = slash + 1;
		if (slash == dir)
			slash[1] = '\0';
		else
			*slash = '\0';
	} else {
		name = path;
		strlcpy(dir, ".", sizeof(dir));
	}
	/* h-s-<64 hex>.log or h-d-<64 hex>.log */
	if (strlen(name) != 72 || strncmp(name, "h-", 2) != 0 ||
	    (name[2] != 's' && name[2] != 'd') || name[3] != '-' ||
	    strcmp(name + 68, ".log") != 0)
		return (EINVAL);
	role = name[2] == 's' ? MIGRATION_HANDOFF_SOURCE : MIGRATION_HANDOFF_DEST;
	for (i = 0; i < 32; i++) {
		unsigned int byte;

		if (!isxdigit((unsigned char)name[4 + 2 * i]) ||
		    !isxdigit((unsigned char)name[5 + 2 * i]) ||
		    sscanf(name + 4 + 2 * i, "%2x", &byte) != 1)
			return (EINVAL);
		challenge[i] = (uint8_t)byte;
	}
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return (errno);
	error = migration_handoff_load(dirfd, role, challenge, entries,
	    MIGRATION_HANDOFF_MAX, &count);
	close(dirfd);
	if (error != 0)
		return (error);
	for (i = 0; i < count; i++) {
		const struct migration_handoff_entry *e = &entries[i];

		fprintf(out, "%3u %s", e->seq,
		    e->role == MIGRATION_HANDOFF_SOURCE ? "source" : "destination");
		switch (e->kind) {
		case MIGRATION_HANDOFF_PHASE:
			fprintf(out, " phase %s", migration_journal_phase_name(e->phase));
			break;
		case MIGRATION_HANDOFF_RESOLVE:
			fprintf(out, " resolve %s", e->action ==
			    MIGRATION_HANDOFF_RESUME ? "resume" : "discard");
			if (e->action == MIGRATION_HANDOFF_RESUME &&
			    !migration_handoff_witness_zero(e))
				fprintf(out, " witness vm %u epoch %#jx entries %ju running %u",
				    e->witness_vmid, (uintmax_t)e->witness_epoch,
				    (uintmax_t)e->witness_entries, e->witness_running);
			break;
		case MIGRATION_HANDOFF_OUTCOME:
			fprintf(out, " outcome %s %s", e->action ==
			    MIGRATION_HANDOFF_RESUME ? "resume" : "discard",
			    e->result == 0 ? "ok" : strerror(e->result));
			break;
		}
		fprintf(out, " destination vm %u epoch %#jx %s\n", e->destination_vmid,
		    (uintmax_t)e->destination_epoch, e->tls ? "tls" : "plaintext");
	}
	fprintf(out, "%zu entr%s\n", count, count == 1 ? "y" : "ies");
	return (0);
}
#endif

int
main(int argc, char *argv[])
{
	char *vmname;
	int action_opts, error, ch, vcpuid;
	struct vm_run vmrun;
	struct vmctx *ctx;
	struct vcpu *vcpu;
	cpuset_t cpus;
	struct option *opts;
#ifdef BHYVE_SNAPSHOT
	char *checkpoint_file = NULL;
	const char *recovery_values[5] = {0};
	bool recovery_requested = false, recovery_conflict = false;
	bool migration_requested = false, migrate_plaintext_unix = false;
	bool repair_requested = false, repair_conflict = false;
	const char *resolve_action = NULL;
	bool resolve_source_retired = false, resolve_acknowledge_loss = false;
	bool resolve_conflict = false;
	const char *journal_path = NULL;
	bool journal_conflict = false;
#endif
	const char *rundir = NULL;

	opts = setup_options();

	action_opts = 0;
	vcpuid = 0;
	vmname = NULL;
	progname = basename(argv[0]);

	while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
#ifdef BHYVE_SNAPSHOT
		if (ch != VMNAME && ch != SET_RUNDIR && ch != MIGRATE_FD &&
		    ch != MIGRATE_PLAINTEXT_UNIX &&
		    (ch < RECOVER_FD || ch > RECOVER_PIN))
			recovery_conflict = true;
		if (ch != VMNAME && ch != SET_RUNDIR && ch != MIGRATE_REPAIR)
			repair_conflict = true;
		if (ch != VMNAME && ch != SET_RUNDIR && ch != MIGRATE_RESOLVE &&
		    ch != MIGRATE_SOURCE_RETIRED && ch != MIGRATE_ACKNOWLEDGE_LOSS)
			resolve_conflict = true;
		if (ch != MIGRATE_JOURNAL)
			journal_conflict = true;
#endif
		if (ch >= OPT_START_MD) {
			bhyvectl_handle_opt(opts, ch);
			continue;
		}

		switch (ch) {
		case 0:
			break;
		case VMNAME:
			vmname = optarg;
			break;
		case VCPU:
			vcpuid = atoi(optarg);
			break;
		case SET_MEM:
			memsize = atoi(optarg) * MB;
			memsize = roundup(memsize, 2 * MB);
			break;
		case SET_CAP:
			capval = strtoul(optarg, NULL, 0);
			setcap = 1;
			break;
		case CAPNAME:
			capname = optarg;
			break;
#ifdef BHYVE_SNAPSHOT
		case MIGRATE_FD:
			if (recovery_values[0] != NULL)
				usage(opts);
			recovery_values[0] = optarg;
			migration_requested = true;
			recovery_requested = true;
			break;
		case RECOVER_FD:
		case RECOVER_CERT:
		case RECOVER_KEY:
		case RECOVER_TRUST:
		case RECOVER_PIN:
			if (recovery_values[ch - RECOVER_FD] != NULL)
				usage(opts);
			recovery_values[ch - RECOVER_FD] = optarg;
			recovery_requested = true;
			break;
		case MIGRATE_REPAIR:
			repair_requested = true;
			break;
		case MIGRATE_PLAINTEXT_UNIX:
			migrate_plaintext_unix = true;
			break;
		case MIGRATE_RESOLVE:
			if (resolve_action != NULL)
				usage(opts);
			resolve_action = optarg;
			break;
		case MIGRATE_SOURCE_RETIRED:
			resolve_source_retired = true;
			break;
		case MIGRATE_ACKNOWLEDGE_LOSS:
			resolve_acknowledge_loss = true;
			break;
		case MIGRATE_JOURNAL:
			if (journal_path != NULL)
				usage(opts);
			journal_path = optarg;
			break;
		case SET_CHECKPOINT_FILE:
		case SET_SUSPEND_FILE:
			if (checkpoint_file != NULL)
				usage(opts);

			checkpoint_file = optarg;
			vm_suspend_opt = (ch == SET_SUSPEND_FILE);
			break;

#endif
		case SET_RUNDIR:
			rundir = optarg;
			break;
		default:
			usage(opts);
		}
	}
	argc -= optind;
	argv += optind;

#ifdef BHYVE_SNAPSHOT
	/* Reading a journal file names no VM and opens none. */
	if (journal_path != NULL) {
		if (journal_conflict || argc != 0)
			usage(opts);
		error = migration_journal_print(journal_path, stdout);
		if (error == EINVAL)
			usage(opts);
		if (error != 0) {
			fprintf(stderr, "migration journal %s: %s\n", journal_path,
			    strerror(error));
			return (1);
		}
		return (0);
	}
#endif
	if (vmname == NULL)
		usage(opts);

	if (rundir == NULL)
		rundir = BHYVE_RUN_DIR;

#ifdef BHYVE_SNAPSHOT
	if (repair_requested) {
		if (repair_conflict || argc != 0)
			usage(opts);
		error = migration_repair_request(vmname, rundir);
		if (error != 0) {
			fprintf(stderr, "migration rollback repair failed%s%s\n",
			    error > 0 ? ": " : "", error > 0 ? strerror(error) : "");
			return (1);
		}
		printf("migration rollback repaired; source runnable\n");
		return (0);
	}
	if (resolve_action != NULL || resolve_source_retired ||
	    resolve_acknowledge_loss) {
		if (resolve_action == NULL || resolve_conflict || argc != 0)
			usage(opts);
		error = migration_resolve_request(vmname, rundir, resolve_action,
		    resolve_source_retired, resolve_acknowledge_loss);
		if (error == EINVAL)
			usage(opts);
		if (error != 0) {
			fprintf(stderr, "migration resolution failed%s%s\n",
			    error > 0 ? ": " : "", error > 0 ? strerror(error) : "");
			return (1);
		}
		printf("retained migration %s\n",
		    strcmp(resolve_action, "resume") == 0 ?
		    "resumed; destination running" : "discarded");
		return (0);
	}
	if (migrate_plaintext_unix && !migration_requested)
		usage(opts);
	if (recovery_requested) {
		if (recovery_conflict || argc != 0)
			usage(opts);
		error = migration_control_request(vmname, rundir, recovery_values,
		    !migration_requested, migrate_plaintext_unix);
		if (error != 0) {
			fprintf(stderr, "migration %s failed%s%s\n",
			    migration_requested ? "initiation" : "recovery",
			    error > 0 ? ": " : "", error > 0 ? strerror(error) : "");
			return (1);
		}
		printf("migration %s; source remains retired\n",
		    migration_requested ? "completed" : "recovery confirmed");
		return (0);
	}
#endif
	action_opts = create + destroy + force_reset + force_poweroff;
#ifdef BHYVE_SNAPSHOT
	if (checkpoint_file)
		action_opts++;
#endif

	if (action_opts > 1) {
		fprintf(stderr, "mutually exclusive actions specified\n");
		exit(1);
	}

	ctx = vm_openf(vmname, create ? VMMAPI_OPEN_CREATE : 0);
	if (ctx == NULL) {
		fprintf(stderr,
		    "vm_open: %s could not be opened: %s\n",
		    vmname, strerror(errno));
		exit(1);
	}
	vcpu = vm_vcpu_open(ctx, vcpuid);
	if (vcpu == NULL) {
		fprintf(stderr,
		    "vm_vcpu_open: %s vcpu %d could not be opened: %s\n",
		    vmname, vcpuid, strerror(errno));
		exit(1);
	}

	error = 0;
	if (!error && memsize)
		error = vm_setup_memory(ctx, memsize, VM_MMAP_ALL);

	if (!error && (get_memseg || get_all))
		error = show_memseg(ctx);

	if (!error && (get_memmap || get_all))
		error = show_memmap(ctx);

	if (!error)
		error = bhyvectl_md_main(ctx, vcpu, vcpuid, get_all);

	if (!error && setcap) {
		int captype;

		captype = vm_capability_name2type(capname);
		error = vm_set_capability(vcpu, captype, capval);
		if (error != 0 && errno == ENOENT)
			printf("Capability \"%s\" is not available\n", capname);
	}

	if (!error && (getcap || get_all)) {
		int captype, val, getcaptype;

		if (getcap && capname)
			getcaptype = vm_capability_name2type(capname);
		else
			getcaptype = -1;

		for (captype = 0; captype < VM_CAP_MAX; captype++) {
			if (getcaptype >= 0 && captype != getcaptype)
				continue;
			error = vm_get_capability(vcpu, captype, &val);
			if (error == 0) {
				printf("Capability \"%s\" is %s on vcpu %d\n",
					vm_capability_type2name(captype),
					val ? "set" : "not set", vcpuid);
			} else if (errno == ENOENT) {
				error = 0;
				printf("Capability \"%s\" is not available\n",
					vm_capability_type2name(captype));
			} else {
				break;
			}
		}
	}

	if (!error && (get_active_cpus || get_all)) {
		error = vm_active_cpus(ctx, &cpus);
		if (!error)
			print_cpus("active cpus", &cpus);
	}

	if (!error && (get_debug_cpus || get_all)) {
		error = vm_debug_cpus(ctx, &cpus);
		if (!error)
			print_cpus("debug cpus", &cpus);
	}

	if (!error && (get_suspended_cpus || get_all)) {
		error = vm_suspended_cpus(ctx, &cpus);
		if (!error)
			print_cpus("suspended cpus", &cpus);
	}

	if (!error && (get_stats || get_all)) {
		int i, num_stats;
		uint64_t *stats;
		struct timeval tv;
		const char *desc;

		stats = vm_get_stats(vcpu, &tv, &num_stats);
		if (stats != NULL) {
			printf("vcpu%d stats:\n", vcpuid);
			for (i = 0; i < num_stats; i++) {
				desc = vm_get_stat_desc(ctx, i);
				printf("%-40s\t%ld\n", desc, stats[i]);
			}
		}
	}

	if (!error && (get_cpu_topology || get_all)) {
		uint16_t sockets, cores, threads, maxcpus;

		vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus);
		printf("cpu_topology:\tsockets=%hu, cores=%hu, threads=%hu, "
		    "maxcpus=%hu\n", sockets, cores, threads, maxcpus);
	}

	if (!error && get_vm_pid) {
		pid_t pid;

		error = vm_pid_request(vmname, rundir, &pid);
		if (!error)
			printf("vm pid:\t%d\n", pid);
	}

	if (!error && run) {
		struct vm_exit vmexit;
		cpuset_t cpuset;

		vmrun.vm_exit = &vmexit;
		vmrun.cpuset = &cpuset;
		vmrun.cpusetsize = sizeof(cpuset);
		error = vm_run(vcpu, &vmrun);
		if (error == 0)
			bhyvectl_dump_vm_run_exitcode(&vmexit, vcpuid);
		else
			printf("vm_run error %d\n", error);
	}

	if (!error && force_reset)
		error = vm_suspend(ctx, VM_SUSPEND_RESET);

	if (!error && force_poweroff)
		error = vm_suspend(ctx, VM_SUSPEND_POWEROFF);

#ifdef BHYVE_SNAPSHOT
	if (!error && checkpoint_file)
		error = snapshot_request(vmname, checkpoint_file,
				vm_suspend_opt,
				rundir);
#endif

	if (error)
		printf("errno = %d\n", errno);

	if (!error && destroy)
		vm_destroy(ctx);

	free(opts);
	exit(error);
}
