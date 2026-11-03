/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * dtrace -E's host half (dtrace.c) and a guest's dtrace -Y link step, on the
 * libdtrace under test (DTRACE_LIB in daemon-main.py).  Programs, identities
 * and frames all come from the library; only connect() is redirected from
 * the fixed daemon socket to the test daemon's.  The library runs without
 * the device (DTRACE_O_NODEV), which compiling, linking and deriving do not
 * need; only the handle lifetime in the registration is a fixed stand-in.
 *
 * usage: consumer-elf-path link BASE-ELF LINKED-ELF
 *	process_elf_hypertrace(): parse BASE-ELF, apply the HyperTrace
 *	relocations, write LINKED-ELF and print the source identity that
 *	dtrace_send_elf() puts on the guest's upload.
 * usage: consumer-elf-path publish SOCKET LINKED-ELF
 *	process_elf_hypertrace() for a program it does not run: upload the
 *	linked program to the guest daemon's outbound with its identity, which
 *	the daemon lists for the launch of the program derived from it.
 * usage: consumer-elf-path -q -Y SPOOL[,guest,SOURCE] [-N]
 *	The guest's dtrace -Y as the guest daemon's launch_program() runs it
 *	(HT_EXEC_DTRACE in daemon-main.cc), the argument parsed by dtrace.c's
 *	link_target_parse(): with -N, read the identifier list;
 *	parse the program (a derived program's srcident is acknowledged, a
 *	base program is acknowledged with no identifier), link it with
 *	dtrace.c's link_acknowledged() and upload it to HT_DTRACE_SOCKET's
 *	outbound with dtrace.c's send_linked(); with -N, report the launch.
 *	Enabling needs the device: a program marked for execution is reported
 *	installed and traces until SIGTERM; a base program exits.
 * usage: consumer-elf-path compile BASE-ELF
 *	dtrace -E's base program: write it and print its source identity.
 * usage: consumer-elf-path derive BASE-ELF LINKED-ELF DERIVED-ELF
 *	listen_dtraced(): the guest program (VM 42, epoch 99) derived from the
 *	guest's linked upload of BASE-ELF.
 * usage: consumer-elf-path upload SOCKET SPOOL,guest,SOURCE LINKED-ELF
 *	The guest's upload of LINKED-ELF for SPOOL again, with send_linked().
 * usage: consumer-elf-path SOCKET OUTDIR COUNT
 *	dtrace -E: compile the program, register it (HPI2) on the ELF receiver,
 *	send the base program (OUTDIR/base) on a READDATA channel, then, as
 *	listen_dtraced(), for each of COUNT linked guest programs: decode the
 *	VM envelope, parse against the host program, derive the guest program
 *	with dtrace_vprog_from(), send it with dtrace_send_elf_derived()
 *	(OUTDIR/derived.N) and acknowledge the ingress as DERIVED.  For the
 *	first, the guest's response (the derived program linked as dtrace -Y
 *	does) is matched as listen_dtraced() does, and the session's KILL is
 *	sent with dtrace.c's kill_from() and send_kill() (OUTDIR/kill.0 holds
 *	the response's guest pid).
 * Prints one line per step; exits nonzero at the first failed step.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <dev/vmm/vmm_param.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dt_program.h>
#include <dtrace.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>
#include <dtrace_identifiers.h>
#include "hypertrace_frame.h"

#define	PROGRAM	"syscall::getpid:entry { @htmark1 = count(); }"

static char sockpath[sizeof(((struct sockaddr_un *)0)->sun_path)];
static hypertrace_errmsg_t errmsg;

/* libdtrace connects to DTRACED_SOCKPATH; reach the test daemon instead. */
int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	static int (*real)(int, const struct sockaddr *, socklen_t);
	struct sockaddr_un alt;

	if (real == NULL)
		real = (int (*)(int, const struct sockaddr *, socklen_t))
		    dlsym(RTLD_NEXT, "connect");
	if (name->sa_family == AF_UNIX && sockpath[0] != '\0' &&
	    strcmp(((const struct sockaddr_un *)name)->sun_path,
	    DTRACED_SOCKPATH) == 0) {
		memset(&alt, 0, sizeof(alt));
		alt.sun_family = AF_UNIX;
		strlcpy(alt.sun_path, sockpath, sizeof(alt.sun_path));
		alt.sun_len = SUN_LEN(&alt);
		return (real(s, (struct sockaddr *)&alt, alt.sun_len));
	}
	return (real(s, name, namelen));
}

static void
step(const char *name, int failed)
{
	if (!failed)
		printf("%s ok\n", name);
	else
		printf("%s FAIL %s%s%s\n", name, strerror(errno),
		    errmsg[0] != '\0' ? ": " : "", errmsg);
	fflush(stdout);
	if (failed)
		exit(1);
}

static dtrace_hdl_t *
open_handle(int guest)
{
	dtrace_hdl_t *dtp;
	int err;

	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS,
	    &err);
	if (dtp == NULL) {
		errno = EINVAL;
		step("open", 1);
	}
	if (guest) {
		dtrace_set_guest(dtp);
		dtrace_set_failmsg_needed(dtp);
	}
	dtrace_enable_hypertrace(dtp);
	return (dtp);
}

static int
write_elf(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, const char *path)
{
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return (-1);
	if (dtrace_elf_create(dtp, pgp, ELFDATA2LSB, fd, path, errmsg) != 0 ||
	    fsync(fd) != 0 || lseek(fd, 0, SEEK_SET) != 0) {
		close(fd);
		errno = EIO;
		return (-1);
	}
	return (fd);
}

/* dtrace.c's link_acknowledged(), kill_from() and send_kill(). */
#include "consumer-elf-path.inc"

/* process_elf_hypertrace(): link_elf(), hypertrace_link(), the upload. */
static int
link_guest(const char *base, const char *linked)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp = NULL;
	uint8_t source[16];
	int fd, err = 0;

	dtp = open_handle(1);
	fd = open(base, O_RDONLY);
	step("parsed", fd < 0 || (pgp = dtrace_elf_parse(dtp, fd, base, 1,
	    &err, errmsg, NULL)) == NULL);
	close(fd);
	step("linked", hypertrace_link(dtp, pgp, errmsg) != 0);
	fd = write_elf(dtp, pgp, linked);
	step("written", fd < 0 || dtrace_program_source_id(pgp, source) != 0);
	close(fd);
	for (size_t i = 0; i < sizeof(source); i++)
		printf("%02x", source[i]);
	printf("\n");
	dtrace_close(dtp);
	return (0);
}

/* process_elf_hypertrace() for a program that is not marked for execution. */
static int
publish_linked(const char *linked)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp = NULL;
	int fd, sock, err = 0;

	dtp = open_handle(1);
	fd = open(linked, O_RDONLY);
	step("parsed", fd < 0 || (pgp = dtrace_elf_parse(dtp, fd, linked, 1,
	    &err, errmsg, NULL)) == NULL);
	sock = open_dtraced(DTD_SUB_READDATA);
	step("published", sock < 0 || lseek(fd, 0, SEEK_SET) != 0 ||
	    dtrace_send_elf(pgp, fd, sock, "outbound", 1) != 0);
	close(sock);
	close(fd);
	dtrace_close(dtp);
	return (0);
}

/*
 * process_elf_hypertrace() as launch_program() runs it, with -N while the
 * daemon lists identifiers.  Its stdout is the daemon's launch channel:
 * diagnostics go to stderr.  For the driver, the linked program is kept as
 * <HT_ROOT>/linked.<spool name> and the number of identifiers received as
 * <HT_ROOT>/idents.<spool name>.
 */
static int
run_guest(char *arg, int with_idents)
{
	char acknowledged[DT_PROG_IDENTLEN], linked[PATH_MAX], path[PATH_MAX];
	const char *daemon = getenv("HT_DTRACE_SOCKET");
	const char *name;
	char *spool;
	unsigned char *idents = NULL;
	uint8_t source[16];
	size_t count = 0;
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	FILE *f;
	int fd, sock, err = 0, prog_exec, host, sourced;

	if (link_target_parse(arg, &spool, &host, source, &sourced) != 0 ||
	    host) {
		fprintf(stderr, "-Y: %s\n", strerror(EINVAL));
		return (1);
	}
	name = strrchr(spool, '/');
	name = name == NULL ? spool : name + 1;
	if (daemon == NULL ||
	    strlcpy(sockpath, daemon, sizeof(sockpath)) >= sizeof(sockpath) ||
	    (with_idents && dtrace_read_identifiers(STDIN_FILENO, &idents,
	    &count, DT_PROG_IDENTLEN, dtraced_io_deadline_after(10000)) != 0)) {
		fprintf(stderr, "-N: %s\n", strerror(errno));
		return (1);
	}
	snprintf(path, sizeof(path), "%.*s/idents.%s",
	    (int)(strrchr(daemon, '/') - daemon), daemon, name);
	snprintf(linked, sizeof(linked), "%.*s/linked.%s",
	    (int)(strrchr(daemon, '/') - daemon), daemon, name);
	if ((f = fopen(path, "w")) == NULL || fprintf(f, "%zu\n", count) < 0 ||
	    fclose(f) != 0)
		return (1);
	dtp = open_handle(1);
	if (with_idents &&
	    dtrace_compile_idents_set(dtp, (char *)idents, count) != 0)
		return (1);
	free(idents);
	fd = open(spool, O_RDONLY);
	pgp = fd < 0 ? NULL : dtrace_elf_parse(dtp, fd, spool, 1, &err,
	    errmsg, NULL);
	close(fd);
	if (pgp == NULL) {
		fprintf(stderr, "parse %s: %s\n", spool, errmsg);
		return (1);
	}
	prog_exec = pgp->dp_exec;
	if (link_acknowledged(dtp, pgp, acknowledged, errmsg) != 0) {
		fprintf(stderr, "link: %s\n", errmsg);
		return (1);
	}
	pgp->dp_pid = getpid();
	fd = write_elf(dtp, pgp, linked);
	sock = fd < 0 ? -1 : open_dtraced(DTD_SUB_READDATA);
	if (sock < 0 || send_linked(pgp, fd, sock, sourced ? source : NULL, 0,
	    prog_exec) != 0) {
		fprintf(stderr, "upload: %s\n", strerror(errno));
		return (1);
	}
	close(sock);
	close(fd);
	if (with_idents && dtrace_write_launch_result(STDOUT_FILENO,
	    prog_exec == DT_PROG_EXEC, acknowledged, DT_PROG_IDENTLEN,
	    dtraced_io_deadline_after(10000)) != 0)
		return (1);
	if (prog_exec != DT_PROG_EXEC)
		return (0);
	for (;;)
		pause();
}

/*
 * A guest's upload of the linked program from SPOOL, again: dtraced must
 * refuse it once a KILL has revoked the spool's source.
 */
static int
upload_again(char *arg, const char *linked)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp = NULL;
	uint8_t source[16];
	char *spool;
	int fd, sock, err = 0, host, sourced;

	if (link_target_parse(arg, &spool, &host, source, &sourced) != 0 ||
	    host || !sourced)
		return (2);
	dtp = open_handle(1);
	fd = open(linked, O_RDONLY);
	step("parsed", fd < 0 || (pgp = dtrace_elf_parse(dtp, fd, linked, 1,
	    &err, errmsg, NULL)) == NULL);
	sock = open_dtraced(DTD_SUB_READDATA);
	step("uploaded", sock < 0 || lseek(fd, 0, SEEK_SET) != 0 ||
	    send_linked(pgp, fd, sock, source, 0, pgp->dp_exec) != 0);
	close(sock);
	close(fd);
	dtrace_close(dtp);
	return (0);
}

/* The base program's ELF and the source of its lineage. */
static int
compile_base(const char *path)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp = NULL;
	uint8_t source[16];
	int fd;

	dtp = open_handle(0);
	step("compiled", (pgp = dtrace_program_strcompile(dtp, PROGRAM,
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS | DTRACE_C_NOLIBS, 0,
	    NULL)) == NULL);
	fd = write_elf(dtp, pgp, path);
	step("written", fd < 0 || dtrace_program_source_id(pgp, source) != 0);
	close(fd);
	for (size_t i = 0; i < sizeof(source); i++)
		printf("%02x", source[i]);
	printf("\n");
	dtrace_close(dtp);
	return (0);
}

/* listen_dtraced(): the guest program derived from a linked upload. */
static int
derive(const char *base, const char *linked, const char *derived)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *hostpgp = NULL, *newprog = NULL, *guestpgp = NULL;
	int fd, err = 0;

	dtp = open_handle(0);
	fd = open(base, O_RDONLY);
	step("base", fd < 0 || (hostpgp = dtrace_elf_parse(dtp, fd, base, 0,
	    &err, errmsg, NULL)) == NULL);
	close(fd);
	fd = open(linked, O_RDONLY);
	step("parsed", fd < 0 || (newprog = dtrace_elf_parse(dtp, fd, linked,
	    0, &err, errmsg, hostpgp)) == NULL);
	close(fd);
	newprog->dp_vmid = 42;
	newprog->dp_vmepoch = 99;
	step("vprog", (guestpgp = dtrace_vprog_from(dtp, newprog,
	    PGP_KIND_HYPERCALLS)) == NULL);
	guestpgp->dp_exec = DT_PROG_EXEC;
	fd = write_elf(dtp, guestpgp, derived);
	step("derived", fd < 0);
	close(fd);
	dtrace_close(dtp);
	return (0);
}

/*
 * listen_dtraced() for the guest's response: dtrace -Y linked the derived
 * program and uploaded it; it names the derived program as its source.
 */
static dtrace_prog_t *
guest_response(dtrace_hdl_t *dtp, dtrace_prog_t *hostpgp,
    dtrace_prog_t *guestpgp, const char *derived, const char *path)
{
	dtrace_hdl_t *guest;
	dtrace_prog_t *pgp, *response;
	int fd, err = 0;

	guest = open_handle(1);
	fd = open(derived, O_RDONLY);
	pgp = fd < 0 ? NULL : dtrace_elf_parse(guest, fd, derived, 1, &err,
	    errmsg, NULL);
	close(fd);
	if (pgp == NULL || hypertrace_link(guest, pgp, errmsg) != 0)
		return (NULL);
	fd = write_elf(guest, pgp, path);
	dtrace_close(guest);
	if (fd < 0)
		return (NULL);
	response = dtrace_elf_parse(dtp, fd, path, 0, &err, errmsg, hostpgp);
	if (response != NULL || err != E_HYPERTRACE_AGAIN) {
		close(fd);
		errno = EPROTO;
		return (NULL);
	}
	response = dtrace_elf_parse(dtp, fd, path, 0, &err, errmsg, guestpgp);
	close(fd);
	return (response);
}

int
main(int argc, char **argv)
{
	uint8_t session[16] = { 0 }, registration[64] = { 0 }, digest[32];
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
	char path[PATH_MAX], rpath[PATH_MAX];
	dtraced_hdr_t program_message = { 0 }, header = { 0 };
	dtraced_consumer_ack_t ack = { 0 };
	dtraced_derived_parent_t parent = { 0 };
	dtrace_handle_lifetime_t lifetime;
	struct dtrace_ht_view view;
	dtrace_hdl_t *dtp;
	dtrace_prog_t *hostpgp = NULL, *newprog = NULL, *guestpgp, *response;
	dt_kill_t *kp = NULL;
	FILE *f;
	unsigned char *frame = NULL;
	size_t transferred;
	int64_t deadline;
	int count, n, rx, wx, fd, err;

	if (argc == 4 && strcmp(argv[1], "link") == 0)
		return (link_guest(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "publish") == 0) {
		strlcpy(sockpath, argv[2], sizeof(sockpath));
		return (publish_linked(argv[3]));
	}
	if ((argc == 4 || (argc == 5 && strcmp(argv[4], "-N") == 0)) &&
	    strcmp(argv[1], "-q") == 0 && strcmp(argv[2], "-Y") == 0)
		return (run_guest(argv[3], argc == 5));
	if (argc == 3 && strcmp(argv[1], "compile") == 0)
		return (compile_base(argv[2]));
	if (argc == 5 && strcmp(argv[1], "derive") == 0)
		return (derive(argv[2], argv[3], argv[4]));
	if (argc == 5 && strcmp(argv[1], "upload") == 0) {
		strlcpy(sockpath, argv[2], sizeof(sockpath));
		return (upload_again(argv[3], argv[4]));
	}
	if (argc != 4 || (count = atoi(argv[3])) <= 0 ||
	    strlcpy(sockpath, argv[1], sizeof(sockpath)) >= sizeof(sockpath))
		return (2);

	/* main(): compile, identify and register the program. */
	dtp = open_handle(0);
	step("compiled", (hostpgp = dtrace_program_strcompile(dtp, PROGRAM,
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS | DTRACE_C_NOLIBS, 0,
	    NULL)) == NULL ||
	    dtrace_program_compiled_digest(dtp, hostpgp, digest) != 0);
	/* The handle lifetime is the device's (DTRACEIOC_HANDLE_ID); without
	 * it, register a fixed one, which dtraced only records. */
	lifetime.generation[0] = 0x5bd5;
	lifetime.generation[1] = 1;
	lifetime.serial = 1;
	memcpy(registration, "HPI2", 4);
	memcpy(registration + 8, digest, 32);
	dtraced_wire_put_u64(registration + 40, lifetime.generation[0]);
	dtraced_wire_put_u64(registration + 48, lifetime.generation[1]);
	dtraced_wire_put_u64(registration + 56, lifetime.serial);
	rx = open_dtraced_session(DTD_SUB_ELFWRITE, session);
	step("rx", rx < 0);
	program_message.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
	program_message.elf.len = sizeof(registration);
	step("registered", dtrace_send_message(rx, &program_message,
	    registration, sizeof(registration)) != 0);
	wx = open_dtraced(DTD_SUB_READDATA);
	step("wx", wx < 0);
	snprintf(path, sizeof(path), "%s/base", argv[2]);
	fd = write_elf(dtp, hostpgp, path);
	step("base", fd < 0 || dtrace_send_elf(hostpgp, fd, wx, "base", 0) != 0);
	close(fd);

	/* listen_dtraced(): each linked program, then its derivative. */
	for (n = 0; n < count; n++) {
		deadline = dtraced_io_deadline_after(30000);
		step("ingress", deadline < 0 ||
		    dtraced_io_transfer(rx, header_wire, sizeof(header_wire),
		    false, deadline, &transferred) != 0 ||
		    dtraced_wire_decode_header(&header, header_wire) != 0 ||
		    DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF ||
		    header.elf.delivery_id == 0 ||
		    (frame = malloc(DTRACED_MSG_LEN(header))) == NULL ||
		    dtraced_io_transfer(rx, frame, DTRACED_MSG_LEN(header),
		    false, deadline, &transferred) != 0 ||
		    dtrace_ht_decode(frame, DTRACED_MSG_LEN(header),
		    VM_MAX_NAMELEN, &view) != 0 ||
		    dtrace_ht_validate_delivery(&view, header.elf.delivery_id,
		    header.elf.program_id, header.elf.source_id,
		    header.elf.vmid, header.elf.epoch) != 0);
		snprintf(path, sizeof(path), "%s/ingress.%d", argv[2], n);
		fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		err = 0;
		step("parsed", fd < 0 ||
		    write(fd, view.elf, view.length) != (ssize_t)view.length ||
		    fsync(fd) != 0 ||
		    (newprog = dtrace_elf_parse(dtp, fd, path, 0, &err, errmsg,
		    hostpgp)) == NULL);
		close(fd);
		free(frame);
		newprog->dp_vmid = view.vmid;
		newprog->dp_vmepoch = view.epoch;
		guestpgp = dtrace_vprog_from(dtp, newprog, PGP_KIND_HYPERCALLS);
		step("vprog", guestpgp == NULL);
		guestpgp->dp_exec = DT_PROG_EXEC;
		snprintf(path, sizeof(path), "%s/derived.%d", argv[2], n);
		fd = write_elf(dtp, guestpgp, path);
		parent.delivery_id = header.elf.delivery_id;
		parent.vmid = header.elf.vmid;
		parent.epoch = header.elf.epoch;
		memcpy(parent.consumer_session, session, 16);
		memcpy(parent.program_id, header.elf.program_id, 16);
		memcpy(parent.source_id, header.elf.source_id, 16);
		step("derived", fd < 0 ||
		    dtrace_send_elf_derived(guestpgp, fd, wx, &parent) != 0);
		close(fd);

		/* ack_identified_delivery() */
		ack.delivery_id = header.elf.delivery_id;
		memcpy(ack.program_id, header.elf.program_id, 16);
		memcpy(ack.source_id, header.elf.source_id, 16);
		ack.vmid = header.elf.vmid;
		ack.epoch = header.elf.epoch;
		ack.outcome = DTRACED_CONSUMER_ACK_DERIVED;
		dtraced_wire_encode_consumer_ack(ack_wire, &ack);
		deadline = dtraced_io_deadline_after(10000);
		step("acked", deadline < 0 || dtraced_io_transfer(rx, ack_wire,
		    sizeof(ack_wire), true, deadline, &transferred) != 0);
		if (n != 0)
			continue;

		/* The guest's response, kept for the session's KILL. */
		snprintf(path, sizeof(path), "%s/derived.%d", argv[2], n);
		snprintf(rpath, sizeof(rpath), "%s/response.%d", argv[2], n);
		response = guest_response(dtp, hostpgp, guestpgp, path, rpath);
		step("response", response == NULL);
		response->dp_vmid = view.vmid;
		response->dp_vmepoch = view.epoch;
		response->dp_pid = 4243;
		step("kill", (kp = kill_from(newprog, response)) == NULL);
	}

	/* Once the driver has seen the publication, the session ends: the
	 * KILL for the first guest program. */
	(void)getchar();
	snprintf(path, sizeof(path), "%s/kill.0", argv[2]);
	f = fopen(path, "w");
	step("killed", f == NULL || fprintf(f, "%d\n", kp->response->dp_pid) < 0 ||
	    fclose(f) != 0 || send_kill(wx, kp) != 0);
	free(kp);
	(void)getchar();
	close(wx);
	close(rx);
	dtrace_close(dtp);
	return (0);
}
