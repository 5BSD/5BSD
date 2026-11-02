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
 * usage: consumer-elf-path SOCKET OUTDIR COUNT
 *	dtrace -E: compile the program, register it (HPI2) on the ELF receiver,
 *	send the base program (OUTDIR/base) on a READDATA channel, then, as
 *	listen_dtraced(), for each of COUNT linked guest programs: decode the
 *	VM envelope, parse against the host program, derive the guest program
 *	with dtrace_vprog_from(), send it with dtrace_send_elf_derived()
 *	(OUTDIR/derived.N) and acknowledge the ingress as DERIVED.
 * Prints one line per step; exits nonzero at the first failed step.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <dev/vmm/vmm_param.h>
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

int
main(int argc, char **argv)
{
	uint8_t session[16] = { 0 }, registration[64] = { 0 }, digest[32];
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
	char path[PATH_MAX];
	dtraced_hdr_t program_message = { 0 }, header = { 0 };
	dtraced_consumer_ack_t ack = { 0 };
	dtraced_derived_parent_t parent = { 0 };
	dtrace_handle_lifetime_t lifetime;
	struct dtrace_ht_view view;
	dtrace_hdl_t *dtp;
	dtrace_prog_t *hostpgp = NULL, *newprog = NULL, *guestpgp;
	unsigned char *frame = NULL;
	size_t transferred;
	int64_t deadline;
	int count, n, rx, wx, fd, err;

	if (argc == 4 && strcmp(argv[1], "link") == 0)
		return (link_guest(argv[2], argv[3]));
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
	}
	/* Hold both channels until the driver has seen the publication. */
	(void)getchar();
	close(wx);
	close(rx);
	dtrace_close(dtp);
	return (0);
}
