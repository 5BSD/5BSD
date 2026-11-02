/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The host half of dtrace -E (dtrace.c), built from libdtrace's own transport
 * (library-transport.inc): register the program (HPI2) on an ELF-only
 * receiver, send the compiled base program to "base" on a READDATA channel,
 * then, for each of COUNT guest uploads, receive the linked program, send the
 * derived guest program with dtrace_send_elf_derived() and acknowledge the
 * ingress as DERIVED, exactly in dtrace(1)'s order.  daemon-main.py drives
 * the real daemon and the guest.
 *
 * usage: consumer-elf-path SOCKET BASE-ELF DERIVED-ELF COUNT
 * Prints one line per step; exits nonzero at the first failed step.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <dtraced.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <dt_list.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>
#define DT_PROG_IDENTLEN DTRACED_PROGIDENTLEN
#define EDT_NOMEM ENOMEM
typedef struct { char dp_ident[DT_PROG_IDENTLEN]; char dp_srcident[DT_PROG_IDENTLEN]; uint16_t dp_vmid; uint64_t dp_vmepoch; } dtrace_prog_t;
int dtrace_program_source_id(const dtrace_prog_t *, uint8_t[16]);
int dtrace_send_elf(dtrace_prog_t *, int, int, const char *, int);
static char test_dtraced_sockpath[sizeof(((struct sockaddr_un *)0)->sun_path)];
#undef DTRACED_SOCKPATH
#define DTRACED_SOCKPATH test_dtraced_sockpath
#include "library-transport.inc"

static int
step(const char *name, int failed)
{
	printf("%s %s%s%s\n", name, failed ? "FAIL" : "ok",
	    failed ? " " : "", failed ? strerror(errno) : "");
	fflush(stdout);
	if (failed)
		exit(1);
	return (0);
}

int
main(int argc, char **argv)
{
	uint8_t session[16] = { 0 }, registration[64] = { 0 };
	uint8_t ingress_digest[SHA256_DIGEST_LENGTH];
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
	dtraced_hdr_t program_message = { 0 }, header = { 0 };
	dtraced_consumer_ack_t ack = { 0 };
	dtraced_derived_parent_t parent = { 0 };
	dtrace_prog_t host = { 0 }, guest = { 0 };
	unsigned char *frame;
	size_t transferred;
	int64_t deadline;
	int count, rx, wx, fd;

	if (argc != 5 || (count = atoi(argv[4])) <= 0 ||
	    strlcpy(test_dtraced_sockpath, argv[1],
	    sizeof(test_dtraced_sockpath)) >= sizeof(test_dtraced_sockpath))
		return (2);
	/* dtrace.c: digest and handle lifetime of the compiled program. */
	memcpy(registration, "HPI2", 4);
	SHA256((const unsigned char *)"consumer-elf-path", 17, registration + 8);
	dtraced_wire_put_u64(registration + 40, 0x5bd5);
	dtraced_wire_put_u64(registration + 48, 1);
	dtraced_wire_put_u64(registration + 56, 1);
	strlcpy(host.dp_ident, "consumer-elf-path", sizeof(host.dp_ident));

	rx = open_dtraced_session(DTD_SUB_ELFWRITE, session);
	step("rx", rx < 0);
	program_message.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
	program_message.elf.len = sizeof(registration);
	step("registered", dtrace_send_message(rx, &program_message,
	    registration, sizeof(registration)) != 0);
	wx = open_dtraced(DTD_SUB_READDATA);
	step("wx", wx < 0);
	fd = open(argv[2], O_RDONLY);
	step("base", fd < 0 ||
	    dtrace_send_elf(&host, fd, wx, "base", 0) != 0);
	close(fd);

	/* listen_dtraced(): each linked program, then its derivative. */
	while (count-- > 0) {
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
		    SHA256(frame, DTRACED_MSG_LEN(header),
		    ingress_digest) == NULL);
		parent.delivery_id = header.elf.delivery_id;
		parent.vmid = header.elf.vmid;
		parent.epoch = header.elf.epoch;
		memcpy(parent.consumer_session, session, 16);
		memcpy(parent.program_id, header.elf.program_id, 16);
		memcpy(parent.source_id, header.elf.source_id, 16);
		guest = host;
		guest.dp_vmid = header.elf.vmid;
		guest.dp_vmepoch = header.elf.epoch;
		fd = open(argv[3], O_RDONLY);
		step("derived", fd < 0 ||
		    dtrace_send_elf_derived(&guest, fd, wx, &parent) != 0);
		close(fd);

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
		free(frame);
	}
	/* Hold both channels until the driver has seen the publication. */
	(void)getchar();
	close(wx);
	close(rx);
	return (0);
}
