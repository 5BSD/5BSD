/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * A host consumer's registered program reaches the attested bhyve forwarder.
 *
 * Path under test (overlord): the base ELF that dtrace -E stored is published
 * to outbound exactly as process_base() does, process_outbound() queues a
 * NOTIFY_ELFWRITE job for the ELF-write subscriber, and the worker's
 * handle_job() -> send_elf() sends it. The peer is modelled on bhyve's
 * forwarder (usr.sbin/bhyve/hypertrace.c hypertrace_read_epoch() and
 * hypertrace_ack_epoch()): it reads one dtraced header and the payload and
 * acknowledges the delivery ID after the device accepted the frame.
 *
 * Oracles: the job succeeds (no "failed to handle job kind 1"), the forwarder
 * received a bare ELF with program/source/delivery IDs, outbound deliveries
 * are recorded and accepted, and the durable token is accepted. Three program
 * shapes: guest-only clauses, host and guest clauses, host-only clauses.
 */
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <openssl/sha.h>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_io.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"

using namespace dtraced;

namespace dtraced {
struct state_attestation_test {
	static void set_control(state &s) { s.ctrlmachine = 1; }
	static bool handle(state &s, job *j) { return s.handle_job(j); }
};
}

static int attestation_fd = -1;
static hypertrace_vm_attestation attested_vm{};

extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	if (fd != attestation_fd || request != VM_GET_ATTESTATION) {
		errno = ENOTTY;
		return -1;
	}
	va_list args;
	va_start(args, request);
	void *data = va_arg(args, void *);
	va_end(args);
	memcpy(data, &attested_vm, sizeof(attested_vm));
	return 0;
}

struct forwarder_seen {
	bool framed = false;
	uint64_t delivery_id = 0;
	uint8_t program_id[16]{};
	uint8_t source_id[16]{};
	std::vector<unsigned char> payload;
};

/* bhyve's rx reader: header, payload, then the delivery ACK. */
static void
bhyve_forwarder(int fd, forwarder_seen *seen)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];
	dtraced_hdr_t header{};
	size_t transferred = 0;
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (dtraced_io_transfer(fd, wire, sizeof(wire), false, deadline,
	    &transferred) != 0 || dtraced_wire_decode_header(&header, wire) != 0 ||
	    header.msg_type != DTRACED_MSG_ELF || header.elf.len == 0 ||
	    header.elf.delivery_id == 0)
		return;
	seen->payload.resize(header.elf.len);
	if (dtraced_io_transfer(fd, seen->payload.data(), header.elf.len, false,
	    deadline, &transferred) != 0)
		return;
	/* pci_vtdtr_elf_target(): the device takes a bare ELF or a VM target
	 * envelope followed by one. Anything else fails the frame: no ACK, and
	 * the device is marked NEEDS_RESET. */
	const unsigned char *p = seen->payload.data();
	size_t n = seen->payload.size();
	if (n < 4)
		return;
	if (memcmp(p, "\177ELF", 4) != 0) {
		struct hypertrace_vm_envelope target;
		if (n < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4)
			return;
		hypertrace_envelope_decode(&target, p);
		if (target.magic != HYPERTRACE_TARGET_MAGIC ||
		    target.version != HYPERTRACE_ENVELOPE_VERSION ||
		    target.vmid != 7 || target.epoch != 11 ||
		    target.name_length != 0 ||
		    memcmp(p + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "\177ELF", 4) != 0)
			return;
	}
	seen->framed = true;
	seen->delivery_id = header.elf.delivery_id;
	memcpy(seen->program_id, header.elf.program_id, 16);
	memcpy(seen->source_id, header.elf.source_id, 16);
	dtraced_delivery_ack_t ack{};
	ack.delivery_id = header.elf.delivery_id;
	(void)dtraced_wire_write_ack(fd, &ack, deadline, &transferred);
}

static void
write_file(int dirfd, const char *name, const std::vector<unsigned char> &bytes)
{
	int fd = openat(dirfd, name, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0);
	assert(write(fd, bytes.data(), bytes.size()) == (ssize_t)bytes.size());
	assert(close(fd) == 0);
}

static void
run_case(const char *label, const char *name, const char *clauses)
{
	char base_path[] = "/tmp/hypertrace-guest-delivery-base.XXXXXX";
	char out_path[] = "/tmp/hypertrace-guest-delivery-out.XXXXXX";
	assert(mkdtemp(base_path) != nullptr && mkdtemp(out_path) != nullptr);
	state s{};
	state_attestation_test::set_control(s);
	{
		dir base(base_path, nullptr);
		dir outbound(out_path, &process_outbound);
		base.state = &s;
		outbound.state = &s;
		s.basedir = &base;
		s.outbounddir = &outbound;

		int kq = kqueue(), pair[2];
		assert(kq >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
		dtd_initmsg_t hello{};
		hello.kind = DTRACED_KIND_FORWARDER;
		/* bhyve's rx channel (hypertrace.c ht_connector). */
		hello.subs = DTD_SUB_ELFWRITE | DTD_SUB_KILL | DTD_SUB_CLEANUP |
		    DTD_SUB_ADMISSION_ACK;
		hello.session_id[0] = 0x5a;
		strlcpy(hello.ident, "ht-trace1", sizeof(hello.ident));
		{
			client_fd forwarder(kq, pair[0], hello);
			attestation_fd = dup(pair[0]);
			assert(attestation_fd >= 0);
			forwarder.vm_attestation_fd = attestation_fd;
			forwarder.vmid = attested_vm.vmid = 7;
			forwarder.vm_epoch = attested_vm.epoch = 11;
			strlcpy(attested_vm.name, "ht-trace1",
			    sizeof(attested_vm.name));
			assert(forwarder.current_vm_attestation());
			assert(s.recover_outbound_deliveries(&forwarder));
			assert(forwarder.enable_write(&forwarder));
			s.sockfds.insert(&forwarder);
			/* The registered dtrace -E ELF receiver is connected too;
			 * outbound publication is for forwarders only. */
			int cpair[2];
			assert(socketpair(AF_UNIX, SOCK_STREAM, 0, cpair) == 0);
			dtd_initmsg_t chello{};
			chello.kind = DTRACED_KIND_CONSUMER;
			chello.subs = DTD_SUB_ELFWRITE;
			chello.session_id[0] = 0xc5;
			snprintf(chello.ident, sizeof(chello.ident), "dtrace-%d",
			    (int)getpid());
			client_fd consumer(kq, cpair[0], chello);
			consumer.consumer_program_valid = true;
			consumer.consumer_registration_acked = true;
			s.sockfds.insert(&consumer);

			/* dtrace -E's unlinked base ELF (guest clauses keep their
			 * VM target inside the DIF, not in a VM envelope). */
			std::vector<unsigned char> elf = { 0x7f, 'E', 'L', 'F' };
			elf.insert(elf.end(), clauses, clauses + strlen(clauses));
			write_file(base.dirfd, name, elf);
			/* process_base(): publish to guests, then the host link. */
			assert(outbound.copy_data(base.dirfd, name));
			/* The copy is a new publication: a fresh program ID
			 * with the base program's source lineage. */
			struct dirent file{};
			{
				DIR *d = opendir(out_path);
				assert(d != nullptr);
				struct dirent *e;
				unsigned found = 0;
				while ((e = readdir(d)) != nullptr)
					if (strncmp(e->d_name, "elf.", 4) == 0 &&
					    strlen(e->d_name) == 69) {
						file = *e;
						found++;
					}
				closedir(d);
				assert(found == 1);
				assert(strcmp(file.d_name + 37, name + 37) == 0);
			}
			assert(process_outbound(outbound, &file));
			assert(outbound.memorized(file.d_name));
			assert(s.joblist.size() == 1); /* none for the consumer */
			job *pending = s.joblist.front();
			s.joblist.clear();
			assert(pending->kind == NOTIFY_ELFWRITE &&
			    pending->connsockfd == &forwarder);

			forwarder_seen seen;
			std::thread peer(bhyve_forwarder, pair[1], &seen);
			errno = 0;
			bool handled = state_attestation_test::handle(s, pending);
			int error = errno;
			peer.join();
			if (!handled) {
				fprintf(stderr, "%s: failed to handle job kind %d "
				    "(errno %d: %s)\n", label, pending->kind, error,
				    strerror(error));
				abort();
			}
			assert(seen.framed && seen.payload == elf);
			assert(memcmp(seen.payload.data(), "\177ELF", 4) == 0);
			assert(seen.source_id[0] == 0x22 && seen.source_id[15] == name[68] - '0');
			{
				std::lock_guard lock(forwarder.installed_mtx);
				assert(forwarder.outbound_deliveries.size() == 1);
				const outbound_delivery &d =
				    forwarder.outbound_deliveries[0];
				assert(d.delivery_id == seen.delivery_id &&
				    d.accepted && d.target_vmid == 7 &&
				    d.target_epoch == 11);
			}
			durable_delivery record{};
			record.session_id = forwarder.session_id;
			record.delivery_id = seen.delivery_id;
			record.vmid = 7;
			record.epoch = 11;
			memcpy(record.program_id.data(), seen.program_id, 16);
			memcpy(record.source_id.data(), seen.source_id, 16);
			record.peer_uid = (uint32_t)forwarder.peer_uid;
			record.peer_pid = (uint32_t)forwarder.peer_pid;
			record.journal_version = 4;
			assert(SHA256(elf.data(), elf.size(),
			    record.payload_digest.data()) != nullptr);
			assert(outbound.delivery_status(record) ==
			    (int)delivery_phase::accepted);
			delete pending;
			s.sockfds.clear();
			close(cpair[1]);
		}
		close(pair[1]);
		close(kq);
		s.basedir = nullptr;
		s.outbounddir = nullptr;
	}
	printf("PASS %s\n", label);
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "rm -rf %s %s", base_path, out_path);
	assert(system(cmd) == 0);
}

int main()
{
	run_case("guest-only",
	    "elf.11000000000000000000000000000001.22000000000000000000000000000001",
	    "ht-trace1:syscall:::entry");
	run_case("host+guest",
	    "elf.11000000000000000000000000000002.22000000000000000000000000000002",
	    "syscall:::entry ht-trace1:syscall:::entry");
	run_case("host-only",
	    "elf.11000000000000000000000000000003.22000000000000000000000000000003",
	    "syscall:::entry");
	puts("PASS: registered consumer programs reach the attested forwarder");
}
