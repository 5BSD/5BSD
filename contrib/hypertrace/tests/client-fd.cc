/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * client_fd protocol primitives (dtraced_connection.cc, actual object) over
 * socketpairs: consumer stop/drain challenges, response encoders, and the
 * forwarder attestation gate on every send/recv. VM_GET_ATTESTATION is the
 * only injected boundary; it answers from a per-descriptor table.
 *
 * Oracles: the peer decodes each frame with the production wire codecs and
 * checks every field against the challenge; replies are built field by field
 * so each mismatch is exercised; a stream must be shut down exactly when a
 * reply is missing or does not match (the peer then reads EOF), and the
 * returned errno distinguishes refusal (EOPNOTSUPP), retirement (ESTALE)
 * and protocol damage (EPROTO).
 */
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <amd64/include/vmm_dev.h>
#include <cstdarg>
#include <functional>
#include <map>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_connection.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"

using namespace dtraced;

static std::map<int, hypertrace_vm_attestation> attestations;
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (request != VM_GET_ATTESTATION)
		return (__real_ioctl(fd, request, arg));
	auto it = attestations.find(fd);
	if (it == attestations.end()) {
		errno = EBADF;
		return (-1);
	}
	memcpy(arg, &it->second, sizeof(it->second));
	return (0);
}

struct pair {
	int sv[2] = {-1, -1};
	pair() { CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0); }
	~pair() { if (sv[1] >= 0) close(sv[1]); }
};

static dtd_initmsg_t
consumer_hello(uint64_t subs = DTD_SUB_ELFWRITE)
{
	dtd_initmsg_t m{};
	m.kind = DTRACED_KIND_CONSUMER;
	m.protocol_version = DTRACED_PROTOCOL_VERSION;
	m.subs = subs;
	strlcpy(m.ident, "dtrace-77-0000000000000000000000000000000a", sizeof(m.ident));
	m.session_id[0] = 0xc5;
	return (m);
}

static dtraced_consumer_stop_t
challenge()
{
	dtraced_consumer_stop_t c{};
	c.token[0] = 1;
	c.source_session[0] = 2;
	c.consumer_session[0] = 0xc5;
	c.program_digest[0] = 4;
	c.vmid = 5;
	c.epoch = 6;
	return (c);
}

static void
recv_all(int fd, void *p, size_t n)
{
	size_t t;
	CHECK(dtraced_io_transfer(fd, p, n, false, dtraced_io_deadline_after(5000),
	    &t) == 0);
}

static void
send_all(int fd, const void *p, size_t n)
{
	size_t t;
	CHECK(dtraced_io_transfer(fd, (void *)p, n, true,
	    dtraced_io_deadline_after(5000), &t) == 0);
}

/* Run one stop (or drain) exchange; the peer reads the request, checks it,
 * then applies reply(). Returns (result, errno, peer saw EOF afterwards). */
struct outcome {
	bool ok;
	int error;
	bool eof;
};

static outcome
stop_exchange(bool drain, std::function<void(int, const dtraced_consumer_stop_t &)> reply,
    std::function<void(client_fd &)> before = {})
{
	pair p;
	client_fd c(-1, p.sv[0], consumer_hello());
	if (before)
		before(c);
	dtraced_consumer_stop_t ch = challenge();
	std::thread peer([&] {
		unsigned char hw[DTRACED_MSGHDRSIZE];
		recv_all(p.sv[1], hw, sizeof(hw));
		dtraced_hdr_t h;
		CHECK(dtraced_wire_decode_header(&h, hw) == 0);
		dtraced_consumer_stop_t got{};
		if (drain) {
			unsigned char bw[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
			CHECK(h.msg_type == DTRACED_MSG_CONSUMER_DRAIN &&
			    h.elf.len == sizeof(bw));
			recv_all(p.sv[1], bw, sizeof(bw));
			CHECK(dtraced_wire_decode_consumer_drain(&got, bw) == 0);
		} else {
			unsigned char bw[DTRACED_CONSUMER_STOP_WIRE_SIZE];
			CHECK(h.msg_type == DTRACED_MSG_CONSUMER_STOP &&
			    h.elf.len == sizeof(bw));
			recv_all(p.sv[1], bw, sizeof(bw));
			CHECK(dtraced_wire_decode_consumer_stop(&got, bw) == 0);
		}
		CHECK(memcmp(got.token, ch.token, 16) == 0 &&
		    memcmp(got.consumer_session, ch.consumer_session, 16) == 0 &&
		    got.vmid == ch.vmid && got.epoch == ch.epoch);
		reply(p.sv[1], got);
	});
	errno = 0;
	bool ok = drain ? c.request_consumer_drain(ch) : c.request_consumer_stop(ch);
	int error = errno;
	peer.join();
	struct pollfd pfd = {p.sv[1], POLLIN, 0};
	bool eof = poll(&pfd, 1, 200) == 1 && [&] {
		char b;
		return read(p.sv[1], &b, 1) == 0;
	}();
	return {ok, error, eof};
}

static void
reply_ack(int fd, dtraced_consumer_stop_t ack, bool drain, uint8_t result = 1)
{
	ack.result = result;
	if (drain) {
		unsigned char w[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
		dtraced_wire_encode_consumer_drain_ack(w, &ack);
		send_all(fd, w, sizeof(w));
	} else {
		unsigned char w[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
		dtraced_wire_encode_consumer_stop_ack(w, &ack);
		send_all(fd, w, sizeof(w));
	}
}

static void
test_challenges()
{
	for (bool drain : {false, true}) {
		/* accepted */
		outcome o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &g) {
			reply_ack(fd, g, drain); });
		CHECK(o.ok && !o.eof);
		/* refused by the consumer: stream stays usable */
		o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &g) {
			reply_ack(fd, g, drain, 0); });
		CHECK(!o.ok && o.error == EOPNOTSUPP && !o.eof);
		/* every echoed field must match */
		using edit_t = void (*)(dtraced_consumer_stop_t &);
		const edit_t edits[] = {
			[](dtraced_consumer_stop_t &a) { a.token[1] = 9; },
			[](dtraced_consumer_stop_t &a) { a.source_session[1] = 9; },
			[](dtraced_consumer_stop_t &a) { a.consumer_session[1] = 9; },
			[](dtraced_consumer_stop_t &a) { a.program_digest[1] = 9; },
			[](dtraced_consumer_stop_t &a) { a.vmid = 6; },
			[](dtraced_consumer_stop_t &a) { a.epoch = 7; },
		};
		for (edit_t e : edits) {
			o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &g) {
				dtraced_consumer_stop_t a = g;
				e(a);
				reply_ack(fd, a, drain);
			});
			CHECK(!o.ok && o.error == EPROTO && o.eof);
		}
		/* undecodable reply */
		o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &) {
			std::vector<unsigned char> junk(drain ?
			    DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE :
			    DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE, 0xff);
			send_all(fd, junk.data(), junk.size());
		});
		CHECK(!o.ok && o.error == EPROTO && o.eof);
		/* lost reply */
		o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &) {
			shutdown(fd, SHUT_WR);
		});
		CHECK(!o.ok && o.eof);
		/* the connection is retired while the consumer answers */
		client_fd *seen = nullptr;
		o = stop_exchange(drain, [&](int fd, const dtraced_consumer_stop_t &g) {
			seen->retired.store(true);
			reply_ack(fd, g, drain);
		}, [&](client_fd &c) { seen = &c; });
		CHECK(!o.ok && o.error == ESTALE);
	}
	/* preconditions: no I/O at all */
	pair p;
	{
		client_fd c(-1, p.sv[0], consumer_hello(DTD_SUB_READDATA));
		dtraced_consumer_stop_t ch = challenge();
		CHECK(!c.request_consumer_stop(ch) && errno == EPROTO);
		CHECK(!c.request_consumer_drain(ch) && errno == EPROTO);
		CHECK(peer_quiet(p.sv[1], 20));
	}
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	{
		client_fd c(-1, sv[0], consumer_hello());
		dtraced_consumer_stop_t ch = challenge();
		ch.consumer_session[0] = 0x11;
		CHECK(!c.request_consumer_stop(ch) && errno == EPROTO);
		CHECK(!c.request_consumer_drain(ch) && errno == EPROTO);
		ch = challenge();
		ch.token[0] = 0;	/* not encodable as a canonical challenge */
		CHECK(!c.request_consumer_stop(ch));
		CHECK(!c.request_consumer_drain(ch));
		c.retired.store(true);
		CHECK(!c.request_consumer_stop(challenge()) && errno == EPROTO);
		CHECK(!c.request_consumer_drain(challenge()) && errno == EPROTO);
		dtd_initmsg_t f = consumer_hello();
		f.kind = DTRACED_KIND_FORWARDER;
		client_fd fwd(-1, dup(sv[0]), f);
		CHECK(!fwd.request_consumer_stop(challenge()) && errno == EPROTO);
		CHECK(peer_quiet(sv[1], 20));
	}
	close(sv[1]);
}

static void
test_responses()
{
	pair p;
	client_fd c(-1, p.sv[0], consumer_hello(DTD_SUB_READDATA));
	unsigned char b[64];
	/* transfer */
	std::vector<uint8_t> payload = {1, 2, 3};
	CHECK(c.respond_with_transfer(true, &payload, 0));
	recv_all(p.sv[1], b, 1 + 8 + 3);
	CHECK(b[0] == 1 && dtraced_wire_get_u64(b + 1) == 3 && b[9] == 1 && b[11] == 3);
	std::vector<uint8_t> empty;
	CHECK(!c.respond_with_transfer(true, &empty, 0) && errno == EPROTO);
	CHECK(!c.respond_with_transfer(true, nullptr, 0) && errno == EPROTO);
	std::vector<uint8_t> huge(DTRACED_TRANSFER_MAX_SIZE + 1);
	CHECK(!c.respond_with_transfer(true, &huge, 0) && errno == EPROTO);
	CHECK(c.respond_with_transfer(false, nullptr, 0));
	recv_all(p.sv[1], b, 1);
	CHECK(b[0] == 0);
	/* drain step */
	uint8_t remaining = 1;
	CHECK(c.respond_with_drain_step(true, &remaining, 0));
	recv_all(p.sv[1], b, 2);
	CHECK(b[0] == 1 && b[1] == 1);
	remaining = 2;
	CHECK(!c.respond_with_drain_step(true, &remaining, 0) && errno == EPROTO);
	CHECK(!c.respond_with_drain_step(true, nullptr, 0) && errno == EPROTO);
	CHECK(c.respond_with_drain_step(false, nullptr, 0));
	recv_all(p.sv[1], b, 1);
	CHECK(b[0] == 0);
	/* release */
	uint8_t attestation[DTRACED_RELEASE_ATTESTED_SIZE];
	memset(attestation, 0x5a, sizeof(attestation));
	CHECK(c.respond_with_release(true, attestation, false, 0));
	recv_all(p.sv[1], b, 2);
	CHECK(b[0] == 1 && b[1] == DTRACED_RELEASE_MODE_LOCAL);
	CHECK(c.respond_with_release(true, attestation, true, 0));
	std::vector<unsigned char> big(2 + DTRACED_RELEASE_ATTESTED_SIZE);
	recv_all(p.sv[1], big.data(), big.size());
	CHECK(big[0] == 1 && big[1] == DTRACED_RELEASE_MODE_SIGNED &&
	    memcmp(big.data() + 2, attestation, sizeof(attestation)) == 0);
	CHECK(!c.respond_with_release(true, nullptr, true, 0) && errno == EPROTO);
	CHECK(c.respond_with_release(false, nullptr, false, 0));
	recv_all(p.sv[1], b, 1);
	CHECK(b[0] == 0);
	/* status and statistics */
	dtraced_delivery_status_t st{};
	st.delivery_id = 9;
	st.phase = 'a';
	CHECK(c.respond_with_status(true, &st, 0));
	recv_all(p.sv[1], b, 1 + DTRACED_STATUS_WIRE_SIZE);
	CHECK(b[0] == 1 && dtraced_wire_get_u64(b + 1) == 9 && b[9] == 'a');
	CHECK(c.respond_with_status(true, nullptr, 0));
	recv_all(p.sv[1], b, 1);
	CHECK(b[0] == 1);
	dtraced_stats_t stats{1, 2, 3, 4};
	CHECK(c.respond_with_stats(true, &stats, 0));
	recv_all(p.sv[1], b, 33);
	CHECK(b[0] == 1 && dtraced_wire_get_u64(b + 25) == 4);
	CHECK(c.respond_with_stats(false, &stats, 0));
	recv_all(p.sv[1], b, 1);
	CHECK(b[0] == 0 && peer_quiet(p.sv[1], 20));
	/* the peer is gone: a response fails and retires the stream */
	close(p.sv[1]);
	p.sv[1] = -1;
	signal(SIGPIPE, SIG_IGN);
	CHECK(!c.respond_with_status(true, nullptr, 0));
}

static void
test_attestation_gate()
{
	dtd_initmsg_t f{};
	f.kind = DTRACED_KIND_FORWARDER;
	f.protocol_version = DTRACED_PROTOCOL_VERSION;
	f.subs = DTD_SUB_READDATA;
	strlcpy(f.ident, "guest-a", sizeof(f.ident));
	f.session_id[0] = 1;
	pair p;
	client_fd a(-1, p.sv[0], f);
	/* unattested forwarder with no VM identity is current */
	CHECK(a.current_vm_attestation());
	int afd = open("/dev/null", O_RDONLY);
	a.vm_attestation_fd = afd;
	a.vmid = 7;
	a.vm_epoch = 9;
	hypertrace_vm_attestation id{};
	id.vmid = 7;
	id.epoch = 9;
	strlcpy(id.name, "guest-a", sizeof(id.name));
	attestations[afd] = id;
	CHECK(a.current_vm_attestation());
	unsigned char byte = 1, back;
	CHECK(a.send(&byte, 1, 0));
	recv_all(p.sv[1], &back, 1);
	send_all(p.sv[1], &byte, 1);
	CHECK(a.recv(&back, 1, 0) && back == 1);
	/* same forwarder identity: every component must match */
	int sv2[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
	client_fd b(-1, sv2[0], f);
	int bfd = open("/dev/null", O_RDONLY);
	b.vm_attestation_fd = bfd;
	attestations[bfd] = id;
	b.vmid = 7;
	b.vm_epoch = 9;
	a.peer_pid = b.peer_pid = 100;
	a.peer_uid = b.peer_uid = 0;
	CHECK(a.same_forwarder(b) && b.same_forwarder(a));
	b.peer_pid = 101;
	CHECK(!a.same_forwarder(b));
	b.peer_pid = 100;
	b.peer_uid = 5;
	CHECK(!a.same_forwarder(b));
	b.peer_uid = 0;
	b.vm_epoch = 10;
	CHECK(!a.same_forwarder(b));
	b.vm_epoch = 9;
	b.session_id[0] = 2;
	CHECK(!a.same_forwarder(b));
	b.session_id[0] = 1;
	b.ident[0] = 'h';
	CHECK(!a.same_forwarder(b));
	b.ident[0] = 'g';
	a.peer_pid = -1;
	CHECK(!a.same_forwarder(b));
	a.peer_pid = 100;
	a.peer_uid = (uid_t)-1;
	CHECK(!a.same_forwarder(b));
	a.peer_uid = 0;
	CHECK(a.same_forwarder(b));
	/* attestation that no longer matches: every component checked */
	using edit_t = void (*)(hypertrace_vm_attestation &);
	const edit_t stale[] = {
		[](hypertrace_vm_attestation &x) { x.vmid = 8; },
		[](hypertrace_vm_attestation &x) { x.epoch = 10; },
		[](hypertrace_vm_attestation &x) { strlcpy(x.name, "guest-b", sizeof(x.name)); },
		[](hypertrace_vm_attestation &x) { memset(x.name, 'n', sizeof(x.name)); },
	};
	for (edit_t e : stale) {
		hypertrace_vm_attestation x = id;
		e(x);
		attestations[bfd] = x;
		CHECK(!b.current_vm_attestation() && !a.same_forwarder(b));
	}
	attestations.erase(bfd);
	CHECK(!b.current_vm_attestation());
	/* a stale forwarder can neither send nor receive; the stream is
	 * shut down so a partial frame is never reused */
	errno = 0;
	CHECK(!b.send(&byte, 1, 0) && errno == ESTALE);
	CHECK(!b.recv(&back, 1, 0) && errno == ESTALE);
	char eof;
	CHECK(read(sv2[1], &eof, 1) == 0);
	/* attestation lost between transfer and the post-check */
	attestations[bfd] = id;
	int sv3[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3) == 0);
	client_fd d(-1, sv3[0], f);
	d.vm_attestation_fd = open("/dev/null", O_RDONLY);
	d.vmid = 7;
	d.vm_epoch = 9;
	attestations[d.vm_attestation_fd] = id;
	std::thread revoke([&] {
		/* the peer answers only after the attestation was revoked */
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		attestations[d.vm_attestation_fd].epoch = 99;
		send_all(sv3[1], &byte, 1);
	});
	CHECK(!d.recv(&back, 1, dtraced_io_deadline_after(3000)) && errno == ESTALE);
	revoke.join();
	close(sv2[1]);
	close(sv3[1]);
	attestations.clear();
}

/* Helpers kept for existing test callers (decision 2): one status byte per
 * call, the documented value, and -1 once the descriptor is closed. */
static void
test_kept_helpers()
{
	{
		pair p;
		client_fd c(-1, p.sv[0], consumer_hello());
		unsigned char got[4];
		CHECK(c.send_ack() == 0 && c.send_nak() == 0);	/* 0: the byte was sent */
		CHECK(c.respond(true) && c.respond(false));
		recv_all(p.sv[1], got, 4);
		CHECK(got[0] == 1 && got[1] == 0 && got[2] == 1 && got[3] == 0);
		std::string name = c;
		CHECK(name.find(c.ident) != std::string::npos &&
		    name.find(std::to_string(p.sv[0])) != std::string::npos);
		c.close();
		errno = 0;
		CHECK(c.send_ack() == -1 && c.send_nak() == -1 && !c.respond(true));
	}
}

int
main()
{
	alarm(120);
	test_challenges();
	test_responses();
	test_attestation_gate();
	test_kept_helpers();
	printf("client-fd: %u checks passed\n", harness_checks);
	return (0);
}
