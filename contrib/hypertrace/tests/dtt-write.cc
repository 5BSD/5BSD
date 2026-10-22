/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Guest dttransport writer (write_dttransport and setup_connection) with
 * the actual daemon objects. The daemon's control socket path is redirected
 * by a connect() wrapper to a private listener; any other use of that path
 * fails, so the installed daemon is never contacted. The device is a
 * socketpair; listen_dttransport runs alongside so a DTT_HOST_ELF receipt
 * from the scripted driver releases the writer exactly as in production.
 *
 * Oracles: the driver reassembles DTT_ELF fragments and compares them byte
 * for byte with the frame the local daemon sent, checking identifiers,
 * hasmore/len/totallen bookkeeping and the SHA-256 the writer registers; the
 * local daemon receives an 8-byte little-endian delivery ACK only after the
 * receipt. Every malformed frame or transport fault must stop the writer
 * before any device record is written.
 */
#include <sys/un.h>
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <semaphore.h>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>
#include "daemon-harness.h"
#include "dtraced.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_elf.h"
#include "dtraced_io.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"

using namespace dtraced;

static char redirect_path[104];
extern "C" int __real_connect(int, const struct sockaddr *, socklen_t);
extern "C" int
__wrap_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
	if (addr->sa_family == AF_UNIX &&
	    strcmp(un->sun_path, DTRACED_SOCKPATH) == 0) {
		if (redirect_path[0] == '\0') {
			errno = ECONNREFUSED;
			return (-1);
		}
		struct sockaddr_un local{};
		local.sun_family = AF_UNIX;
		strlcpy(local.sun_path, redirect_path, sizeof(local.sun_path));
		return (__real_connect(fd, (struct sockaddr *)&local, sizeof(local)));
	}
	return (__real_connect(fd, addr, len));
}

static std::atomic<int> socket_errno{0};
extern "C" int __real_socket(int, int, int);
extern "C" int
__wrap_socket(int domain, int type, int protocol)
{
	if (domain == PF_UNIX && socket_errno.load() != 0) {
		errno = socket_errno.exchange(0);
		return (-1);
	}
	return (__real_socket(domain, type, protocol));
}

static std::atomic<int> device_fd{-1};
static std::mutex inject_mtx;
static std::deque<int> device_write_errors;
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" ssize_t
__wrap_write(int fd, const void *buf, size_t len)
{
	if (fd == device_fd.load()) {
		std::unique_lock lock(inject_mtx);
		if (!device_write_errors.empty()) {
			int e = device_write_errors.front();
			device_write_errors.pop_front();
			if (e == -1)
				return (__real_write(fd, buf, len / 2));
			if (e) {
				errno = e;
				return (-1);
			}
		}
	}
	return (__real_write(fd, buf, len));
}

/* ---- fixture ---- */
struct writer_fixture {
	temp_tree tree{"dtt-write"};
	std::unique_ptr<dir> inbound;
	int dev[2] = {-1, -1};
	int listener = -1;
	state s{};
	std::thread writer, reader;
	std::atomic<bool> writer_done{false};

	explicit writer_fixture(bool listen_socket = true)
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		inbound->state = &s;
		s.inbounddir = inbound.get();
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, dev) == 0);
		CHECK(fcntl(dev[0], F_SETFL, O_NONBLOCK) == 0);
		s.dtt_fd = dev[0];
		device_fd.store(dev[0]);
		CHECK(sem_init(&s.socksema, 0, 0) == 0);
		s.socksema_initialized = true;
		snprintf(redirect_path, sizeof(redirect_path), "%s/sub.sock", tree.path);
		if (listen_socket) {
			listener = socket(PF_UNIX, SOCK_STREAM, 0);
			CHECK(listener >= 0);
			struct sockaddr_un a{};
			a.sun_family = AF_UNIX;
			strlcpy(a.sun_path, redirect_path, sizeof(a.sun_path));
			CHECK(bind(listener, (struct sockaddr *)&a, sizeof(a)) == 0);
			CHECK(::listen(listener, 4) == 0);
		}
	}
	void start(bool with_reader = true, bool post = true)
	{
		if (post)
			CHECK(sem_post(&s.socksema) == 0);
		writer = std::thread([this] {
			write_dttransport(&s);
			writer_done.store(true);
		});
		if (with_reader)
			reader = std::thread(listen_dttransport, &s);
	}
	/* The daemon side of the control socket. */
	int accept_peer()
	{
		struct pollfd p = {listener, POLLIN, 0};
		CHECK(poll(&p, 1, 5000) == 1);
		int c = accept(listener, nullptr, nullptr);
		CHECK(c >= 0);
		return (c);
	}
	bool writer_stopped(int timeout_ms = 5000)
	{
		if (!eventually([&] { return writer_done.load(); }, timeout_ms))
			return (false);
		writer.join();
		return (true);
	}
	~writer_fixture()
	{
		s.shutdown.store(true);
		{
			std::lock_guard lock(s.host_elf_mtx);
			s.host_elf_cv.notify_all();
		}
		if (writer.joinable())
			writer.join();
		if (reader.joinable())
			reader.join();
		device_fd.store(-1);
		redirect_path[0] = '\0';
		if (listener >= 0)
			close(listener);
		close(dev[0]);
		close(dev[1]);
		sem_destroy(&s.socksema);
		s.socksema_initialized = false;
		s.inbounddir = nullptr;
	}
};

static void
send_all(int fd, const void *p, size_t n)
{
	size_t t = 0;
	CHECK(dtraced_io_transfer(fd, (void *)p, n, true,
	    dtraced_io_deadline_after(5000), &t) == 0 && t == n);
}

static void
recv_all(int fd, void *p, size_t n)
{
	size_t t = 0;
	CHECK(dtraced_io_transfer(fd, p, n, false,
	    dtraced_io_deadline_after(5000), &t) == 0 && t == n);
}

/* Daemon handshake: server hello, then the forwarder's own hello. */
static void
handshake(int c)
{
	dtd_initmsg_t hello{};
	hello.kind = DTRACED_KIND_DTRACED;
	hello.protocol_version = DTRACED_PROTOCOL_VERSION;
	size_t t;
	CHECK(dtraced_wire_write_init(c, &hello, dtraced_io_deadline_after(5000),
	    &t) == 0);
	dtd_initmsg_t client{};
	CHECK(dtraced_wire_read_init(c, &client, dtraced_io_deadline_after(5000),
	    &t) == 0);
	char expected[DTRACED_FDIDENTLEN] = {};
	snprintf(expected, sizeof(expected), "dtraced-dttransport-%d", getpid());
	const uint8_t zero[16] = {};
	CHECK(client.kind == DTRACED_KIND_FORWARDER &&
	    client.protocol_version == DTRACED_PROTOCOL_VERSION &&
	    client.subs == DTD_SUB_ELFWRITE &&
	    memcmp(client.ident, expected, sizeof(expected)) == 0 &&
	    memcmp(client.session_id, zero, 16) != 0);
}

static dtraced_hdr_t
elf_header(uint64_t delivery, size_t len)
{
	dtraced_hdr_t h{};
	h.msg_type = DTRACED_MSG_ELF;
	h.elf.len = len;
	h.elf.delivery_id = delivery;
	h.elf.program_id[0] = 0x71;
	h.elf.source_id[0] = 0x72;
	h.elf.vmid = 3;
	h.elf.epoch = 4;
	return (h);
}

static void
send_frame(int c, const dtraced_hdr_t &h, const std::vector<unsigned char> &body,
    size_t body_bytes = SIZE_MAX)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];
	dtraced_wire_encode_header(wire, &h);
	send_all(c, wire, sizeof(wire));
	if (!body.empty())
		send_all(c, body.data(), std::min(body_bytes, body.size()));
}

static std::vector<unsigned char>
payload(size_t n, unsigned char seed)
{
	std::vector<unsigned char> v(n);
	for (size_t i = 0; i < n; ++i)
		v[i] = (unsigned char)(seed ^ (i * 29));
	memcpy(v.data(), "\177ELF", 4);
	return (v);
}

/* Read DTT_ELF fragments until hasmore is clear; validate bookkeeping. */
static std::vector<unsigned char>
collect_elf(int dev, const dtraced_hdr_t &h)
{
	std::vector<unsigned char> out;
	uint32_t identifier = 0;
	for (;;) {
		dtt_entry_t e{};
		CHECK(peer_recv(dev, e));
		CHECK(e.event_kind == DTT_ELF);
		if (out.empty())
			identifier = e.u.elf.identifier;
		CHECK(e.u.elf.identifier == identifier &&
		    e.u.elf.delivery_id == h.elf.delivery_id &&
		    e.u.elf.vmid == h.elf.vmid && e.u.elf.epoch == h.elf.epoch &&
		    memcmp(e.u.elf.program_id, h.elf.program_id, 16) == 0 &&
		    memcmp(e.u.elf.source_id, h.elf.source_id, 16) == 0 &&
		    e.u.elf.totallen == h.elf.len && e.u.elf.len > 0 &&
		    e.u.elf.len <= DTT_MAXDATALEN);
		out.insert(out.end(), e.u.elf.data, e.u.elf.data + e.u.elf.len);
		CHECK(e.u.elf.hasmore == (out.size() < h.elf.len));
		if (!e.u.elf.hasmore)
			return (out);
	}
}

static dtt_entry_t
host_receipt(const dtraced_hdr_t &h, const std::vector<unsigned char> &body)
{
	dtt_entry_t r{};
	r.event_kind = DTT_HOST_ELF;
	r.u.installed.delivery_id = h.elf.delivery_id;
	r.u.installed.vmid = h.elf.vmid;
	r.u.installed.epoch = h.elf.epoch;
	memcpy(r.u.installed.program_id, h.elf.program_id, 16);
	memcpy(r.u.installed.source_id, h.elf.source_id, 16);
	SHA256(body.data(), body.size(), r.u.installed.digest);
	return (r);
}

static void
test_delivery()
{
	writer_fixture f;
	f.start();
	int c = f.accept_peer();
	handshake(c);
	for (size_t size : {(size_t)4, (size_t)DTT_MAXDATALEN,
	    (size_t)(3 * DTT_MAXDATALEN + 17)}) {
		dtraced_hdr_t h = elf_header(100 + size, size);
		auto body = payload(size, (unsigned char)size);
		send_frame(c, h, body);
		CHECK(collect_elf(f.dev[1], h) == body);
		{
			std::lock_guard lock(f.s.host_elf_mtx);
			uint8_t digest[32];
			SHA256(body.data(), body.size(), digest);
			CHECK(f.s.host_elf_waiting == h.elf.delivery_id &&
			    memcmp(f.s.host_elf_digest.data(), digest, 32) == 0);
		}
		/* No ACK before the host receipt. */
		CHECK(peer_quiet(c, 50));
		peer_send(f.dev[1], host_receipt(h, body));
		unsigned char ack[8];
		recv_all(c, ack, sizeof(ack));
		CHECK(dtraced_wire_get_u64(ack) == h.elf.delivery_id);
		std::lock_guard lock(f.s.host_elf_mtx);
		CHECK(f.s.host_elf_waiting == 0 && !f.s.host_elf_accepted);
	}
	/* The local daemon closes: the writer stops the guest daemon. */
	close(c);
	CHECK(f.writer_stopped());
	CHECK(f.s.shutdown.load());
}

static void
test_bad_frames()
{
	using edit_t = void (*)(dtraced_hdr_t &);
	const edit_t edits[] = {
		[](dtraced_hdr_t &h) { h.elf.delivery_id = 0; },
		[](dtraced_hdr_t &h) { h.elf.len = 3; },
		[](dtraced_hdr_t &h) { h.elf.len = HYPERTRACE_ELF_MAX + 1; },
		[](dtraced_hdr_t &h) { h.elf.filter_by_vmid = 1; },
		[](dtraced_hdr_t &h) { h.elf.vmid = 0; },
		[](dtraced_hdr_t &h) { h.elf.vmid = HYPERTRACE_MAX_VMS; },
		[](dtraced_hdr_t &h) { h.elf.epoch = 0; },
		[](dtraced_hdr_t &h) { h.elf.program_id[0] = 0; },
		[](dtraced_hdr_t &h) { h.elf.source_id[0] = 0; },
		[](dtraced_hdr_t &h) { h = {}; h.msg_type = DTRACED_MSG_KILL;
		    h.kill.pid = 5; h.kill.vmid = 1; h.kill.epoch = 1;
		    h.kill.source_id[0] = 1; },
	};
	for (edit_t edit : edits) {
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(9, 64);
		edit(h);
		send_frame(c, h, {});
		CHECK(f.writer_stopped());
		CHECK(f.s.shutdown.load() && peer_quiet(f.dev[1], 10));
		close(c);
	}
	{	/* undecodable header */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		unsigned char wire[DTRACED_MSGHDRSIZE] = {};
		wire[0] = 0xee;
		send_all(c, wire, sizeof(wire));
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		close(c);
	}
	{	/* truncated header */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		unsigned char wire[10] = {1};
		send_all(c, wire, sizeof(wire));
		close(c);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
	{	/* payload is not ELF; truncated payload */
		for (int variant = 0; variant < 2; ++variant) {
			writer_fixture f;
			f.start(false);
			int c = f.accept_peer();
			handshake(c);
			dtraced_hdr_t h = elf_header(9, 64);
			auto body = payload(64, 1);
			if (variant == 0)
				body[1] = 'X';
			send_frame(c, h, body, variant == 0 ? SIZE_MAX : 10);
			if (variant == 1)
				close(c);
			CHECK(f.writer_stopped() && f.s.shutdown.load());
			CHECK(peer_quiet(f.dev[1], 10));
			if (variant == 0)
				close(c);
		}
	}
	{	/* another sender already awaits a receipt */
		writer_fixture f;
		{
			std::lock_guard lock(f.s.host_elf_mtx);
			f.s.host_elf_waiting = 77;
		}
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		send_frame(c, elf_header(9, 64), payload(64, 2));
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		CHECK(peer_quiet(f.dev[1], 10));
		close(c);
	}
}

static void
test_device_faults()
{
	/* Transient device errors are retried; the whole record arrives. */
	{
		writer_fixture f;
		{
			std::lock_guard lock(inject_mtx);
			device_write_errors = {EINTR, EAGAIN, ENOBUFS};
		}
		f.start();
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(5, 100);
		auto body = payload(100, 3);
		send_frame(c, h, body);
		CHECK(collect_elf(f.dev[1], h) == body);
		peer_send(f.dev[1], host_receipt(h, body));
		unsigned char ack[8];
		recv_all(c, ack, sizeof(ack));
		CHECK(dtraced_wire_get_u64(ack) == 5);
		close(c);
		CHECK(f.writer_stopped());
	}
	/* A hard device error or a partial record stops the writer. */
	for (int e : {EIO, -1}) {
		writer_fixture f;
		{
			std::lock_guard lock(inject_mtx);
			device_write_errors = {e};
		}
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		send_frame(c, elf_header(5, 100), payload(100, 3));
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		CHECK(peer_eof(c));	/* no ACK */
		close(c);
	}
	/* Cleanup begins while the writer waits for a receipt: it exits
	 * without stopping the daemon (cleanup owns shutdown). */
	{
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(6, 64);
		auto body = payload(64, 4);
		send_frame(c, h, body);
		CHECK(collect_elf(f.dev[1], h) == body);
		f.s.cleanup_in_progress.store(true);
		{
			std::lock_guard lock(f.s.host_elf_mtx);
			f.s.host_elf_cv.notify_all();
		}
		CHECK(f.writer_stopped());
		CHECK(!f.s.shutdown.load() && peer_eof(c));
		close(c);
	}
	/* Daemon shutdown while the writer waits for the receipt. */
	{
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(7, 64);
		auto body = payload(64, 5);
		send_frame(c, h, body);
		CHECK(collect_elf(f.dev[1], h) == body);
		broadcast_shutdown(f.s);
		CHECK(f.writer_stopped());
		CHECK(peer_eof(c));
		close(c);
	}
	/* Shutdown already requested while device writes back off. */
	{
		writer_fixture f;
		{
			std::lock_guard lock(inject_mtx);
			device_write_errors.assign(400, EAGAIN);
		}
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		send_frame(c, elf_header(8, 64), payload(64, 6));
		std::this_thread::sleep_for(std::chrono::milliseconds(60));
		f.s.cleanup_in_progress.store(true);
		CHECK(f.writer_stopped());
		CHECK(!f.s.shutdown.load());
		close(c);
		std::lock_guard lock(inject_mtx);
		device_write_errors.clear();
	}
	/* The local daemon disappears before the ACK. */
	{
		writer_fixture f;
		f.start();
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(9, 64);
		auto body = payload(64, 7);
		send_frame(c, h, body);
		CHECK(collect_elf(f.dev[1], h) == body);
		close(c);
		peer_send(f.dev[1], host_receipt(h, body));
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
}

static void
test_connection_setup()
{
	{	/* socket creation fails */
		writer_fixture f;
		socket_errno.store(EMFILE);
		f.start(false);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
	{	/* no daemon socket */
		writer_fixture f(false);
		f.start(false);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
	{	/* socket thread never reports readiness; shutdown releases */
		writer_fixture f;
		f.start(false, false);
		CHECK(!f.writer_stopped(100));
		f.s.shutdown.store(true);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
	{	/* cleanup already running: setup failure does not broadcast */
		writer_fixture f(false);
		f.s.cleanup_in_progress.store(true);
		f.start(false);
		CHECK(f.writer_stopped() && !f.s.shutdown.load());
	}
	{	/* daemon closes before its hello */
		writer_fixture f;
		f.start(false);
		close(f.accept_peer());
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
	{	/* non-canonical server hello */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		dtd_initmsg_t hello{};
		hello.kind = DTRACED_KIND_DTRACED;
		hello.protocol_version = DTRACED_PROTOCOL_VERSION;
		hello.subs = 1;
		size_t t;
		CHECK(dtraced_wire_write_init(c, &hello,
		    dtraced_io_deadline_after(5000), &t) == 0);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		close(c);
	}
	{	/* daemon closes after its hello: our hello cannot be written */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		dtd_initmsg_t hello{};
		hello.kind = DTRACED_KIND_DTRACED;
		hello.protocol_version = DTRACED_PROTOCOL_VERSION;
		size_t t;
		CHECK(dtraced_wire_write_init(c, &hello,
		    dtraced_io_deadline_after(5000), &t) == 0);
		close(c);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
	}
}

int
main()
{
	alarm(240);
	signal(SIGPIPE, SIG_IGN);
	test_delivery();
	test_bad_frames();
	test_device_faults();
	test_connection_setup();
	printf("dtt-write: %u checks passed\n", harness_checks);
	return (0);
}
