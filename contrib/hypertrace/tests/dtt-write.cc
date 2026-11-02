/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Guest dttransport writer (write_dttransport and setup_connection) with
 * the actual daemon objects. The daemon's control socket path is redirected
 * by a connect() wrapper to a private listener; any other use of that path
 * fails, so the installed daemon is never contacted. The device is a
 * socketpair; listen_dttransport runs alongside so a DTT_HOST_ELF receipt
 * from the scripted driver releases the writer exactly as in production.
 *
 * Oracles: the driver accepts DTT_ELF fragments under bhyve's rules (the
 * shared hypertrace_elf_append() reassembly plus pci_virtio_dtrace.c's
 * delivery continuity; any violation would reset the real transport) and
 * compares the result byte for byte with the frame the local daemon sent,
 * checking identifiers, hasmore/len/totallen bookkeeping and the SHA-256 the
 * writer registers; the local daemon receives an 8-byte little-endian
 * delivery ACK only after the receipt. A malformed frame stops the writer
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
#include "dtraced_job.h"
#include "dtraced_connection.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"

using namespace dtraced;

namespace dtraced {
struct state_attestation_test {
	static bool handle(state &s, job *j) { return s.handle_job(j); }
};
}

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
/* Records the device still has room for; it then stays full (EAGAIN). */
static std::atomic<int> device_room{-1};
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
		if (device_room.load() == 0) {
			errno = EAGAIN;
			return (-1);
		}
		if (device_room.load() > 0)
			--device_room;
	}
	return (__real_write(fd, buf, len));
}

/*
 * bhyve's acceptance of guest ELF fragments (pci_vtdtr_control_rx(),
 * VTDTR_DEVICE_ELF): fragments reassemble through the same
 * hypertrace_elf_append() bhyve uses, which refuses another identifier or
 * total and enforces hasmore/length ordering, and while a partial ELF is held
 * only its own delivery (delivery_id, vmid, epoch, program and source) may
 * continue it.  Any refusal sets NEEDS_RESET there; here it marks the model
 * reset, which no test allows.
 */
struct bhyve_inbound {
	struct hypertrace_elf elf{};
	dtt_entry_t first{};
	bool reset = false;

	/* Accept one fragment; true when it completed an ELF into *out. */
	bool accept(const dtt_entry_t &e, std::vector<unsigned char> *out)
	{
		int complete, error;

		if (e.event_kind != DTT_ELF || e.u.elf.len > DTT_MAXDATALEN) {
			fail();
			return (false);
		}
		if (elf.data == nullptr)
			first = e;
		else if (e.u.elf.delivery_id != first.u.elf.delivery_id ||
		    e.u.elf.vmid != first.u.elf.vmid ||
		    e.u.elf.epoch != first.u.elf.epoch ||
		    memcmp(e.u.elf.program_id, first.u.elf.program_id, 16) != 0 ||
		    memcmp(e.u.elf.source_id, first.u.elf.source_id, 16) != 0) {
			fail();
			return (false);
		}
		error = hypertrace_elf_append(&elf, e.u.elf.identifier,
		    e.u.elf.totallen, e.u.elf.data, e.u.elf.len,
		    e.u.elf.hasmore, &complete);
		if (error != 0) {
			fail();
			return (false);
		}
		if (!complete)
			return (false);
		out->assign(elf.data, elf.data + elf.total);
		hypertrace_elf_reset(&elf);
		return (true);
	}
	void fail()
	{
		hypertrace_elf_reset(&elf);
		reset = true;
	}
	~bhyve_inbound() { hypertrace_elf_reset(&elf); }
};

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
		device_room.store(-1);
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

/* After a failed job the bridge registers again with a fresh session; the
 * guest daemon stays up and nothing reached the device. */
static void
expect_reregistered(writer_fixture &f)
{
	int c = f.accept_peer();
	handshake(c);
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	CHECK(peer_quiet(f.dev[1], 10));
	close(c);
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

/* Read DTT_ELF fragments until bhyve completes the ELF; validate them. */
static std::vector<unsigned char>
collect_elf(int dev, const dtraced_hdr_t &h)
{
	bhyve_inbound bhyve;
	std::vector<unsigned char> out;
	for (;;) {
		dtt_entry_t e{};
		CHECK(peer_recv(dev, e));
		CHECK(e.event_kind == DTT_ELF);
		CHECK(e.u.elf.delivery_id == h.elf.delivery_id &&
		    e.u.elf.vmid == h.elf.vmid && e.u.elf.epoch == h.elf.epoch &&
		    memcmp(e.u.elf.program_id, h.elf.program_id, 16) == 0 &&
		    memcmp(e.u.elf.source_id, h.elf.source_id, 16) == 0 &&
		    e.u.elf.totallen == h.elf.len && e.u.elf.len > 0 &&
		    e.u.elf.len <= DTT_MAXDATALEN);
		bool complete = bhyve.accept(e, &out);
		CHECK(!bhyve.reset);
		if (complete)
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
	/* The local daemon closes the bridge (a failed job): the writer
	 * re-registers instead of stopping the guest daemon. */
	close(c);
	c = f.accept_peer();
	handshake(c);
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	close(c);
}

/* Deliver one frame end to end over an established bridge connection. */
static void
deliver_one(writer_fixture &f, int c, uint64_t delivery, unsigned char seed)
{
	dtraced_hdr_t h = elf_header(delivery, 2 * DTT_MAXDATALEN + 9);
	auto body = payload(h.elf.len, seed);
	send_frame(c, h, body);
	CHECK(collect_elf(f.dev[1], h) == body);
	peer_send(f.dev[1], host_receipt(h, body));
	unsigned char ack[8];
	recv_all(c, ack, sizeof(ack));
	CHECK(dtraced_wire_get_u64(ack) == delivery);
}

/*
 * The real-host failure: the minion fails one job to the bridge and
 * state::kill_socket() closes the bridge connection before any header byte.
 * The bridge must log, re-register with a fresh session and deliver the next
 * job; the guest daemon stays up.  The same holds when the job fails while
 * a frame awaits the host receipt (the late receipt cannot be ACKed and
 * cannot hold the receipt slot against the next frame).
 */
static void
test_failed_job_recovers()
{
	writer_fixture f;
	f.start();
	int c = f.accept_peer();
	handshake(c);
	close(c);	/* failed job: kill_socket */
	c = f.accept_peer();
	handshake(c);
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	deliver_one(f, c, 41, 0x41);

	/* Failure while the frame awaits bhyve's receipt. */
	dtraced_hdr_t h = elf_header(42, 100);
	auto body = payload(100, 0x42);
	send_frame(c, h, body);
	CHECK(collect_elf(f.dev[1], h) == body);
	close(c);
	peer_send(f.dev[1], host_receipt(h, body));
	c = f.accept_peer();
	handshake(c);
	{
		std::lock_guard lock(f.s.host_elf_mtx);
		CHECK(f.s.host_elf_waiting == 0);
	}
	deliver_one(f, c, 43, 0x43);
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	close(c);
}

/*
 * Conditions a reconnect cannot repair still stop the guest daemon: the
 * dttransport device is gone, or this process no longer owns it.
 */
static void
test_bridge_fatal()
{
	for (int e : {ENXIO, EBUSY}) {
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
		CHECK(peer_eof(c));
		close(c);
		std::lock_guard lock(f.s.host_elf_mtx);
		CHECK(f.s.host_elf_waiting == 0);
	}
	/* A daemon that refuses every registration: bounded attempts. */
	{
		writer_fixture f;
		f.start(false);
		unsigned attempts = 0;
		while (!f.writer_done.load()) {
			struct pollfd p = {f.listener, POLLIN, 0};
			if (poll(&p, 1, 100) != 1)
				continue;
			int r = accept(f.listener, nullptr, nullptr);
			CHECK(r >= 0);
			close(r);
			++attempts;
		}
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		CHECK(attempts == 6);
	}
}

/*
 * The minion's durable outbound token survives the failed job.  The real
 * process_outbound()/queue_elfwrite_batch() journal the token and queue the
 * real job::send_elf() for the bridge; the daemon's end fails (the minion
 * then kills the socket).  The bridge re-registers, the token is still
 * pending, and the real queue_recovered_outbound() (the runtime outbound
 * scan's replay) sends the exact token over the new registration; the
 * bridge delivers it, ACKs, and the token is retired.
 */
static void
test_failed_job_token_replayed()
{
	writer_fixture f;
	std::string out_path = f.tree.sub("outbound");
	dir outbound(out_path.c_str(), &process_outbound);
	outbound.state = &f.s;
	f.s.outbounddir = &outbound;
	f.start();
	auto accept_bridge = [&f]() {
		int c = f.accept_peer();
		dtd_initmsg_t server{};
		server.kind = DTRACED_KIND_DTRACED;
		server.protocol_version = DTRACED_PROTOCOL_VERSION;
		size_t t;
		CHECK(dtraced_wire_write_init(c, &server,
		    dtraced_io_deadline_after(5000), &t) == 0);
		dtd_initmsg_t hello{};
		CHECK(dtraced_wire_read_init(c, &hello,
		    dtraced_io_deadline_after(5000), &t) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER);
		CHECK(fcntl(c, F_SETFL, O_NONBLOCK) == 0);
		return (std::make_pair(c, hello));
	};
	/* bhyve + guest driver as seen through /dev/dttransport. */
	std::atomic<bool> device_stop{false};
	std::mutex device_mtx;
	std::vector<unsigned char> uploaded;
	uint64_t uploaded_id = 0;
	std::atomic<bool> uploaded_done{false};
	std::thread device([&] {
		bhyve_inbound bhyve;
		std::vector<unsigned char> partial;
		while (!device_stop.load()) {
			dtt_entry_t e{};
			if (!peer_recv(f.dev[1], e, 100))
				continue;
			if (e.event_kind == DTT_VM_IDENTITY_QUERY) {
				dtt_entry_t r{};
				r.event_kind = DTT_VM_IDENTITY;
				r.u.installed.query_id = e.u.installed.query_id;
				r.u.installed.vmid = 3;
				r.u.installed.epoch = 4;
				peer_send(f.dev[1], r);
			} else if (e.event_kind == DTT_ELF) {
				if (!bhyve.accept(e, &partial)) {
					CHECK(!bhyve.reset);
					continue;
				}
				dtt_entry_t r{};
				r.event_kind = DTT_HOST_ELF;
				r.u.installed.delivery_id = e.u.elf.delivery_id;
				r.u.installed.vmid = e.u.elf.vmid;
				r.u.installed.epoch = e.u.elf.epoch;
				memcpy(r.u.installed.program_id, e.u.elf.program_id, 16);
				memcpy(r.u.installed.source_id, e.u.elf.source_id, 16);
				SHA256(partial.data(), partial.size(),
				    r.u.installed.digest);
				{
					std::lock_guard lock(device_mtx);
					uploaded.swap(partial);
					uploaded_id = e.u.elf.delivery_id;
				}
				partial.clear();
				uploaded_done.store(true);
				peer_send(f.dev[1], r);
			}
			/* Ingress status queries stay unanswered. */
		}
	});
	int kq = kqueue();
	CHECK(kq >= 0);
	const char *name = "elf.13000000000000000000000000000007."
	    "24000000000000000000000000000007";
	auto elf = payload(2 * DTT_MAXDATALEN + 11, 0x5a);
	{
		int fd = openat(outbound.dirfd, name, O_CREAT | O_EXCL | O_WRONLY,
		    0600);
		CHECK(fd >= 0 && write(fd, elf.data(), elf.size()) ==
		    (ssize_t)elf.size() && close(fd) == 0);
	}
	auto first = accept_bridge();
	{
		client_fd bridge(kq, first.first, first.second);
		CHECK(bridge.enable_write(&bridge));
		{
			std::lock_guard clients(f.s.sockfdsmtx);
			f.s.sockfds.insert(&bridge);
		}
		struct dirent file{};
		strlcpy(file.d_name, name, sizeof(file.d_name));
		file.d_namlen = strlen(name);
		file.d_type = DT_REG;
		CHECK(process_outbound(outbound, &file));
		job *pending = nullptr;
		{
			std::lock_guard jobs(f.s.joblistmtx);
			CHECK(f.s.joblist.size() == 1);
			pending = f.s.joblist.front();
			f.s.joblist.clear();
		}
		CHECK(pending->kind == NOTIFY_ELFWRITE &&
		    pending->connsockfd == &bridge);
		/* The job fails on this connection; the minion kills it. */
		CHECK(shutdown(first.first, SHUT_RDWR) == 0);
		CHECK(!pending->send_elf());
		delete pending;
		std::lock_guard clients(f.s.sockfdsmtx);
		f.s.sockfds.erase(&bridge);
	}	/* ~client_fd closes the socket, as kill_socket does */
	CHECK(!uploaded_done.load());

	/* The token of the failed job is recorded, not lost. */
	std::vector<durable_delivery_state> records;
	CHECK(outbound.list_deliveries(records));
	durable_delivery token{};
	unsigned pending_tokens = 0;
	for (const auto &entry : records)
		if (entry.record.scope == 2 &&
		    entry.phase == delivery_phase::pending) {
			token = entry.record;
			++pending_tokens;
		}
	CHECK(pending_tokens == 1);
	CHECK(outbound.delivery_status(token) == (int)delivery_phase::pending);

	/* The bridge re-registers instead of stopping the guest daemon. */
	auto second = accept_bridge();
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	CHECK(memcmp(second.second.session_id, first.second.session_id,
	    sizeof(first.second.session_id)) != 0);
	{
		client_fd bridge(kq, second.first, second.second);
		CHECK(bridge.enable_write(&bridge));
		{
			std::lock_guard clients(f.s.sockfdsmtx);
			f.s.sockfds.insert(&bridge);
		}
		CHECK(outbound.queue_recovered_outbound(token, 3, 4) == 1);
		job *replay = nullptr;
		{
			std::lock_guard jobs(f.s.joblistmtx);
			CHECK(f.s.joblist.size() == 1);
			replay = f.s.joblist.front();
			f.s.joblist.clear();
		}
		CHECK(replay->connsockfd == &bridge);
		CHECK(replay->send_elf());
		delete replay;
		{
			std::lock_guard lock(device_mtx);
			CHECK(uploaded_done.load() && uploaded == elf &&
			    uploaded_id == token.delivery_id);
		}
		CHECK(outbound.delivery_status(token) !=
		    (int)delivery_phase::pending);
		CHECK(!f.writer_done.load() && !f.s.shutdown.load());
		std::lock_guard clients(f.s.sockfdsmtx);
		f.s.sockfds.erase(&bridge);
	}
	device_stop.store(true);
	device.join();
	close(kq);
	f.s.outbounddir = nullptr;
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
	/* The local daemon is this binary: a malformed frame is a protocol
	 * violation that a reconnect would only repeat.  Nothing reaches the
	 * device and the guest daemon stops. */
	for (edit_t edit : edits) {
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		dtraced_hdr_t h = elf_header(9, 64);
		edit(h);
		send_frame(c, h, {});
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		CHECK(peer_eof(c) && peer_quiet(f.dev[1], 10));
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
		CHECK(peer_eof(c) && peer_quiet(f.dev[1], 10));
		close(c);
	}
	{	/* truncated header: the daemon closed the bridge */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		unsigned char wire[10] = {1};
		send_all(c, wire, sizeof(wire));
		close(c);
		expect_reregistered(f);
	}
	{	/* payload is not ELF: protocol violation */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		auto body = payload(64, 1);
		body[1] = 'X';
		send_frame(c, elf_header(9, 64), body);
		CHECK(f.writer_stopped() && f.s.shutdown.load());
		CHECK(peer_eof(c) && peer_quiet(f.dev[1], 10));
		close(c);
	}
	{	/* truncated payload: the daemon closed the bridge */
		writer_fixture f;
		f.start(false);
		int c = f.accept_peer();
		handshake(c);
		send_frame(c, elf_header(9, 64), payload(64, 1), 10);
		close(c);
		expect_reregistered(f);
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
		expect_reregistered(f);
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
		/* The ACK cannot be written: that job fails and the bridge
		 * re-registers; its token stays pending at the daemon. */
		expect_reregistered(f);
		std::lock_guard lock(f.s.host_elf_mtx);
		CHECK(f.s.host_elf_waiting == 0);
	}
}

/*
 * The device stays full after accepting the first fragment of a delivery.
 * bhyve now holds that partial ELF and accepts only its continuation, so
 * the bridge must not re-register: the daemon would replay the job as a new
 * transfer (another identifier) and bhyve would reset the transport.  The
 * bridge stops instead, past its 10 s device deadline.
 */
static void
test_device_full_mid_delivery()
{
	writer_fixture f;
	bhyve_inbound bhyve;
	std::vector<unsigned char> out;
	dtt_entry_t e{};

	device_room.store(1);
	f.start(false);
	int c = f.accept_peer();
	handshake(c);
	dtraced_hdr_t h = elf_header(10, 2 * DTT_MAXDATALEN + 9);
	auto body = payload(h.elf.len, 8);
	send_frame(c, h, body);
	CHECK(peer_recv(f.dev[1], e));
	CHECK(!bhyve.accept(e, &out) && !bhyve.reset);
	for (int waited = 0; waited < 15000 && !f.writer_done.load();
	    waited += 100) {
		struct pollfd p = {f.listener, POLLIN, 0};
		if (poll(&p, 1, 100) != 1)
			continue;
		/* Re-registered: the daemon replays the pending token. */
		int r = accept(f.listener, nullptr, nullptr);
		CHECK(r >= 0);
		handshake(r);
		device_room.store(-1);
		send_frame(r, h, body);
		CHECK(peer_recv(f.dev[1], e));
		(void)bhyve.accept(e, &out);
		CHECK(!bhyve.reset);
		close(r);
		break;
	}
	CHECK(f.writer_stopped() && f.s.shutdown.load());
	CHECK(peer_eof(c));
	close(c);
	std::lock_guard lock(f.s.host_elf_mtx);
	CHECK(f.s.host_elf_waiting == 0);
}

/*
 * A host that stalls for minutes fails every job the bridge forwards: the
 * frame gets no receipt, then the device stays full before the first
 * fragment, then the local daemon fails the replayed job (kill_socket) again
 * and again.  None of that stops the guest daemon; once the host drains, the
 * pending token is replayed and delivered.
 */
static void
test_host_stall_recovers()
{
	writer_fixture f;
	f.start();
	dtraced_hdr_t h = elf_header(60, 2 * DTT_MAXDATALEN + 9);
	auto body = payload(h.elf.len, 0x60);

	/* No receipt within 20 s. */
	int c = f.accept_peer();
	handshake(c);
	send_frame(c, h, body);
	CHECK(collect_elf(f.dev[1], h) == body);
	CHECK(peer_eof(c, 25000));
	close(c);

	/* The device stays full for the 10 s deadline at offset 0. */
	device_room.store(0);
	c = f.accept_peer();
	handshake(c);
	send_frame(c, h, body);
	CHECK(peer_eof(c, 15000));
	close(c);
	CHECK(peer_quiet(f.dev[1], 10));
	device_room.store(-1);

	/* Twice the sessions of the former idle bound, all failed jobs. */
	for (int i = 0; i < 12; ++i) {
		CHECK(!f.writer_done.load() && !f.s.shutdown.load());
		c = f.accept_peer();
		handshake(c);
		close(c);
	}

	/* The host drained: the replayed token is delivered. */
	c = f.accept_peer();
	handshake(c);
	deliver_one(f, c, 60, 0x60);
	CHECK(!f.writer_done.load() && !f.s.shutdown.load());
	close(c);
}

static void
test_connection_setup()
{
	{	/* socket creation fails once: the next attempt registers */
		writer_fixture f;
		socket_errno.store(EMFILE);
		f.start(false);
		expect_reregistered(f);
	}
	{	/* no daemon socket: bounded attempts, then a clean stop */
		writer_fixture f(false);
		f.start(false);
		CHECK(f.writer_stopped(10000) && f.s.shutdown.load());
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
		expect_reregistered(f);
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
		expect_reregistered(f);
	}
}

/*
 * The guest round trip with the real code on both sides of the local socket:
 * a derived ELF that guest dtrace stored in outbound is queued by the real
 * process_outbound()/queue_elfwrite_batch() and sent by the real minion
 * job::send_elf() to the real write_dttransport() bridge client. The scripted
 * device answers every DTT_VM_IDENTITY_QUERY (the queue-time and the send-time
 * query, through the real listen_dttransport() reader), reassembles the
 * bridge's DTT_ELF fragments and returns bhyve's DTT_HOST_ELF receipt.
 *
 * Oracles: the job succeeds (no "failed to handle job kind 1"), the bridge
 * never logs a header error or stops the daemon, the device receives the
 * spool bytes as a bare ELF with the minion's delivery/program/source IDs and
 * the attested VM identity, and the minion's durable outbound token is
 * accepted and retired after the bridge's ACK.
 */
static void
test_minion_round_trip()
{
	writer_fixture f;
	std::string out_path = f.tree.sub("outbound");
	dir outbound(out_path.c_str(), &process_outbound);
	outbound.state = &f.s;
	f.s.outbounddir = &outbound;
	f.start();
	int c = f.accept_peer();
	/* The minion's accept path: server hello, then the bridge's hello. */
	dtd_initmsg_t server{};
	server.kind = DTRACED_KIND_DTRACED;
	server.protocol_version = DTRACED_PROTOCOL_VERSION;
	size_t t;
	CHECK(dtraced_wire_write_init(c, &server,
	    dtraced_io_deadline_after(5000), &t) == 0);
	dtd_initmsg_t hello{};
	CHECK(dtraced_wire_read_init(c, &hello,
	    dtraced_io_deadline_after(5000), &t) == 0);
	CHECK(hello.kind == DTRACED_KIND_FORWARDER);
	CHECK(fcntl(c, F_SETFL, O_NONBLOCK) == 0);
	int kq = kqueue();
	CHECK(kq >= 0);
	{
		client_fd bridge(kq, c, hello);
		CHECK(bridge.enable_write(&bridge));
		{
			std::lock_guard clients(f.s.sockfdsmtx);
			f.s.sockfds.insert(&bridge);
		}
		/* bhyve + guest driver, as seen through /dev/dttransport. */
		std::atomic<bool> device_stop{false};
		std::atomic<unsigned> identity_queries{0};
		std::vector<unsigned char> uploaded;
		dtt_entry_t first{};
		std::atomic<bool> uploaded_done{false};
		std::thread device([&] {
			bhyve_inbound bhyve;
			while (!device_stop.load()) {
				dtt_entry_t e{};
				if (!peer_recv(f.dev[1], e, 100))
					continue;
				if (e.event_kind == DTT_VM_IDENTITY_QUERY) {
					dtt_entry_t r{};
					r.event_kind = DTT_VM_IDENTITY;
					r.u.installed.query_id = e.u.installed.query_id;
					r.u.installed.vmid = 3;
					r.u.installed.epoch = 4;
					identity_queries++;
					peer_send(f.dev[1], r);
				} else if (e.event_kind == DTT_ELF) {
					if (!bhyve.accept(e, &uploaded)) {
						CHECK(!bhyve.reset);
						continue;
					}
					first = bhyve.first;
					dtt_entry_t r{};
					r.event_kind = DTT_HOST_ELF;
					r.u.installed.delivery_id = e.u.elf.delivery_id;
					r.u.installed.vmid = e.u.elf.vmid;
					r.u.installed.epoch = e.u.elf.epoch;
					memcpy(r.u.installed.program_id,
					    e.u.elf.program_id, 16);
					memcpy(r.u.installed.source_id,
					    e.u.elf.source_id, 16);
					SHA256(uploaded.data(), uploaded.size(),
					    r.u.installed.digest);
					uploaded_done.store(true);
					peer_send(f.dev[1], r);
				}
				/* Ingress status queries stay unanswered. */
			}
		});
		/* Guest dtrace -Y's derived (linked) ELF in outbound. */
		const char *name = "elf.11000000000000000000000000000009."
		    "22000000000000000000000000000009";
		auto elf = payload(3 * DTT_MAXDATALEN + 5, 0x3c);
		{
			int fd = openat(outbound.dirfd, name,
			    O_CREAT | O_EXCL | O_WRONLY, 0600);
			CHECK(fd >= 0 && write(fd, elf.data(), elf.size()) ==
			    (ssize_t)elf.size() && close(fd) == 0);
		}
		struct dirent file{};
		strlcpy(file.d_name, name, sizeof(file.d_name));
		file.d_namlen = strlen(name);
		file.d_type = DT_REG;
		CHECK(process_outbound(outbound, &file));
		job *pending = nullptr;
		{
			std::lock_guard jobs(f.s.joblistmtx);
			CHECK(f.s.joblist.size() == 1);
			pending = f.s.joblist.front();
			f.s.joblist.clear();
		}
		CHECK(pending->kind == NOTIFY_ELFWRITE &&
		    pending->connsockfd == &bridge);
		errno = 0;
		bool handled = state_attestation_test::handle(f.s, pending);
		int error = errno;
		if (!handled) {
			fprintf(stderr, "minion: failed to handle job kind %d for "
			    "%s: %s\n", pending->kind, bridge.ident,
			    strerror(error));
			abort();
		}
		CHECK(uploaded_done.load() && uploaded == elf);
		/* Queue-time and send-time queries: each needs its own device credit. */
		CHECK(identity_queries.load() == 2);
		CHECK(first.u.elf.vmid == 3 && first.u.elf.epoch == 4 &&
		    first.u.elf.delivery_id != 0 &&
		    first.u.elf.program_id[0] == 0x11 &&
		    first.u.elf.program_id[15] == 0x09 &&
		    first.u.elf.source_id[0] == 0x22 &&
		    memcmp(uploaded.data(), "\177ELF", 4) == 0);
		CHECK(!f.s.shutdown.load() && !f.writer_done.load());
		{
			std::lock_guard lock(f.s.host_elf_mtx);
			CHECK(f.s.host_elf_waiting == 0);
		}
		durable_delivery record{};
		record.session_id = bridge.session_id;
		record.delivery_id = first.u.elf.delivery_id;
		record.vmid = 3;
		record.epoch = 4;
		memcpy(record.program_id.data(), first.u.elf.program_id, 16);
		memcpy(record.source_id.data(), first.u.elf.source_id, 16);
		record.peer_uid = (uint32_t)bridge.peer_uid;
		record.peer_pid = (uint32_t)bridge.peer_pid;
		record.scope = 2;
		record.journal_version = 4;
		SHA256(elf.data(), elf.size(), record.payload_digest.data());
		int phase = outbound.delivery_status(record);
		CHECK(phase != (int)delivery_phase::pending);
		delete pending;
		{
			std::lock_guard clients(f.s.sockfdsmtx);
			f.s.sockfds.clear();
		}
		device_stop.store(true);
		device.join();
	}
	close(kq);
	f.s.outbounddir = nullptr;
}

int
main()
{
	alarm(300);
	signal(SIGPIPE, SIG_IGN);
	test_delivery();
	test_bad_frames();
	test_failed_job_recovers();
	test_bridge_fatal();
	test_failed_job_token_replayed();
	test_device_faults();
	test_device_full_mid_delivery();
	test_host_stall_recovers();
	test_connection_setup();
	test_minion_round_trip();
	printf("dtt-write: %u checks passed\n", harness_checks);
	return (0);
}
