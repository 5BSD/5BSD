/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Guest dttransport reader (listen_dttransport) driven through the actual
 * daemon objects. The transport is a socketpair standing in for
 * /dev/dttransport; only ioctl on that descriptor, execve (re-exec) and
 * clock failure are injected. Every case asserts the exact durable state,
 * the exact records written back to the transport, and whether the reader
 * shut the daemon down.
 *
 * Oracles: the inbound journal is read back through the public dir API and
 * the published artifact digest is compared with an independently computed
 * SHA-256 of the bytes the peer sent; observations written by the reader are
 * decoded field by field; protocol violations must stop the reader
 * (broadcast_shutdown) without publishing or acknowledging anything.
 */
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <array>
#include <cstdarg>
#include <memory>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

using namespace dtraced;
namespace dtraced {
struct state_attestation_test {
	static void set_control(state &s, int value = 1) { s.ctrlmachine = value; }
	static void set_argv(state &s, const char **argv) { s.argv = argv; }
};
}

/* ---- injected boundaries ---- */
static std::atomic<int> ioctl_fd{-1};
static dtt_vm_identity identity_reply{};
static dtt_cleanup_state cleanup_reply{};
static std::atomic<int> identity_errno{0}, cleanup_errno{0};
/* After the stop proof, report this identity (fresh prepare). */
static std::atomic<int> identity_calls{0};
static dtt_vm_identity identity_after{};
static std::atomic<int> identity_switch_after{-1};
static std::atomic<int> cleanup_calls{0};
static dtt_cleanup_state cleanup_after{};
static std::atomic<int> cleanup_switch_after{-1};
/* Fail exactly one cleanup-state query (by call index) with this errno. */
static std::atomic<int> cleanup_fail_at{-1}, cleanup_fail_errno{0};
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (fd != ioctl_fd.load())
		return (__real_ioctl(fd, request, arg));
	if (request == DTT_GET_VM_IDENTITY) {
		if (identity_errno.load()) {
			errno = identity_errno.load();
			return (-1);
		}
		int n = identity_calls.fetch_add(1);
		int sw = identity_switch_after.load();
		memcpy(arg, sw >= 0 && n >= sw ? &identity_after : &identity_reply,
		    sizeof(dtt_vm_identity));
		return (0);
	}
	if (request == DTT_GET_CLEANUP_STATE) {
		if (cleanup_errno.load()) {
			errno = cleanup_errno.load();
			return (-1);
		}
		int n = cleanup_calls.fetch_add(1);
		if (n == cleanup_fail_at.load()) {
			errno = cleanup_fail_errno.load();
			return (-1);
		}
		int sw = cleanup_switch_after.load();
		memcpy(arg, sw >= 0 && n >= sw ? &cleanup_after : &cleanup_reply,
		    sizeof(cleanup_reply));
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

/* re_exec: the reader replaced the daemon image. Only a forked child may
 * reach this; it flushes counters and exits with a recognizable status. */
static pid_t parent_pid;
static const char *exec_marker = "/nonexistent/dtraced-test-reexec";
extern "C" int
__wrap_execve(const char *path, char *const argv[], char *const envp[])
{
	(void)argv; (void)envp;
	if (getpid() == parent_pid || strcmp(path, exec_marker) != 0)
		abort();
	harness_flush_profile();
	_exit(73);
}

static std::atomic<int> clock_fail_after{-1};
static std::atomic<bool> clock_on_main{false};
static pthread_t main_thread;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	/* Faults target the reader (or requester) thread, never the main
	 * thread that plays the driver and polls for outcomes. */
	if (id == CLOCK_MONOTONIC && (clock_on_main.load() ==
	    (bool)pthread_equal(pthread_self(), main_thread))) {
		int left = clock_fail_after.load();
		if (left == 0) {
			errno = EIO;
			return (-1);
		}
		if (left > 0)
			clock_fail_after.fetch_sub(1);
	}
	return (__real_clock_gettime(id, ts));
}

/* ---- fixture ---- */
static const char *reexec_argv[] = {exec_marker, nullptr};

struct guest {
	temp_tree tree{"dtt-listen"};
	std::unique_ptr<dir> inbound, outbound;
	int fd[2] = {-1, -1};
	state s{};
	std::thread reader;
	std::atomic<bool> done{false};

	explicit guest(bool with_outbound = false, int type = SOCK_STREAM)
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		inbound->state = &s;
		s.inbounddir = inbound.get();
		if (with_outbound) {
			outbound = std::make_unique<dir>(tree.sub("outbound").c_str(),
			    nullptr);
			outbound->state = &s;
			s.outbounddir = outbound.get();
		}
		CHECK(socketpair(AF_UNIX, type, 0, fd) == 0);
		CHECK(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
		s.dtt_fd = fd[0];
		state_attestation_test::set_argv(s, reexec_argv);
		ioctl_fd.store(fd[0]);
	}
	void start()
	{
		reader = std::thread([this] {
			listen_dttransport(&s);
			done.store(true);
		});
	}
	/* The reader returned on its own and requested daemon shutdown. */
	bool stopped(int timeout_ms = 3000)
	{
		if (!eventually([&] { return done.load(); }, timeout_ms))
			return (false);
		reader.join();
		return (s.shutdown.load());
	}
	bool running(int window_ms = 60)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(window_ms));
		return (!done.load() && !s.shutdown.load());
	}
	~guest()
	{
		s.shutdown.store(true);
		if (reader.joinable())
			reader.join();
		ioctl_fd.store(-1);
		if (fd[0] >= 0) close(fd[0]);
		if (fd[1] >= 0) close(fd[1]);
		s.inbounddir = nullptr;
		s.outbounddir = nullptr;
	}
};

static std::vector<unsigned char>
elf_payload(size_t n, unsigned char seed)
{
	std::vector<unsigned char> v(n);
	for (size_t i = 0; i < n; ++i)
		v[i] = (unsigned char)(seed + i * 131);
	if (n >= 4)
		memcpy(v.data(), "\177ELF", 4);
	return (v);
}

struct elf_id {
	uint64_t delivery = 17;
	uint16_t vmid = 42;
	uint64_t epoch = 99;
	unsigned char program = 0x51;
	unsigned char source = 0x61;
};

static std::vector<dtt_entry_t>
fragments(const std::vector<unsigned char> &data, const elf_id &id,
    uint32_t identifier = 7)
{
	std::vector<dtt_entry_t> out;
	for (size_t off = 0; off < data.size(); off += DTT_MAXDATALEN) {
		dtt_entry_t e{};
		e.event_kind = DTT_ELF;
		size_t len = std::min(DTT_MAXDATALEN, data.size() - off);
		e.u.elf.len = len;
		e.u.elf.totallen = data.size();
		e.u.elf.identifier = identifier;
		e.u.elf.delivery_id = id.delivery;
		e.u.elf.vmid = id.vmid;
		e.u.elf.epoch = id.epoch;
		e.u.elf.program_id[0] = id.program;
		e.u.elf.source_id[0] = id.source;
		e.u.elf.hasmore = off + len < data.size();
		memcpy(e.u.elf.data, data.data() + off, len);
		out.push_back(e);
	}
	return (out);
}

static guest_delivery
delivery_of(const elf_id &id)
{
	guest_delivery d{};
	d.delivery_id = id.delivery;
	d.vmid = id.vmid;
	d.epoch = id.epoch;
	d.program_id[0] = id.program;
	d.source_id[0] = id.source;
	d.journal_version = 4;
	d.payload_digest[0] = 0xaa;	/* HTD4 records require a payload digest */
	return (d);
}

static bool
artifact_digest_is(dir &d, const elf_id &id, const std::vector<unsigned char> &data)
{
	uint8_t program[16] = {id.program}, source[16] = {id.source};
	uint8_t actual[32], expected[32];
	if (!d.hash_identified_data(program, source, actual))
		return (false);
	SHA256(data.data(), data.size(), expected);
	return (memcmp(actual, expected, 32) == 0);
}

static void
expect_uninstalled(int fd, const elf_id &id)
{
	dtt_entry_t e{};
	CHECK(peer_recv(fd, e));
	CHECK(e.event_kind == DTT_UNINSTALLED &&
	    e.u.installed.delivery_id == id.delivery &&
	    e.u.installed.vmid == id.vmid && e.u.installed.epoch == id.epoch &&
	    e.u.installed.program_id[0] == id.program &&
	    e.u.installed.source_id[0] == id.source);
}

/* ---- transport failures ---- */
static void
test_transport_failures()
{
	{	/* peer EOF */
		guest g;
		g.start();
		CHECK(g.running());
		close(g.fd[1]);
		g.fd[1] = -1;
		CHECK(g.stopped());
	}
	{	/* truncated record on a datagram transport */
		guest g(false, SOCK_DGRAM);
		g.start();
		char partial[17] = {DTT_KILL};
		CHECK(write(g.fd[1], partial, sizeof(partial)) == sizeof(partial));
		CHECK(g.stopped());
	}
	{	/* read error other than EWOULDBLOCK/EINTR */
		guest g;
		int writeonly = open("/dev/null", O_WRONLY);
		CHECK(writeonly >= 0);
		g.s.dtt_fd = writeonly;
		g.start();
		CHECK(g.stopped());
		close(writeonly);
	}
	{	/* unknown kinds and replies to nobody's query are ignored */
		guest g;
		g.start();
		dtt_entry_t e{};
		e.event_kind = 200;
		peer_send(g.fd[1], e);
		e = {};
		e.event_kind = DTT_VM_IDENTITY;
		e.u.installed.query_id = 5;
		peer_send(g.fd[1], e);
		e = {};
		e.event_kind = DTT_HOST_STATUS;
		e.u.installed.query_id = 5;
		peer_send(g.fd[1], e);
		CHECK(g.running(100));
		CHECK(peer_quiet(g.fd[1], 20));
	}
	{	/* monotonic clock failure inside the receive loop */
		guest g;
		clock_fail_after.store(3);
		g.start();
		CHECK(g.stopped());
		clock_fail_after.store(-1);
	}
	{	/* clock failure before the first outbound scan deadline */
		guest g;
		clock_fail_after.store(1);
		g.start();
		CHECK(g.stopped());
		clock_fail_after.store(-1);
	}
}

/* ---- guest ELF assembly and publication ---- */
static void
test_elf_publication()
{
	elf_id id;
	auto data = elf_payload(2 * DTT_MAXDATALEN + 100, 3);
	{
		guest g;
		g.start();
		for (const auto &e : fragments(data, id))
			peer_send(g.fd[1], e);
		guest_delivery d = delivery_of(id);
		SHA256(data.data(), data.size(), d.payload_digest.data());
		CHECK(eventually([&] {
			return g.inbound->delivery_status(guest_delivery_record(d)) ==
			    (int)delivery_phase::pending;
		}));
		CHECK(artifact_digest_is(*g.inbound, id, data));
		{
			std::lock_guard lock(g.s.deliverymtx);
			CHECK(g.s.guest_deliveries.size() == 1);
			const auto &rec = g.s.guest_deliveries[0];
			CHECK(rec.delivery_id == id.delivery && rec.authorized_current &&
			    rec.journal_version == 4 &&
			    rec.payload_digest == d.payload_digest);
		}
		/* Exact retry of the same token: no observation, no new record. */
		for (const auto &e : fragments(data, id, 8))
			peer_send(g.fd[1], e);
		CHECK(peer_quiet(g.fd[1], 100));
		{
			std::lock_guard lock(g.s.deliverymtx);
			CHECK(g.s.guest_deliveries.size() == 1);
		}
		/* A new token for an existing artifact cannot produce a fresh
		 * installation: the reader reports it uninstalled. */
		elf_id next = id;
		next.delivery = 18;
		for (const auto &e : fragments(data, next))
			peer_send(g.fd[1], e);
		expect_uninstalled(g.fd[1], next);
		CHECK(g.running());
		/* The same program from another source is a protocol violation. */
		elf_id other = id;
		other.delivery = 19;
		other.source = 0x62;
		for (const auto &e : fragments(data, other))
			peer_send(g.fd[1], e);
		CHECK(g.stopped());
		CHECK(peer_quiet(g.fd[1], 20));
	}
	/* Recovered (unauthorized) deliveries. */
	for (int variant = 0; variant < 3; ++variant) {
		guest g;
		guest_delivery d = delivery_of(id);
		SHA256(data.data(), data.size(), d.payload_digest.data());
		d.authorized_current = false;
		d.terminal_sent = variant == 0;
		g.s.guest_deliveries.push_back(d);
		g.start();
		/* A recovered identity is first queried, never executed. */
		dtt_entry_t query{};
		CHECK(peer_recv(g.fd[1], query));
		CHECK(query.event_kind == DTT_STATUS &&
		    query.u.installed.delivery_id == id.delivery &&
		    query.u.installed.query_id != 0);
		elf_id sent = id;
		if (variant == 2)
			sent.delivery = 30;	/* fresh token */
		for (const auto &e : fragments(data, sent))
			peer_send(g.fd[1], e);
		if (variant == 1) {
			/* exact retry still awaiting status: the bytes are
			 * republished, nothing is reported */
			CHECK(eventually([&] {
				return artifact_digest_is(*g.inbound, id, data); }));
			CHECK(peer_quiet(g.fd[1], 100));
		} else
			expect_uninstalled(g.fd[1], sent);
		CHECK(g.running());
		std::lock_guard lock(g.s.deliverymtx);
		CHECK(g.s.guest_deliveries.size() == 1 &&
		    !g.s.guest_deliveries[0].authorized_current &&
		    g.s.guest_deliveries[0].delivery_id == id.delivery);
	}
	/* Capacity: 16384 tracked deliveries refuse another program. */
	{
		guest g;
		for (unsigned i = 0; i < 16384; ++i) {
			guest_delivery d{};
			d.delivery_id = 1000 + i;
			d.vmid = 1;
			d.epoch = 1;
			d.program_id[1] = (uint8_t)i;
			d.program_id[2] = (uint8_t)(i >> 8);
			d.program_id[3] = 1;
			g.s.guest_deliveries.push_back(d);
		}
		g.start();
		for (const auto &e : fragments(data, id))
			peer_send(g.fd[1], e);
		CHECK(g.stopped());
		CHECK(g.s.guest_deliveries.size() == 16384);
	}
	/* Publication failure restores the in-memory ledger. */
	{
		guest g;
		std::string in = std::string(g.tree.path) + "/inbound";
		CHECK(chmod(in.c_str(), 0500) == 0);
		g.start();
		for (const auto &e : fragments(data, id))
			peer_send(g.fd[1], e);
		CHECK(g.stopped());
		CHECK(chmod(in.c_str(), 0700) == 0);
		CHECK(g.s.guest_deliveries.empty());
	}
}

static void
test_elf_rejections()
{
	elf_id id;
	auto data = elf_payload(DTT_MAXDATALEN + 10, 9);
	auto mutate_first = [&](auto edit) {
		guest g;
		g.start();
		auto frames = fragments(data, id);
		edit(frames[0]);
		peer_send(g.fd[1], frames[0]);
		CHECK(g.stopped());
		CHECK(g.s.guest_deliveries.empty());
		CHECK(peer_quiet(g.fd[1], 10));
	};
	mutate_first([](dtt_entry_t &e) { e.u.elf.len = DTT_MAXDATALEN + 1; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.program_id[0] = 0; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.source_id[0] = 0; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.delivery_id = 0; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.vmid = 0; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.vmid = HYPERTRACE_MAX_VMS; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.epoch = 0; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.hasmore = 2; });
	mutate_first([](dtt_entry_t &e) { e.u.elf.totallen = 0; });
	/* Second fragment disagrees with the first. */
	auto mutate_second = [&](auto edit) {
		guest g;
		g.start();
		auto frames = fragments(data, id);
		edit(frames[1]);
		peer_send(g.fd[1], frames[0]);
		peer_send(g.fd[1], frames[1]);
		CHECK(g.stopped());
		CHECK(g.s.guest_deliveries.empty());
	};
	mutate_second([](dtt_entry_t &e) { e.u.elf.delivery_id++; });
	mutate_second([](dtt_entry_t &e) { e.u.elf.vmid++; });
	mutate_second([](dtt_entry_t &e) { e.u.elf.epoch++; });
	mutate_second([](dtt_entry_t &e) { e.u.elf.program_id[0]++; });
	mutate_second([](dtt_entry_t &e) { e.u.elf.source_id[0]++; });
	mutate_second([](dtt_entry_t &e) { e.u.elf.identifier++; });
	/* Complete payload that is not an ELF image. */
	{
		guest g;
		g.start();
		auto bad = data;
		bad[0] = 'X';
		for (const auto &e : fragments(bad, id))
			peer_send(g.fd[1], e);
		CHECK(g.stopped());
	}
	{	/* shorter than an ELF magic */
		guest g;
		g.start();
		std::vector<unsigned char> tiny = {0x7f, 'E'};
		for (const auto &e : fragments(tiny, id))
			peer_send(g.fd[1], e);
		CHECK(g.stopped());
	}
}

/* ---- host ELF receipt ---- */
static void
test_host_elf()
{
	auto receipt = [] {
		dtt_entry_t e{};
		e.event_kind = DTT_HOST_ELF;
		e.u.installed.delivery_id = 5;
		e.u.installed.vmid = 3;
		e.u.installed.epoch = 4;
		e.u.installed.program_id[0] = 1;
		e.u.installed.source_id[0] = 2;
		e.u.installed.digest[0] = 9;
		return (e);
	};
	using edit_t = void (*)(dtt_entry_t &);
	const edit_t invalid[] = {
		[](dtt_entry_t &e) { e.u.installed.delivery_id = 0; },
		[](dtt_entry_t &e) { e.u.installed.vmid = 0; },
		[](dtt_entry_t &e) { e.u.installed.vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_entry_t &e) { e.u.installed.epoch = 0; },
		[](dtt_entry_t &e) { e.u.installed.program_id[0] = 0; },
		[](dtt_entry_t &e) { e.u.installed.source_id[0] = 0; },
		[](dtt_entry_t &e) { e.u.installed.phase = 'a'; },
		[](dtt_entry_t &e) { e.u.installed.revoked = 1; },
		[](dtt_entry_t &e) { e.u.installed.replay = 1; },
		[](dtt_entry_t &e) { e.u.installed.query_id = 1; },
		[](dtt_entry_t &e) { e.u.installed.digest[0] = 0; },
	};
	for (edit_t edit : invalid) {
		guest g;
		g.start();
		dtt_entry_t e = receipt();
		edit(e);
		peer_send(g.fd[1], e);
		CHECK(g.stopped());
	}
	{	/* late receipt for a sender nobody waits for */
		guest g;
		g.start();
		peer_send(g.fd[1], receipt());
		CHECK(g.running());
		std::lock_guard lock(g.s.host_elf_mtx);
		CHECK(!g.s.host_elf_accepted);
	}
	for (int mismatch = 0; mismatch < 4; ++mismatch) {
		guest g;
		{
			std::lock_guard lock(g.s.host_elf_mtx);
			g.s.host_elf_waiting = 5;
			g.s.host_elf_program[0] = 1;
			g.s.host_elf_source[0] = 2;
			g.s.host_elf_digest[0] = 9;
		}
		g.start();
		dtt_entry_t e = receipt();
		if (mismatch == 1) e.u.installed.program_id[0] = 7;
		if (mismatch == 2) e.u.installed.source_id[0] = 7;
		if (mismatch == 3) e.u.installed.digest[0] = 7;
		peer_send(g.fd[1], e);
		if (mismatch) {
			CHECK(g.stopped());
			std::lock_guard lock(g.s.host_elf_mtx);
			CHECK(!g.s.host_elf_accepted);
		} else {
			CHECK(eventually([&] {
				std::lock_guard lock(g.s.host_elf_mtx);
				return g.s.host_elf_accepted;
			}));
			CHECK(g.running());
		}
	}
}

/* ---- kills ---- */
static void
test_kills()
{
	auto kill_entry = [](uint8_t kind) {
		dtt_entry_t e{};
		e.event_kind = kind;
		e.u.kill.pid = 4321;
		e.u.kill.vmid = 42;
		e.u.kill.epoch = 99;
		e.u.kill.source_id[0] = 0x61;
		return (e);
	};
	using edit_t = void (*)(dtt_entry_t &);
	const edit_t invalid[] = {
		[](dtt_entry_t &e) { e.u.kill.pid = 1; },
		[](dtt_entry_t &e) { e.u.kill.vmid = 0; },
		[](dtt_entry_t &e) { e.u.kill.vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_entry_t &e) { e.u.kill.epoch = 0; },
		[](dtt_entry_t &e) { e.u.kill.source_id[0] = 0; },
	};
	for (uint8_t kind : {(uint8_t)DTT_KILL, (uint8_t)DTT_HOST_KILL_APPLIED})
		for (edit_t edit : invalid) {
			guest g;
			g.start();
			dtt_entry_t e = kill_entry(kind);
			edit(e);
			peer_send(g.fd[1], e);
			CHECK(g.stopped());
			std::vector<durable_kill> kills;
			CHECK(g.inbound->list_kills(kills) && kills.empty());
		}
	{	/* host observation for a source the guest never revoked */
		guest g;
		g.start();
		peer_send(g.fd[1], kill_entry(DTT_HOST_KILL_APPLIED));
		CHECK(g.stopped());
	}
	{	/* kill revokes deliveries: an idle one is reported terminal, an
		 * executing one keeps running until its child is reaped */
		guest g;
		elf_id idle, active;
		active.delivery = 18;
		active.program = 0x52;
		guest_delivery di = delivery_of(idle), da = delivery_of(active);
		g.s.guest_deliveries = {di, da};
		CHECK(g.inbound->record_delivery(guest_delivery_record(di),
		    delivery_phase::pending, true));
		g.s.pidlist.insert(777);
		g.s.pid_deliveries.emplace(777, da);
		g.start();
		peer_send(g.fd[1], kill_entry(DTT_KILL));
		expect_uninstalled(g.fd[1], idle);
		dtt_entry_t ack{};
		CHECK(peer_recv(g.fd[1], ack));
		CHECK(ack.event_kind == DTT_KILL_APPLIED && ack.u.kill.pid == 4321);
		CHECK(eventually([&] {
			std::lock_guard lock(g.s.killmtx);
			return !g.s.pids_to_kill.empty();
		}));
		{
			std::lock_guard lock(g.s.deliverymtx);
			CHECK(!g.s.guest_deliveries[0].authorized_current &&
			    g.s.guest_deliveries[0].terminal_sent);
			CHECK(!g.s.guest_deliveries[1].authorized_current &&
			    !g.s.guest_deliveries[1].terminal_sent);
		}
		CHECK(g.inbound->delivery_status(guest_delivery_record(di)) ==
		    (int)delivery_phase::exited);
		std::array<uint8_t, 16> src{};
		src[0] = 0x61;
		{
			std::lock_guard lock(g.s.pidlistmtx);
			CHECK(g.s.revoked_sources.count(src) == 1);
		}
		/* The ACK is retransmitted until the host confirms it. */
		CHECK(peer_recv(g.fd[1], ack, 2000) && ack.event_kind == DTT_KILL_APPLIED);
		dtt_entry_t confirm = kill_entry(DTT_HOST_KILL_APPLIED);
		peer_send(g.fd[1], confirm);
		durable_kill record{4321, 42, 99, src};
		CHECK(eventually([&] { return g.inbound->kill_applied(record) == 1; }));
		/* A duplicate confirmation is harmless. */
		peer_send(g.fd[1], confirm);
		CHECK(g.running());
		/* drain retransmissions sent before the confirmation */
		while (peer_recv(g.fd[1], ack, 300))
			CHECK(ack.event_kind == DTT_KILL_APPLIED);
	}
	{	/* recovery: kill journal without inbound tombstone is re-revoked
		 * and its pending ACK replayed after restart */
		temp_tree tree("dtt-kill-recovery");
		std::string path = tree.sub("inbound");
		durable_kill record{2222, 5, 6, {}};
		record.source_id[0] = 0x33;
		{
			dir d(path.c_str(), nullptr);
			CHECK(d.record_kill(record));
		}
		guest g;
		g.inbound = std::make_unique<dir>(path.c_str(), nullptr);
		g.inbound->state = &g.s;
		g.s.inbounddir = g.inbound.get();
		g.start();
		dtt_entry_t ack{};
		CHECK(peer_recv(g.fd[1], ack));
		CHECK(ack.event_kind == DTT_KILL_APPLIED && ack.u.kill.pid == 2222);
		CHECK(g.inbound->source_revoked(record.source_id.data()) == 1);
		g.s.shutdown.store(true);
		g.reader.join();
	}
	{	/* unreadable kill journal at startup */
		guest g;
		std::string in = std::string(g.tree.path) + "/inbound";
		CHECK(chmod(in.c_str(), 0300) == 0);
		g.start();
		CHECK(g.stopped());
		CHECK(chmod(in.c_str(), 0700) == 0);
	}
}

/* ---- VM identity queries ---- */
static void
test_vm_identity()
{
	auto reply_for = [](const dtt_entry_t &q) {
		dtt_entry_t r{};
		r.event_kind = DTT_VM_IDENTITY;
		r.u.installed.query_id = q.u.installed.query_id;
		r.u.installed.vmid = 12;
		r.u.installed.epoch = 34;
		return (r);
	};
	{
		guest g;
		g.start();
		uint16_t vmid = 0;
		uint64_t epoch = 0;
		std::atomic<int> result{-1};
		std::thread asker([&] {
			result.store(g.s.query_vm_identity(vmid, epoch) ? 1 : 0); });
		dtt_entry_t q{};
		CHECK(peer_recv(g.fd[1], q));
		CHECK(q.event_kind == DTT_VM_IDENTITY_QUERY && q.u.installed.query_id != 0);
		dtt_entry_t stale = reply_for(q);
		stale.u.installed.query_id ^= 1;	/* another query: ignored */
		peer_send(g.fd[1], stale);
		peer_send(g.fd[1], reply_for(q));
		asker.join();
		CHECK(result.load() == 1 && vmid == 12 && epoch == 34);
		CHECK(g.running());
	}
	using edit_t = void (*)(dtt_entry_t &);
	const edit_t invalid[] = {
		[](dtt_entry_t &e) { e.u.installed.delivery_id = 1; },
		[](dtt_entry_t &e) { e.u.installed.vmid = 0; },
		[](dtt_entry_t &e) { e.u.installed.vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_entry_t &e) { e.u.installed.epoch = 0; },
		[](dtt_entry_t &e) { e.u.installed.program_id[3] = 1; },
		[](dtt_entry_t &e) { e.u.installed.source_id[3] = 1; },
		[](dtt_entry_t &e) { e.u.installed.phase = 'a'; },
		[](dtt_entry_t &e) { e.u.installed.revoked = 1; },
		[](dtt_entry_t &e) { e.u.installed.replay = 1; },
		[](dtt_entry_t &e) { e.u.installed.digest[31] = 1; },
	};
	for (edit_t edit : invalid) {
		guest g;
		g.start();
		uint16_t vmid = 0;
		uint64_t epoch = 0;
		std::atomic<int> result{-1};
		std::atomic<int> saved{0};
		std::thread asker([&] {
			result.store(g.s.query_vm_identity(vmid, epoch) ? 1 : 0);
			saved.store(errno);
		});
		dtt_entry_t q{};
		CHECK(peer_recv(g.fd[1], q));
		dtt_entry_t r = reply_for(q);
		edit(r);
		peer_send(g.fd[1], r);
		CHECK(g.stopped());
		asker.join();
		CHECK(result.load() == 0 && saved.load() == ECANCELED && vmid == 0);
		std::lock_guard lock(g.s.vm_identity_mtx);
		CHECK(g.s.vm_identity_query_id == 0 && !g.s.vm_identity_ready);
	}
	{	/* argument and transport failures of the requester */
		state s{};
		uint16_t vmid;
		uint64_t epoch;
		s.dtt_fd = -1;
		errno = 0;
		CHECK(!s.query_vm_identity(vmid, epoch) && errno == EINVAL);
		state_attestation_test::set_control(s);
		s.dtt_fd = 3;
		errno = 0;
		CHECK(!s.query_vm_identity(vmid, epoch) && errno == EINVAL);
		state_attestation_test::set_control(s, 0);
		int sv[2];
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
		s.dtt_fd = sv[0];
		close(sv[1]);
		signal(SIGPIPE, SIG_IGN);
		errno = 0;
		CHECK(!s.query_vm_identity(vmid, epoch) && errno == EPIPE);
		s.shutdown.store(true);
		CHECK(!s.query_vm_identity(vmid, epoch) && errno == ECANCELED);
		close(sv[0]);
		clock_on_main.store(true);
		clock_fail_after.store(0);
		state t{};
		int tv[2];
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, tv) == 0);
		t.dtt_fd = tv[0];
		errno = 0;
		CHECK(!t.query_vm_identity(vmid, epoch) && errno == EIO);
		clock_fail_after.store(1);
		CHECK(!t.query_vm_identity(vmid, epoch) && errno == EIO);
		clock_fail_after.store(-1);
		clock_on_main.store(false);
		close(tv[0]);
		close(tv[1]);
	}
}

/* ---- cleanup, rekey and fresh-session stop (re-exec in a child) ---- */
static dtt_entry_t
cleanup_event(uint8_t kind)
{
	dtt_entry_t e{};
	e.event_kind = kind;
	e.u.cleanup.delivery_id = 8;
	e.u.cleanup.vmid = 42;
	e.u.cleanup.epoch = 99;
	return (e);
}

/* Runs the reader in a forked child; the parent plays the driver. */
template <class Peer>
static int
child_reader(Peer peer, bool with_outbound = false)
{
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	fflush(nullptr);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		close(sv[1]);
		guest g(with_outbound);
		close(g.fd[0]);
		close(g.fd[1]);
		g.fd[0] = sv[0];
		g.fd[1] = -1;
		CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
		g.s.dtt_fd = sv[0];
		ioctl_fd.store(sv[0]);
		listen_dttransport(&g.s);
		int code = g.s.shutdown.load() ? 0 : 1;
		harness_flush_profile();
		_exit(code);
	}
	close(sv[0]);
	peer(sv[1]);
	int status = 0;
	while (waitpid(pid, &status, 0) < 0)
		CHECK(errno == EINTR);
	close(sv[1]);
	return (status);
}

static void
set_identity(uint32_t flags, uint16_t vmid = 42, uint64_t epoch = 99,
    uint16_t old_vmid = 0, uint64_t old_epoch = 0)
{
	identity_reply = {};
	identity_reply.vmid = vmid;
	identity_reply.epoch = epoch;
	identity_reply.flags = flags;
	identity_reply.old_vmid = old_vmid;
	identity_reply.old_epoch = old_epoch;
	identity_switch_after.store(-1);
	identity_calls.store(0);
	identity_errno.store(0);
	cleanup_errno.store(0);
	cleanup_switch_after.store(-1);
	cleanup_calls.store(0);
	cleanup_fail_at.store(-1);
}

static void
test_reexec_paths()
{
	/* Driver rekey: drop volatile state and re-exec. */
	CHECK(exited_with(child_reader([](int fd) {
		peer_send(fd, cleanup_event(DTT_VM_REKEY));
	}), 73));
	/* Applied cleanup is reported before re-exec. */
	for (uint32_t flags : {0u, (uint32_t)DTT_IDENTITY_FRESH_ACTIVE}) {
		set_identity(flags);
		CHECK(exited_with(child_reader([](int fd) {
			peer_send(fd, cleanup_event(DTT_CLEANUP_DTRACED));
			dtt_entry_t applied{};
			CHECK(peer_recv(fd, applied));
			CHECK(applied.event_kind == DTT_CLEANUP_APPLIED &&
			    applied.u.cleanup.delivery_id == 8 &&
			    applied.u.cleanup.vmid == 42 &&
			    applied.u.cleanup.epoch == 99);
		}), 73));
	}
	/* Cleanup validation failures stop the reader without re-exec. */
	struct { void (*edit)(dtt_entry_t &); uint32_t flags; uint16_t vmid;
	    uint64_t epoch; int ioctl_error; } bad[] = {
		{[](dtt_entry_t &e) { e.u.cleanup.delivery_id = 0; }, 0, 42, 99, 0},
		{[](dtt_entry_t &e) { e.u.cleanup.vmid = 0; }, 0, 42, 99, 0},
		{[](dtt_entry_t &e) { e.u.cleanup.vmid = HYPERTRACE_MAX_VMS; }, 0, 42, 99, 0},
		{[](dtt_entry_t &e) { e.u.cleanup.epoch = 0; }, 0, 42, 99, 0},
		{nullptr, 0, 42, 99, ENXIO},
		{nullptr, DTT_IDENTITY_REKEY_PENDING, 42, 99, 0},
		{nullptr, 0, 43, 99, 0},
		{nullptr, 0, 42, 98, 0},
	};
	for (auto &c : bad) {
		set_identity(c.flags, c.vmid, c.epoch);
		identity_errno.store(c.ioctl_error);
		CHECK(exited_with(child_reader([&](int fd) {
			dtt_entry_t e = cleanup_event(DTT_CLEANUP_DTRACED);
			if (c.edit) c.edit(e);
			peer_send(fd, e);
			CHECK(peer_eof(fd));
		}), 0));
	}
	/* Applied report cannot be written (driver gone): no re-exec. */
	set_identity(0);
	CHECK(exited_with(child_reader([](int fd) {
		peer_send(fd, cleanup_event(DTT_CLEANUP_DTRACED));
		close(dup2(open("/dev/null", O_RDONLY), fd));
	}), 0));

	/* Fresh-session stop: exact proof, stopped report, wait for the new
	 * identity, then re-exec. */
	auto stop_state = [](uint16_t flags) {
		cleanup_reply = {};
		cleanup_reply.delivery_id = 8;
		cleanup_reply.vmid = 42;
		cleanup_reply.epoch = 99;
		cleanup_reply.flags = flags;
	};
	const uint16_t pending_stop = DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_SESSION_STOP;
	const uint16_t applied_stop = pending_stop | DTT_CLEANUP_STATE_APPLIED;
	for (uint32_t fresh : {(uint32_t)DTT_IDENTITY_FRESH_PENDING,
	    (uint32_t)DTT_IDENTITY_FRESH_READY}) {
		/* The driver marks the stop applied once STOPPED is accepted;
		 * the reader accepts either phase for the proof. */
		set_identity(0);
		stop_state(pending_stop);
		cleanup_after = cleanup_reply;
		cleanup_after.flags = applied_stop;
		cleanup_switch_after.store(1);
		identity_after = {};
		identity_after.vmid = 43;
		identity_after.epoch = 100;
		identity_after.old_vmid = 42;
		identity_after.old_epoch = 99;
		identity_after.flags = fresh;
		identity_switch_after.store(3);
		CHECK(exited_with(child_reader([&](int fd) {
			peer_send(fd, cleanup_event(DTT_SESSION_STOP));
			dtt_entry_t stopped{};
			CHECK(peer_recv(fd, stopped));
			CHECK(stopped.event_kind == DTT_SESSION_STOPPED &&
			    stopped.u.cleanup.delivery_id == 8 &&
			    stopped.u.cleanup.vmid == 42 &&
			    stopped.u.cleanup.epoch == 99);
		}), 73));
	}
	/* Stop accepted, but the guest identity changes in an unsafe way. */
	struct { uint32_t flags; uint16_t vmid; uint64_t epoch; uint16_t old_vmid;
	    uint64_t old_epoch; } unsafe[] = {
		{DTT_IDENTITY_FRESH_PENDING, 43, 100, 41, 99},
		{DTT_IDENTITY_FRESH_PENDING, 43, 100, 42, 98},
		{DTT_IDENTITY_FRESH_PENDING, 0, 100, 42, 99},
		{DTT_IDENTITY_FRESH_READY, 43, 99, 42, 99},
		{DTT_IDENTITY_REKEY_PENDING, 42, 99, 41, 9},
		{0, 44, 99, 0, 0},
	};
	for (auto &u : unsafe) {
		set_identity(0);
		stop_state(applied_stop);
		identity_after = {};
		identity_after.vmid = u.vmid;
		identity_after.epoch = u.epoch;
		identity_after.old_vmid = u.old_vmid;
		identity_after.old_epoch = u.old_epoch;
		identity_after.flags = u.flags;
		identity_switch_after.store(2);
		CHECK(exited_with(child_reader([](int fd) {
			peer_send(fd, cleanup_event(DTT_SESSION_STOP));
			dtt_entry_t stopped{};
			CHECK(peer_recv(fd, stopped) &&
			    stopped.event_kind == DTT_SESSION_STOPPED);
		}), 0));
	}
	/* Stop state no longer matches once the reader waits. */
	set_identity(0);
	stop_state(applied_stop);
	cleanup_after = cleanup_reply;
	cleanup_after.delivery_id = 9;	/* a different stop */
	cleanup_switch_after.store(2);
	CHECK(exited_with(child_reader([&](int fd) {
		peer_send(fd, cleanup_event(DTT_SESSION_STOP));
		dtt_entry_t stopped{};
		CHECK(peer_recv(fd, stopped) &&
		    stopped.event_kind == DTT_SESSION_STOPPED);
		CHECK(peer_eof(fd));
	}), 0));
	/* Cleanup-state query fails while waiting for the fresh identity: an
	 * interrupted query is retried, any other error stops the reader. */
	for (int error : {EINTR, EIO}) {
		set_identity(0);
		stop_state(applied_stop);
		identity_after = {};
		identity_after.vmid = 43;
		identity_after.epoch = 100;
		identity_after.old_vmid = 42;
		identity_after.old_epoch = 99;
		identity_after.flags = DTT_IDENTITY_FRESH_READY;
		identity_switch_after.store(1);
		cleanup_fail_at.store(1);
		cleanup_fail_errno.store(error);
		CHECK(exited_with(child_reader([&](int fd) {
			peer_send(fd, cleanup_event(DTT_SESSION_STOP));
			dtt_entry_t stopped{};
			CHECK(peer_recv(fd, stopped));
			if (error == EIO)
				CHECK(peer_eof(fd));
		}), error == EINTR ? 73 : 0));
	}
	cleanup_fail_at.store(-1);
	/* Stop validation failures: no stopped report. */
	struct { uint16_t flags; uint32_t reserved; uint64_t delivery; uint16_t vmid;
	    uint64_t epoch; uint32_t identity_flags; int cleanup_error;
	    void (*edit)(dtt_entry_t &); } invalid[] = {
		{0, 0, 8, 42, 99, 0, 0, nullptr},
		{DTT_CLEANUP_STATE_PENDING, 0, 8, 42, 99, 0, 0, nullptr},
		{pending_stop, 1, 8, 42, 99, 0, 0, nullptr},
		{pending_stop, 0, 9, 42, 99, 0, 0, nullptr},
		{pending_stop, 0, 8, 43, 99, 0, 0, nullptr},
		{pending_stop, 0, 8, 42, 98, 0, 0, nullptr},
		{pending_stop, 0, 8, 42, 99, DTT_IDENTITY_FRESH_PENDING, 0, nullptr},
		{pending_stop, 0, 8, 42, 99, 0, EIO, nullptr},
		{pending_stop, 0, 8, 42, 99, 0, 0,
		    [](dtt_entry_t &e) { e.u.cleanup.delivery_id = 0; }},
		{pending_stop, 0, 8, 42, 99, 0, 0,
		    [](dtt_entry_t &e) { e.u.cleanup.vmid = 0; }},
		{pending_stop, 0, 8, 42, 99, 0, 0,
		    [](dtt_entry_t &e) { e.u.cleanup.vmid = HYPERTRACE_MAX_VMS; }},
		{pending_stop, 0, 8, 42, 99, 0, 0,
		    [](dtt_entry_t &e) { e.u.cleanup.epoch = 0; }},
	};
	for (auto &c : invalid) {
		set_identity(c.identity_flags, 42, 99, c.identity_flags ? 41 : 0,
		    c.identity_flags ? 98 : 0);
		cleanup_reply = {};
		cleanup_reply.flags = c.flags;
		cleanup_reply.reserved = c.reserved;
		cleanup_reply.delivery_id = c.delivery;
		cleanup_reply.vmid = c.vmid;
		cleanup_reply.epoch = c.epoch;
		cleanup_errno.store(c.cleanup_error);
		CHECK(exited_with(child_reader([&](int fd) {
			dtt_entry_t e = cleanup_event(DTT_SESSION_STOP);
			if (c.edit) c.edit(e);
			peer_send(fd, e);
			CHECK(peer_eof(fd));
		}), 0));
	}
	cleanup_errno.store(0);
}

int
main()
{
	alarm(240);
	parent_pid = getpid();
	main_thread = pthread_self();
	signal(SIGPIPE, SIG_IGN);
	test_transport_failures();
	test_elf_publication();
	test_elf_rejections();
	test_host_elf();
	test_kills();
	test_vm_identity();
	test_reexec_paths();
	printf("dtt-listen: %u checks passed\n", harness_checks);
	return (0);
}
