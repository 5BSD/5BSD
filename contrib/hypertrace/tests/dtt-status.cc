/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Recovered-delivery status, outbound ingest status and startup recovery in
 * the guest dttransport reader, with the actual daemon objects and real
 * journals. Time is advanced only for the reader thread (a monotonic skew)
 * so lost replies and rescans happen without real waits.
 *
 * Oracles: queries are decoded field by field against the journal record
 * they concern; each reply must leave the exact durable phase (read back via
 * dir::delivery_status) and the exact next transport record; protocol
 * violations must stop the reader without a further record.
 */
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <memory>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

using namespace dtraced;

static pthread_t main_thread;
static std::atomic<int64_t> skew_s{0};
static std::atomic<int> clock_fail_after{-1};
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	int r = __real_clock_gettime(id, ts);
	if (r == 0 && id == CLOCK_MONOTONIC &&
	    !pthread_equal(pthread_self(), main_thread)) {
		int left = clock_fail_after.load();
		if (left == 0) {
			errno = EIO;
			return (-1);
		}
		if (left > 0)
			clock_fail_after.fetch_sub(1);
		ts->tv_sec += skew_s.load();
	}
	return (r);
}

struct status_guest {
	temp_tree tree{"dtt-status"};
	std::unique_ptr<dir> inbound, outbound;
	int fd[2] = {-1, -1};
	state s{};
	std::thread reader;
	std::atomic<bool> done{false};
	status_guest()
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		outbound = std::make_unique<dir>(tree.sub("outbound").c_str(), nullptr);
		inbound->state = outbound->state = &s;
		s.inbounddir = inbound.get();
		s.outbounddir = outbound.get();
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
		CHECK(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
		s.dtt_fd = fd[0];
	}
	void start()
	{
		reader = std::thread([this] { listen_dttransport(&s); done.store(true); });
	}
	bool stopped(int timeout_ms = 4000)
	{
		if (!eventually([&] { return done.load(); }, timeout_ms))
			return (false);
		reader.join();
		return (s.shutdown.load());
	}
	bool running(int window_ms = 60)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(window_ms));
		return (!done.load());
	}
	~status_guest()
	{
		s.shutdown.store(true);
		if (reader.joinable())
			reader.join();
		close(fd[0]);
		if (fd[1] >= 0)
			close(fd[1]);
		s.inbounddir = nullptr;
		s.outbounddir = nullptr;
		skew_s.store(0);
		clock_fail_after.store(-1);
	}
};

/* ---- recovered inbound deliveries ---- */
static guest_delivery
recovered(status_guest &g, uint64_t id = 17, bool terminal_sent = false)
{
	guest_delivery d{};
	d.delivery_id = id;
	d.vmid = 42;
	d.epoch = 99;
	d.program_id[0] = (uint8_t)id;
	d.source_id[0] = 0x55;
	d.journal_version = 4;
	d.payload_digest[0] = 1;
	d.authorized_current = false;
	d.terminal_sent = terminal_sent;
	CHECK(g.inbound->record_delivery(guest_delivery_record(d),
	    delivery_phase::pending, true));
	g.s.guest_deliveries.push_back(d);
	return (d);
}

static dtt_entry_t
expect_query(int fd, const guest_delivery &d)
{
	dtt_entry_t q{};
	CHECK(peer_recv(fd, q));
	CHECK(q.event_kind == DTT_STATUS && q.u.installed.delivery_id == d.delivery_id &&
	    q.u.installed.vmid == d.vmid && q.u.installed.epoch == d.epoch &&
	    memcmp(q.u.installed.program_id, d.program_id.data(), 16) == 0 &&
	    memcmp(q.u.installed.source_id, d.source_id.data(), 16) == 0 &&
	    q.u.installed.query_id != 0);
	return (q);
}

static dtt_entry_t
status_reply(const dtt_entry_t &q, uint8_t phase)
{
	dtt_entry_t r = q;
	r.event_kind = DTT_HOST_STATUS;
	r.u.installed.phase = phase;
	return (r);
}

static void
test_host_status()
{
	/* Terminal answer retires the journal record and moves on to the next
	 * recovered delivery; an installed answer reports uninstallation. */
	{
		status_guest g;
		guest_delivery a = recovered(g, 17), b = recovered(g, 18);
		g.start();
		dtt_entry_t q = expect_query(g.fd[1], a);
		peer_send(g.fd[1], status_reply(q, 't'));
		q = expect_query(g.fd[1], b);
		CHECK(eventually([&] {
			return g.inbound->delivery_status(guest_delivery_record(a)) == 0; }));
		peer_send(g.fd[1], status_reply(q, 'i'));
		dtt_entry_t u{};
		CHECK(peer_recv(g.fd[1], u) && u.event_kind == DTT_UNINSTALLED &&
		    u.u.installed.delivery_id == b.delivery_id);
		CHECK(g.inbound->delivery_status(guest_delivery_record(b)) ==
		    (int)delivery_phase::exited);
		CHECK(g.running());
	}
	/* Unavailable host: retry after one second with a new query id; a lost
	 * reply is repeated when the 10 s status deadline passes. */
	{
		status_guest g;
		guest_delivery a = recovered(g);
		g.start();
		dtt_entry_t q = expect_query(g.fd[1], a);
		dtt_entry_t u = status_reply(q, 'u');
		peer_send(g.fd[1], u);
		skew_s.store(2);
		dtt_entry_t q2 = expect_query(g.fd[1], a);
		CHECK(q2.u.installed.query_id != q.u.installed.query_id);
		skew_s.store(14);
		dtt_entry_t q3 = expect_query(g.fd[1], a);
		CHECK(q3.u.installed.query_id != q2.u.installed.query_id);
		/* The stale reply cannot settle the newer query. */
		peer_send(g.fd[1], status_reply(q2, 't'));
		CHECK(g.running(100));
		CHECK(g.inbound->delivery_status(guest_delivery_record(a)) ==
		    (int)delivery_phase::pending);
		peer_send(g.fd[1], status_reply(q3, 't'));
		CHECK(eventually([&] {
			return g.inbound->delivery_status(guest_delivery_record(a)) == 0; }));
	}
	/* Malformed replies for the outstanding query stop the reader. */
	using edit_t = void (*)(dtt_entry_t &);
	const edit_t invalid[] = {
		[](dtt_entry_t &r) { r.u.installed.delivery_id++; },
		[](dtt_entry_t &r) { r.u.installed.vmid++; },
		[](dtt_entry_t &r) { r.u.installed.epoch++; },
		[](dtt_entry_t &r) { r.u.installed.program_id[0]++; },
		[](dtt_entry_t &r) { r.u.installed.source_id[0]++; },
		[](dtt_entry_t &r) { r.u.installed.phase = 'u'; r.u.installed.revoked = 1; },
		[](dtt_entry_t &r) { r.u.installed.phase = 'u'; r.u.installed.replay = 1; },
		[](dtt_entry_t &r) { r.u.installed.phase = 'u'; r.u.installed.digest[3] = 1; },
		/* accepted by the dispatcher, refused by handle_host_status */
		[](dtt_entry_t &r) { r.u.installed.phase = 'z'; },
		[](dtt_entry_t &r) { r.u.installed.phase = 0; r.u.installed.revoked = 0; },
	};
	for (edit_t edit : invalid) {
		status_guest g;
		guest_delivery a = recovered(g);
		g.start();
		dtt_entry_t r = status_reply(expect_query(g.fd[1], a), 't');
		edit(r);
		peer_send(g.fd[1], r);
		CHECK(g.stopped());
		CHECK(g.inbound->delivery_status(guest_delivery_record(a)) ==
		    (int)delivery_phase::pending);
	}
	/* Startup query cannot be written. */
	{
		status_guest g;
		recovered(g);
		close(g.fd[1]);
		g.fd[1] = -1;
		g.start();
		CHECK(g.stopped());
	}
	/* Repeat query cannot be written once the deadline passes. */
	{
		status_guest g;
		guest_delivery a = recovered(g);
		g.start();
		expect_query(g.fd[1], a);
		/* the reader can still read but no longer write */
		CHECK(shutdown(g.fd[0], SHUT_WR) == 0);
		skew_s.store(20);
		CHECK(g.stopped());
	}
	/* Retry after 'u' cannot be written. */
	{
		status_guest g;
		guest_delivery a = recovered(g);
		g.start();
		peer_send(g.fd[1], status_reply(expect_query(g.fd[1], a), 'u'));
		CHECK(g.running(50));
		CHECK(shutdown(g.fd[0], SHUT_WR) == 0);
		skew_s.store(2);
		CHECK(g.stopped());
	}
	/* Clock failure when scheduling the retry or the repeat. */
	for (int which = 0; which < 2; ++which) {
		status_guest g;
		guest_delivery a = recovered(g);
		g.start();
		dtt_entry_t q = expect_query(g.fd[1], a);
		if (which == 0) {
			clock_fail_after.store(0);
			peer_send(g.fd[1], status_reply(q, 'u'));
		} else {
			skew_s.store(20);
			clock_fail_after.store(1);
		}
		CHECK(g.stopped());
	}
}

/* ---- outbound ingest status ---- */
static durable_delivery
outbound_record(status_guest &g, uint64_t id, uint16_t vmid, bool spool = true,
    bool spool_matches = true)
{
	std::vector<unsigned char> elf = {0x7f, 'E', 'L', 'F', (unsigned char)id};
	durable_delivery r{};
	r.scope = 2;
	r.journal_version = 4;
	r.session_id[0] = (uint8_t)id;
	r.delivery_id = id;
	r.vmid = vmid;
	r.epoch = vmid ? 99 : 0;
	r.program_id[0] = (uint8_t)(0x80 + id);
	r.source_id[0] = (uint8_t)(0x40 + id);
	r.peer_pid = 100;
	SHA256(elf.data(), elf.size(), r.payload_digest.data());
	if (spool) {
		if (!spool_matches)
			elf.push_back(1);
		bool created;
		CHECK(g.outbound->write_identified_data(elf.data(), elf.size(),
		    r.program_id.data(), &created, r.source_id.data()));
	}
	CHECK(g.outbound->record_delivery(r, delivery_phase::pending, true));
	return (r);
}

static dtt_entry_t
expect_ingress_query(int fd, const durable_delivery &r)
{
	dtt_entry_t q{};
	CHECK(peer_recv(fd, q));
	CHECK(q.event_kind == DTT_INGRESS_STATUS &&
	    q.u.installed.delivery_id == r.delivery_id &&
	    memcmp(q.u.installed.program_id, r.program_id.data(), 16) == 0 &&
	    memcmp(q.u.installed.source_id, r.source_id.data(), 16) == 0 &&
	    q.u.installed.query_id != 0 && q.u.installed.vmid == 0);
	return (q);
}

/* The journal lists records in directory order; follow whichever comes. */
static dtt_entry_t
expect_ingress_either(int fd, durable_delivery &first, durable_delivery &second)
{
	dtt_entry_t q{};
	CHECK(peer_recv(fd, q));
	if (q.u.installed.delivery_id == second.delivery_id)
		std::swap(first, second);
	CHECK(q.event_kind == DTT_INGRESS_STATUS &&
	    q.u.installed.delivery_id == first.delivery_id &&
	    memcmp(q.u.installed.program_id, first.program_id.data(), 16) == 0 &&
	    q.u.installed.query_id != 0);
	return (q);
}

static dtt_entry_t
ingress_reply(const dtt_entry_t &q, const durable_delivery &r, uint8_t phase,
    uint16_t vmid = 42)
{
	dtt_entry_t e = q;
	e.event_kind = DTT_HOST_INGRESS_STATUS;
	e.u.installed.phase = phase;
	e.u.installed.vmid = vmid;
	e.u.installed.epoch = 99;
	if (phase == 'p' || phase == 'a')
		memcpy(e.u.installed.digest, r.payload_digest.data(), 32);
	return (e);
}

static void
test_ingress_status()
{
	/* accepted: journal records acceptance and retires; then next */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 1, 42), b = outbound_record(g, 2, 42);
		g.start();
		dtt_entry_t q = expect_ingress_either(g.fd[1], a, b);
		peer_send(g.fd[1], ingress_reply(q, a, 'a'));
		q = expect_ingress_query(g.fd[1], b);
		CHECK(eventually([&] { return g.outbound->delivery_status(a) == 0; }));
		/* a token from another VM incarnation keeps its fence */
		peer_send(g.fd[1], ingress_reply(q, b, 'p', 43));
		CHECK(g.running(100));
		CHECK(g.outbound->delivery_status(b) == (int)delivery_phase::pending);
		/* both visited: the reader waits for the next runtime scan, which
		 * revisits the remaining pending token only after 50 s */
		skew_s.store(3);
		CHECK(peer_quiet(g.fd[1], 100));
		skew_s.store(60);
		q = expect_ingress_query(g.fd[1], b);
		/* unavailable: retry after one second */
		peer_send(g.fd[1], ingress_reply(q, b, 'u'));
		skew_s.store(62);
		q = expect_ingress_query(g.fd[1], b);
		/* pending with spool present and no forwarder: retry later */
		peer_send(g.fd[1], ingress_reply(q, b, 'p'));
		skew_s.store(64);
		q = expect_ingress_query(g.fd[1], b);
		/* lost reply is repeated at the 10 s deadline */
		skew_s.store(80);
		q = expect_ingress_query(g.fd[1], b);
		/* absent answer for a VM-bound token behaves like pending */
		peer_send(g.fd[1], ingress_reply(q, b, 0));
		skew_s.store(82);
		q = expect_ingress_query(g.fd[1], b);
		CHECK(g.running());
	}
	/* Unbound token (vmid 0) with an absent answer: no replay, next. */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 3, 0);
		g.start();
		dtt_entry_t q = expect_ingress_query(g.fd[1], a);
		peer_send(g.fd[1], ingress_reply(q, a, 0));
		CHECK(g.running(100));
		CHECK(g.outbound->delivery_status(a) == (int)delivery_phase::pending);
	}
	/* Revoked source or missing spool: no replay, next. */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 4, 42);
		durable_delivery b = outbound_record(g, 5, 42, false);
		CHECK(g.outbound->revoke_source(a.source_id.data()));
		g.start();
		dtt_entry_t q = expect_ingress_either(g.fd[1], a, b);
		peer_send(g.fd[1], ingress_reply(q, a, 'p'));
		q = expect_ingress_query(g.fd[1], b);
		peer_send(g.fd[1], ingress_reply(q, b, 'p'));
		CHECK(g.running(100));
		/* host-revoked answer for a present spool: no replay either */
		status_guest h;
		durable_delivery c = outbound_record(h, 6, 42);
		h.start();
		q = expect_ingress_query(h.fd[1], c);
		dtt_entry_t r = ingress_reply(q, c, 'p');
		r.u.installed.revoked = 1;
		peer_send(h.fd[1], r);
		CHECK(h.running(100));
	}
	/* Local journal already accepted: retire without asking again. */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 7, 42);
		g.start();
		dtt_entry_t q = expect_ingress_query(g.fd[1], a);
		CHECK(g.outbound->record_delivery(a, delivery_phase::accepted));
		peer_send(g.fd[1], ingress_reply(q, a, 'p'));
		CHECK(eventually([&] { return g.outbound->delivery_status(a) == 0; }));
		CHECK(g.running());
	}
	/* Spool differs from the journal digest: fatal. */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 8, 42, true, false);
		g.start();
		dtt_entry_t q = expect_ingress_query(g.fd[1], a);
		peer_send(g.fd[1], ingress_reply(q, a, 'p'));
		CHECK(g.stopped());
	}
	/* Malformed ingest replies. */
	using edit_t = void (*)(dtt_entry_t &);
	const edit_t invalid[] = {
		[](dtt_entry_t &e) { e.u.installed.delivery_id++; },
		[](dtt_entry_t &e) { e.u.installed.vmid = 0; },
		[](dtt_entry_t &e) { e.u.installed.vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_entry_t &e) { e.u.installed.epoch = 0; },
		[](dtt_entry_t &e) { e.u.installed.program_id[0]++; },
		[](dtt_entry_t &e) { e.u.installed.source_id[0]++; },
		[](dtt_entry_t &e) { e.u.installed.phase = 'i'; },
		[](dtt_entry_t &e) { e.u.installed.revoked = 2; },
		[](dtt_entry_t &e) { e.u.installed.replay = 1; },
		[](dtt_entry_t &e) { e.u.installed.phase = 'u'; e.u.installed.revoked = 1;
		    memset(e.u.installed.digest, 0, 32); },
		[](dtt_entry_t &e) { e.u.installed.phase = 'u'; },
		[](dtt_entry_t &e) { e.u.installed.phase = 0; },
		[](dtt_entry_t &e) { e.u.installed.digest[0] ^= 1; },
	};
	for (edit_t edit : invalid) {
		status_guest g;
		durable_delivery a = outbound_record(g, 9, 42);
		g.start();
		dtt_entry_t e = ingress_reply(expect_ingress_query(g.fd[1], a), a, 'p');
		edit(e);
		peer_send(g.fd[1], e);
		CHECK(g.stopped());
		CHECK(g.outbound->delivery_status(a) == (int)delivery_phase::pending);
	}
	/* Replies for no query in flight are ignored. */
	{
		status_guest g;
		g.start();
		dtt_entry_t e{};
		e.event_kind = DTT_HOST_INGRESS_STATUS;
		e.u.installed.query_id = 3;
		peer_send(g.fd[1], e);
		CHECK(g.running(100));
	}
	/* The next query cannot be written. */
	{
		status_guest g;
		durable_delivery a = outbound_record(g, 10, 42);
		durable_delivery b = outbound_record(g, 11, 42);
		g.start();
		dtt_entry_t q = expect_ingress_either(g.fd[1], a, b);
		dtt_entry_t r = ingress_reply(q, a, 'a');
		CHECK(shutdown(g.fd[0], SHUT_WR) == 0);
		peer_send(g.fd[1], r);
		CHECK(g.stopped());
		CHECK(g.outbound->delivery_status(a) == 0);
	}
	/* Outbound journal unreadable at startup or at a runtime scan. */
	{
		status_guest g;
		std::string out = std::string(g.tree.path) + "/outbound";
		CHECK(chmod(out.c_str(), 0300) == 0);
		g.start();
		CHECK(g.stopped());
		CHECK(chmod(out.c_str(), 0700) == 0);
	}
	{
		status_guest g;
		g.start();
		CHECK(g.running(50));
		std::string out = std::string(g.tree.path) + "/outbound";
		CHECK(chmod(out.c_str(), 0300) == 0);
		skew_s.store(3);
		CHECK(g.stopped());
		CHECK(chmod(out.c_str(), 0700) == 0);
	}
}

/* ---- startup recovery and kill acknowledgement failures ---- */
static void
test_startup_failures()
{
	{	/* recovered kill whose source cannot be re-revoked */
		status_guest g;
		durable_kill k{3333, 42, 99, {}};
		k.source_id[0] = 0x77;
		CHECK(g.inbound->record_kill(k));
		std::string in = std::string(g.tree.path) + "/inbound";
		CHECK(chmod(in.c_str(), 0500) == 0);
		g.start();
		CHECK(g.stopped());
		CHECK(chmod(in.c_str(), 0700) == 0);
	}
	{	/* pending kill ACK cannot be written: the driver is gone */
		status_guest g;
		durable_kill k{3334, 42, 99, {}};
		k.source_id[0] = 0x78;
		CHECK(g.inbound->record_kill(k));
		close(g.fd[1]);
		g.fd[1] = -1;
		g.start();
		CHECK(g.stopped());
	}
	{	/* host confirmation cannot be persisted */
		status_guest g;
		durable_kill k{3335, 42, 99, {}};
		k.source_id[0] = 0x79;
		CHECK(g.inbound->record_kill(k));
		CHECK(g.inbound->revoke_source(k.source_id.data()));
		g.start();
		dtt_entry_t ack{};
		CHECK(peer_recv(g.fd[1], ack) && ack.event_kind == DTT_KILL_APPLIED);
		std::string in = std::string(g.tree.path) + "/inbound";
		CHECK(chmod(in.c_str(), 0500) == 0);
		ack.event_kind = DTT_HOST_KILL_APPLIED;
		peer_send(g.fd[1], ack);
		CHECK(g.stopped());
		CHECK(chmod(in.c_str(), 0700) == 0);
	}
	{	/* a duplicate guest KILL does not duplicate the pending ACK */
		status_guest g;
		g.start();
		dtt_entry_t kill{};
		kill.event_kind = DTT_KILL;
		kill.u.kill.pid = 3336;
		kill.u.kill.vmid = 42;
		kill.u.kill.epoch = 99;
		kill.u.kill.source_id[0] = 0x7a;
		peer_send(g.fd[1], kill);
		peer_send(g.fd[1], kill);
		dtt_entry_t ack{};
		CHECK(peer_recv(g.fd[1], ack) && ack.event_kind == DTT_KILL_APPLIED &&
		    ack.u.kill.pid == 3336);
		/* One confirmation retires the single pending ACK: a duplicated
		 * pending entry would keep retransmitting afterwards. */
		ack.event_kind = DTT_HOST_KILL_APPLIED;
		peer_send(g.fd[1], ack);
		durable_kill record{3336, 42, 99, {}};
		record.source_id[0] = 0x7a;
		CHECK(eventually([&] { return g.inbound->kill_applied(record) == 1; }));
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		dtt_entry_t late{};
		while (peer_recv(g.fd[1], late, 20))
			;	/* retransmissions already queued before the confirmation */
		CHECK(peer_quiet(g.fd[1], 350));
		g.s.shutdown.store(true);
	}
	{	/* kill journal unwritable: KILL cannot be recorded */
		status_guest g;
		std::string in = std::string(g.tree.path) + "/inbound";
		g.start();
		CHECK(g.running(30));
		CHECK(chmod(in.c_str(), 0500) == 0);
		dtt_entry_t kill{};
		kill.event_kind = DTT_KILL;
		kill.u.kill.pid = 3337;
		kill.u.kill.vmid = 42;
		kill.u.kill.epoch = 99;
		kill.u.kill.source_id[0] = 0x7b;
		peer_send(g.fd[1], kill);
		CHECK(g.stopped());
		CHECK(chmod(in.c_str(), 0700) == 0);
	}
	{	/* clock failure scheduling the next kill ACK */
		status_guest g;
		durable_kill k{3338, 42, 99, {}};
		k.source_id[0] = 0x7c;
		CHECK(g.inbound->record_kill(k));
		clock_fail_after.store(3);
		g.start();
		CHECK(g.stopped());
	}
	{	/* host lifecycle observation that does not match */
		status_guest g;
		g.start();
		dtt_entry_t e{};
		e.event_kind = DTT_HOST_INSTALLED;
		peer_send(g.fd[1], e);
		CHECK(g.stopped());
	}
}

int
main()
{
	alarm(240);
	main_thread = pthread_self();
	signal(SIGPIPE, SIG_IGN);
	test_host_status();
	test_ingress_status();
	test_startup_failures();
	printf("dtt-status: %u checks passed\n", harness_checks);
	return (0);
}
