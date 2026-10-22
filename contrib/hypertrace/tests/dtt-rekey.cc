/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Guest journal rekey through the actual daemon objects:
 * query_guest_rekey_receipt() and recover_guest_rekey() with real inbound
 * and outbound journals in a private directory tree. A responder thread plays
 * the dttransport driver on a socketpair; DTT_COMMIT_VM_REKEY and
 * DTT_GET_VM_IDENTITY on that descriptor are the only injected ioctls, and
 * write/read faults are injected only on that descriptor.
 *
 * Oracles: every query is decoded field by field against the journal record
 * it must prove; after success the journals are read back and must name only
 * the new incarnation with unchanged program/source/digest identities; after
 * a refused receipt they must still name only the old incarnation.
 */
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <cstdarg>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_io.h"
#include "dtraced_dttransport.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

using namespace dtraced;

/* ---- injected boundaries on the transport descriptor only ---- */
static std::atomic<int> transport_fd{-1};
static std::mutex inject_mtx;
static std::deque<int> write_errors;	/* errno per write; 0 = pass, -1 = short */
static std::deque<int> read_errors;
static std::atomic<int> commit_calls{0}, identity_calls{0};
static std::deque<int> commit_errors;	/* errno per COMMIT; 0 = success */
static std::function<void(dtt_vm_identity &, int)> identity_script;
static std::function<void(const dtt_vm_identity &)> commit_observer;

extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" ssize_t
__wrap_write(int fd, const void *buf, size_t len)
{
	if (fd == transport_fd.load()) {
		std::unique_lock lock(inject_mtx);
		if (!write_errors.empty()) {
			int e = write_errors.front();
			write_errors.pop_front();
			lock.unlock();
			if (e == -1)
				return (__real_write(fd, buf, len / 2));
			if (e != 0) {
				errno = e;
				return (-1);
			}
		}
	}
	return (__real_write(fd, buf, len));
}

extern "C" ssize_t __real_read(int, void *, size_t);
extern "C" ssize_t
__wrap_read(int fd, void *buf, size_t len)
{
	if (fd == transport_fd.load()) {
		std::unique_lock lock(inject_mtx);
		if (!read_errors.empty()) {
			int e = read_errors.front();
			read_errors.pop_front();
			if (e != 0) {
				errno = e;
				return (-1);
			}
		}
	}
	return (__real_read(fd, buf, len));
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (fd != transport_fd.load())
		return (__real_ioctl(fd, request, arg));
	std::unique_lock lock(inject_mtx);
	if (request == DTT_COMMIT_VM_REKEY) {
		commit_calls.fetch_add(1);
		int e = 0;
		if (!commit_errors.empty()) {
			e = commit_errors.front();
			commit_errors.pop_front();
		}
		if (commit_observer)
			commit_observer(*(dtt_vm_identity *)arg);
		if (e) {
			errno = e;
			return (-1);
		}
		return (0);
	}
	if (request == DTT_GET_VM_IDENTITY) {
		int n = identity_calls.fetch_add(1);
		dtt_vm_identity id{};
		identity_script(id, n);
		if (id.flags == 0xffffffffu) {
			errno = id.vmid;	/* scripted failure */
			return (-1);
		}
		memcpy(arg, &id, sizeof(id));
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

static std::atomic<int> clock_fail_after{-1};
static std::atomic<int64_t> clock_skew_ms{0};
static std::atomic<int> clock_skew_at{0};	/* jump 60 s at this call */
static pthread_t main_thread;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	int r = __real_clock_gettime(id, ts);
	/* Only the thread under test sees injected clock faults; the driver
	 * thread and runtime threads keep the real clock. */
	if (id == CLOCK_MONOTONIC && r == 0 && pthread_equal(pthread_self(),
	    main_thread)) {
		int left = clock_fail_after.load();
		if (left == 0) {
			errno = EIO;
			return (-1);
		}
		if (left > 0)
			clock_fail_after.fetch_sub(1);
		int at = clock_skew_at.load();
		if (at > 0 && clock_skew_at.fetch_sub(1) == 1)
			clock_skew_ms.store(60000);
		int64_t skew = clock_skew_ms.load();
		ts->tv_sec += skew / 1000;
	}
	return (r);
}

static void
reset_injection()
{
	std::lock_guard lock(inject_mtx);
	write_errors.clear();
	read_errors.clear();
	commit_errors.clear();
	commit_calls.store(0);
	identity_calls.store(0);
	commit_observer = nullptr;
	clock_fail_after.store(-1);
	clock_skew_ms.store(0);
	clock_skew_at.store(0);
}

/* ---- a scripted driver on the far end of the transport ---- */
using reply_fn = std::function<std::vector<dtt_entry_t>(const dtt_entry_t &)>;

struct driver {
	int fd[2] = {-1, -1};
	std::thread thread;
	std::atomic<bool> stop{false};
	std::mutex mtx;
	std::vector<dtt_entry_t> queries;
	reply_fn reply;
	explicit driver(reply_fn r) : reply(std::move(r))
	{
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
		CHECK(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
		transport_fd.store(fd[0]);
	}
	void preload(const dtt_entry_t &e) { peer_send(fd[1], e); }
	void start()
	{
		thread = std::thread([this] {
			while (!stop.load()) {
				dtt_entry_t q{};
				if (!peer_recv(fd[1], q, 50))
					continue;
				{
					std::lock_guard lock(mtx);
					queries.push_back(q);
				}
				for (const auto &r : reply(q))
					peer_send(fd[1], r);
			}
		});
	}
	~driver()
	{
		stop.store(true);
		if (thread.joinable())
			thread.join();
		transport_fd.store(-1);
		close(fd[0]);
		close(fd[1]);
	}
};

static uint8_t
receipt_kind(uint8_t query)
{
	return (query == DTT_REKEY_DELIVERY_QUERY ? DTT_REKEY_DELIVERY_RECEIPT :
	    query == DTT_REKEY_INGRESS_QUERY ? DTT_REKEY_INGRESS_RECEIPT :
	    DTT_REKEY_KILL_RECEIPT);
}

/* The receipt a correct driver returns for an applied/installed record. */
static dtt_entry_t
good_receipt(const dtt_entry_t &q)
{
	dtt_entry_t r = q;
	r.event_kind = receipt_kind(q.event_kind);
	if (q.event_kind == DTT_REKEY_KILL_QUERY) {
		r.u.installed.phase = 'a';
		r.u.installed.revoked = 1;
	} else
		r.u.installed.phase = 'a';
	return (r);
}

/* ---- query_guest_rekey_receipt ---- */
struct receipt_args {
	uint8_t kind = DTT_REKEY_DELIVERY_QUERY;
	uint16_t old_vmid = 4, new_vmid = 5;
	uint64_t old_epoch = 6, new_epoch = 7;
	uint64_t delivery = 9;
	uint8_t program[16] = {1}, source[16] = {2}, digest[32] = {3};
	bool terminal_ok = false;
};

static bool
call(int fd, const receipt_args &a, int64_t deadline_ms = 3000)
{
	return (query_guest_rekey_receipt(fd, a.kind, a.old_vmid, a.old_epoch,
	    a.new_vmid, a.new_epoch, a.delivery, a.program, a.source, a.digest,
	    a.terminal_ok, dtraced_io_deadline_after(deadline_ms)));
}

static void
test_receipt_arguments()
{
	using edit_t = void (*)(receipt_args &);
	const edit_t invalid[] = {
		[](receipt_args &a) { a.kind = DTT_REKEY_DELIVERY_RECEIPT; },
		[](receipt_args &a) { a.old_vmid = 0; },
		[](receipt_args &a) { a.old_vmid = HYPERTRACE_MAX_VMS; },
		[](receipt_args &a) { a.terminal_ok = true; a.kind = DTT_REKEY_INGRESS_QUERY; },
		[](receipt_args &a) { a.old_epoch = 0; },
		[](receipt_args &a) { a.new_vmid = 0; },
		[](receipt_args &a) { a.new_vmid = HYPERTRACE_MAX_VMS; },
		[](receipt_args &a) { a.new_epoch = 0; },
		[](receipt_args &a) { a.new_vmid = a.old_vmid; a.new_epoch = a.old_epoch; },
		[](receipt_args &a) { a.delivery = 0; },
		[](receipt_args &a) { a.source[0] = 0; },
		[](receipt_args &a) { a.program[0] = 0; },
		[](receipt_args &a) { a.digest[0] = 0; },
		/* kill receipts carry a pid and no program or digest */
		[](receipt_args &a) { a.kind = DTT_REKEY_KILL_QUERY; a.program[0] = 0;
		    a.digest[0] = 0; a.delivery = 1; },
		[](receipt_args &a) { a.kind = DTT_REKEY_KILL_QUERY; a.program[0] = 0;
		    a.digest[0] = 0; a.delivery = (uint64_t)INT32_MAX + 1; },
		[](receipt_args &a) { a.kind = DTT_REKEY_KILL_QUERY; a.digest[0] = 0; },
		[](receipt_args &a) { a.kind = DTT_REKEY_KILL_QUERY; a.program[0] = 0; },
	};
	driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
	for (edit_t edit : invalid) {
		receipt_args a;
		edit(a);
		errno = 0;
		CHECK(!call(d.fd[0], a) && errno == EINVAL);
	}
	receipt_args a;
	CHECK(!query_guest_rekey_receipt(-1, a.kind, a.old_vmid, a.old_epoch,
	    a.new_vmid, a.new_epoch, a.delivery, a.program, a.source, a.digest,
	    false, dtraced_io_deadline_after(100)) && errno == EINVAL);
	CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid, a.old_epoch,
	    a.new_vmid, a.new_epoch, a.delivery, nullptr, a.source, a.digest,
	    false, dtraced_io_deadline_after(100)) && errno == EINVAL);
	CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid, a.old_epoch,
	    a.new_vmid, a.new_epoch, a.delivery, a.program, nullptr, a.digest,
	    false, dtraced_io_deadline_after(100)) && errno == EINVAL);
	CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid, a.old_epoch,
	    a.new_vmid, a.new_epoch, a.delivery, a.program, a.source, nullptr,
	    false, dtraced_io_deadline_after(100)) && errno == EINVAL);
	CHECK(peer_quiet(d.fd[1], 10));	/* no query was written */
}

static void
test_receipt_replies()
{
	/* Each case: arguments, reply builder, expected success and errno. */
	struct rcase {
		const char *name;
		void (*setup)(receipt_args &);
		std::function<std::vector<dtt_entry_t>(const dtt_entry_t &)> reply;
		bool ok;
		int error;
	};
	auto one = [](std::function<void(dtt_entry_t &)> edit) {
		return [edit](const dtt_entry_t &q) {
			dtt_entry_t r = good_receipt(q);
			edit(r);
			return std::vector<dtt_entry_t>{r};
		};
	};
	auto noop = [](receipt_args &) {};
	auto kill = [](receipt_args &a) {
		a.kind = DTT_REKEY_KILL_QUERY;
		memset(a.program, 0, 16);
		memset(a.digest, 0, 32);
		a.delivery = 1234;
	};
	auto ingress = [](receipt_args &a) { a.kind = DTT_REKEY_INGRESS_QUERY; };
	auto terminal = [](receipt_args &a) { a.terminal_ok = true; };
	std::vector<rcase> cases = {
		{"delivery applied", noop, one([](dtt_entry_t &) {}), true, 0},
		{"delivery installed", noop, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'i'; }), true, 0},
		{"delivery pending refused", noop, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'p'; }), false, EPROTO},
		{"delivery revoked refused", noop, one([](dtt_entry_t &r) {
			r.u.installed.revoked = 1; }), false, EPROTO},
		{"delivery digest mismatch", noop, one([](dtt_entry_t &r) {
			r.u.installed.digest[0] ^= 1; }), false, EPROTO},
		{"ingress accepted", ingress, one([](dtt_entry_t &) {}), true, 0},
		{"ingress installed refused", ingress, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'i'; }), false, EPROTO},
		{"kill applied", kill, one([](dtt_entry_t &) {}), true, 0},
		{"kill pending", kill, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'p'; }), true, 0},
		{"kill not revoked", kill, one([](dtt_entry_t &r) {
			r.u.installed.revoked = 0; }), false, EPROTO},
		{"kill with digest", kill, one([](dtt_entry_t &r) {
			r.u.installed.digest[5] = 1; }), false, EPROTO},
		{"kill wrong phase", kill, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'i'; }), false, EPROTO},
		{"unavailable", noop, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'u'; memset(r.u.installed.digest, 0, 32); }),
		    false, EAGAIN},
		{"unavailable with digest", noop, one([](dtt_entry_t &r) {
			r.u.installed.phase = 'u'; }), false, EPROTO},
		{"terminal accepted", terminal, one([](dtt_entry_t &r) {
			r.u.installed.phase = 't'; memset(r.u.installed.digest, 0, 32); }),
		    true, 0},
		{"terminal revoked", terminal, one([](dtt_entry_t &r) {
			r.u.installed.phase = 't'; r.u.installed.revoked = 1;
			memset(r.u.installed.digest, 0, 32); }), true, 0},
		{"terminal not allowed", noop, one([](dtt_entry_t &r) {
			r.u.installed.phase = 't'; memset(r.u.installed.digest, 0, 32); }),
		    false, EPROTO},
		{"terminal bad revoked", terminal, one([](dtt_entry_t &r) {
			r.u.installed.phase = 't'; r.u.installed.revoked = 2;
			memset(r.u.installed.digest, 0, 32); }), false, EPROTO},
		{"terminal with digest", terminal, one([](dtt_entry_t &r) {
			r.u.installed.phase = 't'; }), false, EPROTO},
		{"wrong kind", noop, one([](dtt_entry_t &r) {
			r.event_kind = DTT_REKEY_KILL_RECEIPT; }), false, EPROTO},
		{"wrong delivery", noop, one([](dtt_entry_t &r) {
			r.u.installed.delivery_id++; }), false, EPROTO},
		{"wrong vmid", noop, one([](dtt_entry_t &r) {
			r.u.installed.vmid++; }), false, EPROTO},
		{"wrong epoch", noop, one([](dtt_entry_t &r) {
			r.u.installed.epoch++; }), false, EPROTO},
		{"wrong program", noop, one([](dtt_entry_t &r) {
			r.u.installed.program_id[0]++; }), false, EPROTO},
		{"wrong source", noop, one([](dtt_entry_t &r) {
			r.u.installed.source_id[0]++; }), false, EPROTO},
		{"replay set", noop, one([](dtt_entry_t &r) {
			r.u.installed.replay = 1; }), false, EPROTO},
		/* A queued new-incarnation notice and stale old-incarnation
		 * replies for other nonces are drained before the answer. */
		{"notice and orphans drained", noop, [](const dtt_entry_t &q) {
			dtt_entry_t notice{};
			notice.event_kind = DTT_VM_REKEY;
			notice.u.installed.vmid = 5;
			notice.u.installed.epoch = 7;
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id ^= 0x5a5a;
			dtt_entry_t orphan_kill = orphan;
			orphan_kill.event_kind = DTT_REKEY_KILL_RECEIPT;
			dtt_entry_t orphan_ingress = orphan;
			orphan_ingress.event_kind = DTT_REKEY_INGRESS_RECEIPT;
			return std::vector<dtt_entry_t>{notice, orphan, orphan_kill,
			    orphan_ingress, good_receipt(q)};
		}, true, 0},
		{"second notice refused", noop, [](const dtt_entry_t &q) {
			dtt_entry_t notice{};
			notice.event_kind = DTT_VM_REKEY;
			notice.u.installed.vmid = 5;
			notice.u.installed.epoch = 7;
			return std::vector<dtt_entry_t>{notice, notice, good_receipt(q)};
		}, false, EPROTO},
		{"notice for another incarnation", noop, [](const dtt_entry_t &q) {
			dtt_entry_t notice{};
			notice.event_kind = DTT_VM_REKEY;
			notice.u.installed.vmid = 5;
			notice.u.installed.epoch = 8;
			return std::vector<dtt_entry_t>{notice, good_receipt(q)};
		}, false, EPROTO},
		{"orphan replay is not drained", noop, [](const dtt_entry_t &q) {
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id ^= 1;
			orphan.u.installed.replay = 1;
			return std::vector<dtt_entry_t>{orphan, good_receipt(q)};
		}, false, EPROTO},
		{"orphan with zero query is not drained", noop, [](const dtt_entry_t &q) {
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id = 0;
			return std::vector<dtt_entry_t>{orphan, good_receipt(q)};
		}, false, EPROTO},
		{"orphan with zero delivery is not drained", noop, [](const dtt_entry_t &q) {
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id ^= 1;
			orphan.u.installed.delivery_id = 0;
			return std::vector<dtt_entry_t>{orphan, good_receipt(q)};
		}, false, EPROTO},
		{"orphan with zero source is not drained", noop, [](const dtt_entry_t &q) {
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id ^= 1;
			memset(orphan.u.installed.source_id, 0, 16);
			return std::vector<dtt_entry_t>{orphan, good_receipt(q)};
		}, false, EPROTO},
		{"orphan from another incarnation is not drained", noop,
		    [](const dtt_entry_t &q) {
			dtt_entry_t orphan = good_receipt(q);
			orphan.u.installed.query_id ^= 1;
			orphan.u.installed.epoch = 77;
			return std::vector<dtt_entry_t>{orphan, good_receipt(q)};
		}, false, EPROTO},
	};
	for (auto &c : cases) {
		receipt_args a;
		c.setup(a);
		driver d(c.reply);
		d.start();
		errno = 0;
		bool ok = call(d.fd[0], a);
		if (ok != c.ok || (!ok && errno != c.error)) {
			fprintf(stderr, "case '%s': ok=%d errno=%d\n", c.name, ok, errno);
			abort();
		}
		std::lock_guard lock(d.mtx);
		CHECK(d.queries.size() == 1);
		const dtt_entry_t &q = d.queries[0];
		CHECK(q.event_kind == a.kind && q.u.installed.delivery_id == a.delivery &&
		    q.u.installed.vmid == a.old_vmid &&
		    q.u.installed.epoch == a.old_epoch &&
		    memcmp(q.u.installed.program_id, a.program, 16) == 0 &&
		    memcmp(q.u.installed.source_id, a.source, 16) == 0 &&
		    memcmp(q.u.installed.digest, a.digest, 32) == 0 &&
		    q.u.installed.query_id != 0);
	}
}

static void
test_receipt_transport()
{
	receipt_args a;
	auto good = [](const dtt_entry_t &q) {
		return std::vector<dtt_entry_t>{good_receipt(q)}; };
	/* transient write errors are retried, a hard error is returned */
	for (int e : {EINTR, EAGAIN, ENOBUFS, EBUSY}) {
		reset_injection();
		driver d(good);
		write_errors = {e, e};
		d.start();
		CHECK(call(d.fd[0], a));
	}
	{
		reset_injection();
		driver d(good);
		write_errors = {EPERM};
		d.start();
		CHECK(!call(d.fd[0], a) && errno == EPERM);
	}
	{	/* a partial device write is an I/O failure */
		reset_injection();
		driver d(good);
		write_errors = {-1};
		d.start();
		CHECK(!call(d.fd[0], a) && errno == EIO);
	}
	{	/* interrupted read is retried */
		reset_injection();
		driver d(good);
		read_errors = {EINTR};
		d.start();
		CHECK(call(d.fd[0], a));
	}
	{	/* hard read error */
		reset_injection();
		driver d(good);
		read_errors = {EBADF};
		d.start();
		CHECK(!call(d.fd[0], a) && errno == EBADF);
	}
	{	/* short reply then EOF */
		reset_injection();
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		std::thread t([&] {
			dtt_entry_t q{};
			CHECK(peer_recv(d.fd[1], q));
			CHECK(write(d.fd[1], &q, 10) == 10);
			shutdown(d.fd[1], SHUT_WR);
		});
		CHECK(!call(d.fd[0], a) && errno == EPROTO);
		t.join();
	}
	{	/* EOF before any reply byte */
		reset_injection();
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		std::thread t([&] {
			dtt_entry_t q{};
			CHECK(peer_recv(d.fd[1], q));
			shutdown(d.fd[1], SHUT_WR);
		});
		CHECK(!call(d.fd[0], a) && errno == EPROTO);
		t.join();
	}
	{	/* no reply before the deadline */
		reset_injection();
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		d.start();
		CHECK(!call(d.fd[0], a, 150) && errno == ETIMEDOUT);
	}
	{	/* deadline already expired; and writes that never complete */
		reset_injection();
		driver d(good);
		CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid,
		    a.old_epoch, a.new_vmid, a.new_epoch, a.delivery, a.program,
		    a.source, a.digest, false, 0) && errno == ETIMEDOUT);
		write_errors.assign(1000, EAGAIN);
		CHECK(!call(d.fd[0], a, 100) && errno == ETIMEDOUT);
	}
	{	/* clock failure while writing and while reading */
		reset_injection();
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		int64_t deadline = dtraced_io_deadline_after(1000);
		clock_fail_after.store(0);
		CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid,
		    a.old_epoch, a.new_vmid, a.new_epoch, a.delivery, a.program,
		    a.source, a.digest, false, deadline) && errno == EIO);
		clock_fail_after.store(1);
		CHECK(!query_guest_rekey_receipt(d.fd[0], a.kind, a.old_vmid,
		    a.old_epoch, a.new_vmid, a.new_epoch, a.delivery, a.program,
		    a.source, a.digest, false, deadline) && errno == EIO);
	}
	reset_injection();
}

/* ---- recover_guest_rekey with real journals ---- */
static constexpr uint16_t OLD_VM = 21, NEW_VM = 22;
static constexpr uint64_t OLD_EPOCH = 31, NEW_EPOCH = 32;

struct journals {
	temp_tree tree{"dtt-rekey"};
	std::unique_ptr<dir> inbound, outbound;
	state s{};
	std::vector<unsigned char> in_elf, out_elf;
	durable_delivery in_rec{}, out_rec{};
	durable_kill kill{};

	/* variant: 0 HTD4 accepted; 1 HTD3; 2 HTD4 with a different spool;
	 * 3 HTD4 terminal without spool; 4 HTD4 accepted without spool;
	 * 5 HTD3 without spool. */
	explicit journals(int variant = 0)
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		outbound = std::make_unique<dir>(tree.sub("outbound").c_str(), nullptr);
		inbound->state = outbound->state = &s;
		s.inbounddir = inbound.get();
		s.outbounddir = outbound.get();
		in_elf = {0x7f, 'E', 'L', 'F', 1, 2, 3};
		out_elf = {0x7f, 'E', 'L', 'F', 9, 8, 7, 6};
		guest_delivery g{};
		g.delivery_id = 41;
		g.vmid = OLD_VM;
		g.epoch = OLD_EPOCH;
		g.program_id[0] = 0x11;
		g.source_id[0] = 0x12;
		g.journal_version = variant == 1 || variant == 5 ? 3 : 4;
		if (g.journal_version == 4)
			SHA256(in_elf.data(), in_elf.size(), g.payload_digest.data());
		in_rec = guest_delivery_record(g);
		bool created = false;
		std::vector<unsigned char> spool = in_elf;
		if (variant == 2)
			spool.push_back(0);
		if (variant != 3 && variant != 4 && variant != 5)
			CHECK(inbound->write_identified_data(spool.data(), spool.size(),
			    g.program_id.data(), &created, g.source_id.data()) && created);
		CHECK(inbound->record_delivery(in_rec, delivery_phase::pending, true));
		CHECK(inbound->record_delivery(in_rec, delivery_phase::accepted));
		if (variant == 3) {
			CHECK(inbound->record_delivery(in_rec, delivery_phase::exited));
			CHECK(inbound->record_delivery(in_rec, delivery_phase::terminal));
		}
		out_rec = {};
		out_rec.scope = 2;
		out_rec.journal_version = 4;
		out_rec.session_id[0] = 0x21;
		out_rec.delivery_id = 51;
		out_rec.vmid = OLD_VM;
		out_rec.epoch = OLD_EPOCH;
		out_rec.program_id[0] = 0x22;
		out_rec.source_id[0] = 0x23;
		out_rec.peer_pid = 100;
		SHA256(out_elf.data(), out_elf.size(), out_rec.payload_digest.data());
		CHECK(outbound->write_identified_data(out_elf.data(), out_elf.size(),
		    out_rec.program_id.data(), &created, out_rec.source_id.data()) &&
		    created);
		CHECK(outbound->record_delivery(out_rec, delivery_phase::pending, true));
		kill = {4242, OLD_VM, OLD_EPOCH, {}};
		kill.source_id[0] = 0x31;
		CHECK(inbound->record_kill(kill));
	}
	/* Journals name exactly one incarnation and keep their identities. */
	bool names(uint16_t vmid, uint64_t epoch)
	{
		std::vector<durable_delivery_state> in, out;
		std::vector<durable_kill> kills;
		if (!inbound->list_deliveries(in) || !outbound->list_deliveries(out) ||
		    !inbound->list_kills(kills))
			return (false);
		if (in.size() != 1 || out.size() != 1 || kills.size() != 1)
			return (false);
		return (in[0].record.vmid == vmid && in[0].record.epoch == epoch &&
		    in[0].record.program_id == in_rec.program_id &&
		    in[0].record.payload_digest == in_rec.payload_digest &&
		    out[0].record.vmid == vmid && out[0].record.epoch == epoch &&
		    out[0].record.delivery_id == out_rec.delivery_id &&
		    out[0].record.payload_digest == out_rec.payload_digest &&
		    kills[0].vmid == vmid && kills[0].epoch == epoch &&
		    kills[0].pid == kill.pid && kills[0].source_id == kill.source_id);
	}
	~journals()
	{
		s.inbounddir = nullptr;
		s.outbounddir = nullptr;
	}
};

static dtt_vm_identity
pending_identity(uint32_t flags = DTT_IDENTITY_REKEY_PENDING)
{
	dtt_vm_identity id{};
	id.vmid = NEW_VM;
	id.epoch = NEW_EPOCH;
	id.old_vmid = OLD_VM;
	id.old_epoch = OLD_EPOCH;
	id.flags = flags;
	return (id);
}

/* The driver acknowledges the commit after `after` identity queries. */
static void
identity_clears_after(int after, uint32_t interim = DTT_IDENTITY_REKEY_LOCAL_COMMITTED)
{
	identity_script = [after, interim](dtt_vm_identity &id, int n) {
		id = pending_identity(n < after ? interim : 0);
		if (n >= after) {
			id.old_vmid = 0;
			id.old_epoch = 0;
		}
	};
}

static void
test_recover_success()
{
	reset_injection();
	journals j;
	driver d([](const dtt_entry_t &q) {
		return std::vector<dtt_entry_t>{good_receipt(q)}; });
	/* A former daemon left the priority notice and an orphan reply. */
	dtt_entry_t notice{};
	notice.event_kind = DTT_VM_REKEY;
	notice.u.installed.vmid = NEW_VM;
	notice.u.installed.epoch = NEW_EPOCH;
	d.preload(notice);
	j.s.dtt_fd = d.fd[0];
	d.start();
	identity_clears_after(2);
	dtt_vm_identity committed{};
	commit_observer = [&](const dtt_vm_identity &id) { committed = id; };
	CHECK(recover_guest_rekey(&j.s, pending_identity()));
	CHECK(j.names(NEW_VM, NEW_EPOCH));
	CHECK(j.inbound->guest_rekey_pair_complete(*j.outbound, OLD_VM,
	    OLD_EPOCH, NEW_VM, NEW_EPOCH));
	CHECK(commit_calls.load() == 1 && committed.flags == 0 &&
	    committed.vmid == NEW_VM && committed.old_vmid == OLD_VM);
	std::lock_guard lock(d.mtx);
	CHECK(d.queries.size() == 3);
	int seen = 0;
	for (const auto &q : d.queries) {
		CHECK(q.u.installed.vmid == OLD_VM && q.u.installed.epoch == OLD_EPOCH);
		if (q.event_kind == DTT_REKEY_DELIVERY_QUERY) {
			CHECK(q.u.installed.delivery_id == j.in_rec.delivery_id &&
			    memcmp(q.u.installed.digest, j.in_rec.payload_digest.data(),
			    32) == 0);
			seen |= 1;
		} else if (q.event_kind == DTT_REKEY_INGRESS_QUERY) {
			CHECK(q.u.installed.delivery_id == j.out_rec.delivery_id &&
			    memcmp(q.u.installed.digest, j.out_rec.payload_digest.data(),
			    32) == 0);
			seen |= 2;
		} else {
			CHECK(q.event_kind == DTT_REKEY_KILL_QUERY &&
			    q.u.installed.delivery_id == (uint64_t)j.kill.pid);
			seen |= 4;
		}
	}
	CHECK(seen == 7);
}

static void
test_recover_retries()
{
	/* Unavailable host answers and transient commit errors are retried
	 * with the same identity and deadline. */
	reset_injection();
	journals j;
	std::atomic<int> unavailable{1};
	driver d([&](const dtt_entry_t &q) {
		dtt_entry_t r = good_receipt(q);
		if (q.event_kind == DTT_REKEY_DELIVERY_QUERY &&
		    unavailable.fetch_sub(1) > 0) {
			r.u.installed.phase = 'u';
			memset(r.u.installed.digest, 0, 32);
		}
		return std::vector<dtt_entry_t>{r};
	});
	j.s.dtt_fd = d.fd[0];
	d.start();
	commit_errors = {EBUSY, EAGAIN, ENOMEM, EINTR, EIO, 0};
	identity_script = [](dtt_vm_identity &id, int n) {
		if (n == 0) {	/* the driver is momentarily busy */
			id.flags = 0xffffffffu;
			id.vmid = EAGAIN;
			return;
		}
		id = pending_identity(n < 2 ? DTT_IDENTITY_REKEY_LOCAL_COMMITTED : 0);
	};
	CHECK(recover_guest_rekey(&j.s, pending_identity()));
	CHECK(commit_calls.load() == 6);
	CHECK(j.names(NEW_VM, NEW_EPOCH));
}

static void
test_recover_refusals()
{
	/* A refused receipt leaves every journal on the old incarnation. */
	for (uint8_t refuse : {(uint8_t)DTT_REKEY_DELIVERY_QUERY,
	    (uint8_t)DTT_REKEY_INGRESS_QUERY, (uint8_t)DTT_REKEY_KILL_QUERY}) {
		reset_injection();
		journals j;
		driver d([refuse](const dtt_entry_t &q) {
			dtt_entry_t r = good_receipt(q);
			if (q.event_kind == refuse)
				r.u.installed.revoked = 2;
			return std::vector<dtt_entry_t>{r};
		});
		j.s.dtt_fd = d.fd[0];
		d.start();
		identity_clears_after(0);
		errno = 0;
		CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == EPROTO);
		CHECK(j.names(OLD_VM, OLD_EPOCH));
		CHECK(commit_calls.load() == 0);
	}
	/* Hard commit failure after durable journal rekey. The local state is
	 * then recoverable through the LOCAL_COMMITTED path without another
	 * COMMIT. */
	{
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &q) {
			return std::vector<dtt_entry_t>{good_receipt(q)}; });
		j.s.dtt_fd = d.fd[0];
		d.start();
		commit_errors = {EPERM};
		identity_clears_after(0);
		CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == EPERM);
		CHECK(j.names(NEW_VM, NEW_EPOCH));
		reset_injection();
		identity_clears_after(1);
		CHECK(recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)));
		CHECK(commit_calls.load() == 0);
		/* identity regresses after the commit */
		reset_injection();
		identity_script = [](dtt_vm_identity &id, int) {
			id = pending_identity(0);
			id.epoch = NEW_EPOCH + 1;
		};
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == EPROTO);
		reset_injection();
		identity_script = [](dtt_vm_identity &id, int) {
			id = pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED);
			id.old_epoch = OLD_EPOCH + 5;
		};
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == EPROTO);
		reset_injection();
		identity_script = [](dtt_vm_identity &id, int) {
			id = pending_identity(DTT_IDENTITY_REKEY_PENDING);
		};
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == EPROTO);
		reset_injection();
		identity_script = [](dtt_vm_identity &id, int) {
			id.flags = 0xffffffffu;
			id.vmid = ENXIO;
		};
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == ENXIO);
	}
	/* LOCAL_COMMITTED with an incomplete pair is a protocol failure. */
	{
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		j.s.dtt_fd = d.fd[0];
		identity_clears_after(0);
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)));
		CHECK(errno != EIO && errno != EINTR);
		CHECK(j.names(OLD_VM, OLD_EPOCH));
	}
}

static void
test_recover_notice_and_arguments()
{
	reset_injection();
	journals j;
	using edit_t = void (*)(dtt_vm_identity &);
	const edit_t invalid[] = {
		[](dtt_vm_identity &i) { i.vmid = 0; },
		[](dtt_vm_identity &i) { i.vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_vm_identity &i) { i.epoch = 0; },
		[](dtt_vm_identity &i) { i.old_vmid = 0; },
		[](dtt_vm_identity &i) { i.old_vmid = HYPERTRACE_MAX_VMS; },
		[](dtt_vm_identity &i) { i.old_epoch = 0; },
		[](dtt_vm_identity &i) { i.old_vmid = i.vmid; i.old_epoch = i.epoch; },
		[](dtt_vm_identity &i) { i.flags = 0; },
		[](dtt_vm_identity &i) { i.flags = DTT_IDENTITY_FRESH_PENDING; },
	};
	driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
	j.s.dtt_fd = d.fd[0];
	for (edit_t edit : invalid) {
		dtt_vm_identity id = pending_identity();
		edit(id);
		errno = 0;
		CHECK(!recover_guest_rekey(&j.s, id) && errno == EINVAL);
	}
	CHECK(!recover_guest_rekey(nullptr, pending_identity()) && errno == EINVAL);
	j.s.dtt_fd = -1;
	CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == EINVAL);
	j.s.dtt_fd = d.fd[0];
	j.s.outbounddir = nullptr;
	CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == EINVAL);
	j.s.outbounddir = j.outbound.get();
	j.s.inbounddir = nullptr;
	CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == EINVAL);
	j.s.inbounddir = j.inbound.get();
	CHECK(peer_quiet(d.fd[1], 10));
	CHECK(j.names(OLD_VM, OLD_EPOCH));
	/* Queued events before the notice. */
	auto queued = [&](std::vector<dtt_entry_t> events, int expect_errno,
	    bool close_peer = false, bool short_record = false) {
		reset_injection();
		journals k;
		driver q([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		for (const auto &e : events)
			q.preload(e);
		if (short_record)
			CHECK(write(q.fd[1], "x", 1) == 1);
		if (close_peer)
			shutdown(q.fd[1], SHUT_WR);
		k.s.dtt_fd = q.fd[0];
		errno = 0;
		CHECK(!recover_guest_rekey(&k.s, pending_identity()) &&
		    errno == expect_errno);
		CHECK(k.names(OLD_VM, OLD_EPOCH));
	};
	dtt_entry_t other{};
	other.event_kind = DTT_KILL;
	queued({other}, EPROTO);
	queued({}, EPROTO, true);		/* driver closed */
	queued({}, EPROTO, true, true);		/* truncated record */
	dtt_entry_t wrong_notice{};
	wrong_notice.event_kind = DTT_VM_REKEY;
	wrong_notice.u.installed.vmid = NEW_VM;
	wrong_notice.u.installed.epoch = NEW_EPOCH + 1;
	queued({wrong_notice}, EPROTO);
	/* Interrupted reads of the notice are retried; a hard error stops. */
	{
		reset_injection();
		journals k;
		driver q([](const dtt_entry_t &qq) {
			return std::vector<dtt_entry_t>{good_receipt(qq)}; });
		read_errors = {EINTR};
		k.s.dtt_fd = q.fd[0];
		q.start();
		identity_clears_after(0);
		CHECK(recover_guest_rekey(&k.s, pending_identity()));
		reset_injection();
		journals m;
		driver r([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		read_errors = {EBADF};
		m.s.dtt_fd = r.fd[0];
		CHECK(!recover_guest_rekey(&m.s, pending_identity()) && errno == EBADF);
	}
	/* Clock failures at each deadline check. */
	for (int fail = 0; fail < 3; ++fail) {
		reset_injection();
		journals k;
		driver q([](const dtt_entry_t &qq) {
			return std::vector<dtt_entry_t>{good_receipt(qq)}; });
		k.s.dtt_fd = q.fd[0];
		q.start();
		identity_clears_after(0);
		clock_fail_after.store(fail);
		CHECK(!recover_guest_rekey(&k.s, pending_identity()) && errno == EIO);
	}
	reset_injection();
}

static void
test_recover_deadlines_and_variants()
{
	/* The fixed 50 s deadline bounds each phase. */
	{	/* journal phase */
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		j.s.dtt_fd = d.fd[0];
		clock_skew_at.store(3);
		CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == ETIMEDOUT);
		CHECK(j.names(OLD_VM, OLD_EPOCH));
	}
	{	/* LOCAL_COMMITTED pair check */
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &) { return std::vector<dtt_entry_t>{}; });
		j.s.dtt_fd = d.fd[0];
		clock_skew_at.store(3);
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == ETIMEDOUT);
	}
	{	/* commit phase and identity phase, after a durable rekey */
		reset_injection();
		journals j;
		std::atomic<bool> skew_next{false};
		driver d([&](const dtt_entry_t &q) {
			if (q.event_kind == DTT_REKEY_KILL_QUERY)
				skew_next.store(true);
			return std::vector<dtt_entry_t>{good_receipt(q)}; });
		j.s.dtt_fd = d.fd[0];
		d.start();
		commit_errors = {EBUSY};
		commit_observer = [&](const dtt_vm_identity &) {
			if (skew_next.exchange(false))
				clock_skew_ms.store(60000);
		};
		identity_clears_after(0);
		CHECK(!recover_guest_rekey(&j.s, pending_identity()) && errno == ETIMEDOUT);
		CHECK(commit_calls.load() == 1);
		CHECK(j.names(NEW_VM, NEW_EPOCH));
		/* identity never clears: the local-commit recovery times out */
		reset_injection();
		identity_script = [](dtt_vm_identity &id, int n) {
			id = pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED);
			if (n == 1)
				clock_skew_ms.store(60000);
		};
		CHECK(!recover_guest_rekey(&j.s,
		    pending_identity(DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) &&
		    errno == ETIMEDOUT);
		CHECK(identity_calls.load() == 2);
	}
	{	/* a lost receipt write is retried through the journal loop */
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &q) {
			return std::vector<dtt_entry_t>{good_receipt(q)}; });
		j.s.dtt_fd = d.fd[0];
		d.start();
		write_errors = {-1};
		identity_clears_after(0);
		CHECK(recover_guest_rekey(&j.s, pending_identity()));
		CHECK(j.names(NEW_VM, NEW_EPOCH));
		std::lock_guard lock(d.mtx);
		CHECK(d.queries.size() == 3);	/* the short write never arrived whole */
	}
	{	/* orphan old receipt queued before the notice is discarded */
		reset_injection();
		journals j;
		driver d([](const dtt_entry_t &q) {
			return std::vector<dtt_entry_t>{good_receipt(q)}; });
		dtt_entry_t orphan{};
		orphan.event_kind = DTT_REKEY_INGRESS_RECEIPT;
		orphan.u.installed.vmid = OLD_VM;
		orphan.u.installed.epoch = OLD_EPOCH;
		orphan.u.installed.query_id = 99;
		orphan.u.installed.delivery_id = 5;
		orphan.u.installed.source_id[0] = 1;
		d.preload(orphan);
		j.s.dtt_fd = d.fd[0];
		d.start();
		identity_clears_after(0);
		CHECK(recover_guest_rekey(&j.s, pending_identity()));
	}
	/* Inbound journal variants: HTD3 hashes its spool for the receipt; a
	 * HTD4 spool must match its digest unless the delivery is terminal and
	 * its spool already retired. */
	struct { int variant; bool ok; int error; } variants[] = {
		{1, true, 0},		/* HTD3: digest comes from the spool */
		{2, false, EPROTO},	/* HTD4 spool differs from its digest */
		{3, true, 0},		/* HTD4 terminal, spool retired */
		{4, false, EPROTO},	/* HTD4 accepted, spool missing */
		{5, false, ENOENT},	/* HTD3, spool missing */
	};
	for (auto &v : variants) {
		reset_injection();
		journals j(v.variant);
		driver d([](const dtt_entry_t &q) {
			return std::vector<dtt_entry_t>{good_receipt(q)}; });
		j.s.dtt_fd = d.fd[0];
		d.start();
		identity_clears_after(0);
		errno = 0;
		bool ok = recover_guest_rekey(&j.s, pending_identity());
		if (ok != v.ok || (!ok && errno != v.error)) {
			fprintf(stderr, "inbound variant %d: ok=%d errno=%d\n", v.variant,
			    ok, errno);
			abort();
		}
		std::lock_guard lock(d.mtx);
		for (const auto &q : d.queries)
			if (q.event_kind == DTT_REKEY_DELIVERY_QUERY) {
				uint8_t expected[32];
				SHA256(j.in_elf.data(), j.in_elf.size(), expected);
				CHECK(memcmp(q.u.installed.digest, expected, 32) == 0);
			}
	}
	reset_injection();
}

int
main()
{
	alarm(240);
	main_thread = pthread_self();
	signal(SIGPIPE, SIG_IGN);
	identity_clears_after(0);
	test_receipt_arguments();
	test_receipt_replies();
	test_receipt_transport();
	test_recover_success();
	test_recover_retries();
	test_recover_refusals();
	test_recover_notice_and_arguments();
	test_recover_deadlines_and_variants();
	printf("dtt-rekey: %u checks passed\n", harness_checks);
	return (0);
}
