/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interrupted persistence for the daemon journals (actual dtraced_directory
 * objects). Each operation is repeated with a single injected failure at the
 * k-th file-system call made by the calling thread, for every k until the
 * operation completes without reaching the injection point. Injected calls:
 * openat, fsync, write, read, pread, renameat, linkat, unlinkat, fstat,
 * close (closes for real, then reports EIO) and readdir.
 *
 * Oracle (crash/retry consistency), checked with a fresh dir object on the
 * same directory after populate_existing(), as a restarted daemon sees it:
 *   1. every reader (list_deliveries, list_kills, list_pending_cleanups, and
 *      the operation's own status query) succeeds: no failure may leave a
 *      record that makes recovery fail;
 *   2. the operation's durable effect is either entirely absent (old state)
 *      or entirely present (new state);
 *   3. repeating the operation without injection reaches the new state.
 */
#include <sys/stat.h>
#include <dirent.h>
#include <cstdarg>
#include <openssl/sha.h>
#include <sys/hypertrace.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

using namespace dtraced;

static pthread_t main_thread;
static int countdown = -1;	/* main thread only */
static bool fired;
static unsigned injected_total;

static const char *fired_call;
#define inject(e) inject_named(e, __func__)
static bool
inject_named(int &error, const char *call)
{
	if (!pthread_equal(pthread_self(), main_thread) || countdown < 0)
		return (false);
	if (countdown-- == 0) {
		fired = true;
		fired_call = call;
		++injected_total;
		error = EIO;
		return (true);
	}
	return (false);
}

#define WRAP_INT(name, proto, args) \
	extern "C" int __real_##name proto; \
	extern "C" int __wrap_##name proto { \
		int e; \
		if (inject(e)) { errno = e; return (-1); } \
		return (__real_##name args); \
	}

extern "C" int __real_openat(int, const char *, int, ...);
extern "C" int
__wrap_openat(int fd, const char *path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	int mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	va_end(ap);
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	return (__real_openat(fd, path, flags, mode));
}
WRAP_INT(fsync, (int fd), (fd))
WRAP_INT(renameat, (int a, const char *b, int c, const char *d), (a, b, c, d))
WRAP_INT(linkat, (int a, const char *b, int c, const char *d, int f), (a, b, c, d, f))
/* Name-targeted fault: the next N removals of a publication temporary
 * (".handoff-tmp.*") fail with EIO, independent of the countdown sweep. */
static int tmp_unlink_failures;
static unsigned tmp_unlink_attempts;
extern "C" int __real_unlinkat(int, const char *, int);
extern "C" int
__wrap_unlinkat(int a, const char *b, int c)
{
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	if (pthread_equal(pthread_self(), main_thread) &&
	    strncmp(b, ".handoff-tmp.", 13) == 0) {
		++tmp_unlink_attempts;
		if (tmp_unlink_failures > 0) {
			--tmp_unlink_failures;
			errno = EIO;
			return (-1);
		}
	}
	return (__real_unlinkat(a, b, c));
}
WRAP_INT(fstat, (int a, struct stat *b), (a, b))

extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" ssize_t
__wrap_write(int fd, const void *b, size_t n)
{
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	return (__real_write(fd, b, n));
}
extern "C" ssize_t __real_read(int, void *, size_t);
extern "C" ssize_t
__wrap_read(int fd, void *b, size_t n)
{
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	return (__real_read(fd, b, n));
}
extern "C" ssize_t __real_pread(int, void *, size_t, off_t);
extern "C" ssize_t
__wrap_pread(int fd, void *b, size_t n, off_t o)
{
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	return (__real_pread(fd, b, n, o));
}
extern "C" int __real_close(int);
extern "C" int
__wrap_close(int fd)
{
	int e;
	if (inject(e)) {
		(void)__real_close(fd);
		errno = e;
		return (-1);
	}
	return (__real_close(fd));
}
extern "C" struct dirent *__real_readdir(DIR *);
extern "C" struct dirent *
__wrap_readdir(DIR *d)
{
	int e;
	if (inject(e)) {
		errno = e;
		return (nullptr);
	}
	return (__real_readdir(d));
}

/* The HyperTrace epoch gate (fresh-session stop) is emulated; opening it is
 * itself an injectable call. */
static int gate_fd = -1;
static bool gate_suspended;
static uint8_t gate_token[16];
extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	int mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	va_end(ap);
	int e;
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		if (inject(e)) {
			errno = e;
			return (-1);
		}
		gate_fd = __real_open("/dev/null", O_RDONLY);
		return (gate_fd);
	}
	CHECK(strncmp(path, "/dev/", 5) != 0 || strcmp(path, "/dev/null") == 0);
	return (__real_open(path, flags, mode));
}
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (fd != gate_fd || request != HYPERTRACE_IOC_EPOCH_GATE_QUERY)
		return (__real_ioctl(fd, request, arg));
	int e;
	if (inject(e)) {
		errno = e;
		return (-1);
	}
	auto *gate = static_cast<hypertrace_epoch_gate *>(arg);
	gate->suspended = gate_suspended ? 1 : 0;
	memcpy(gate->token, gate_token, 16);
	return (0);
}

/* ---- sweep driver ---- */
struct journal {
	temp_tree tree{"journal-faults"};
	std::string path;
	std::unique_ptr<dir> d;
	state s{};
	journal() : path(tree.sub("j"))
	{
		d = std::make_unique<dir>(path.c_str(), nullptr);
		d->state = &s;
	}
	/* What a restarted daemon sees: initialize() opens the directory and
	 * runs populate_existing(), which removes stale publication
	 * temporaries before any journal is read. */
	std::unique_ptr<dir> reopen()
	{
		auto fresh = std::make_unique<dir>(path.c_str(), nullptr);
		fresh->state = &s;
		CHECK(fresh->populate_existing());
		return (fresh);
	}
};

static bool
readers_ok(dir &d)
{
	std::vector<durable_delivery_state> deliveries;
	std::vector<durable_kill> kills;
	std::vector<durable_cleanup> cleanups;
	return (d.list_deliveries(deliveries) && d.list_kills(kills) &&
	    d.list_pending_cleanups(cleanups));
}

struct op_spec {
	const char *name;
	std::function<void(dir &)> setup;	/* precondition, no injection */
	std::function<bool(dir &)> op;
	/* 0 old state, 1 new state, -1 neither/unreadable */
	std::function<int(dir &)> classify;
};

static unsigned sweeps, points;

static void
sweep(const op_spec &spec)
{
	for (int k = 0;; ++k) {
		CHECK(k < 2000);
		journal j;
		spec.setup(*j.d);
		CHECK(spec.classify(*j.d) == 0);
		fired = false;
		countdown = k;
		errno = 0;
		bool ok = spec.op(*j.d);
		countdown = -1;
		if (!fired) {
			/* completed before the k-th call: the final new state */
			if (!ok)
				fprintf(stderr, "%s: failed without injection (errno %d)\n",
				    spec.name, errno);
			CHECK(ok);
			auto fresh = j.reopen();
			CHECK(readers_ok(*fresh) && spec.classify(*fresh) == 1);
			++sweeps;
			return;
		}
		++points;
		auto fresh = j.reopen();
		bool readable = readers_ok(*fresh);
		int seen = spec.classify(*fresh);
		if (!readable || seen < 0 || (ok && seen != 1)) {
			fprintf(stderr, "%s: injection at call %d (%s) left %s state "
			    "(op %s)\n", spec.name, k, fired_call,
			    !readable ? "an unreadable" : seen < 0 ? "a partial" :
			    "an old", ok ? "reported success" : "failed");
			abort();
		}
		/* Retry on the restarted view must converge on the new state. */
		bool retried = spec.op(*fresh) || spec.classify(*fresh) == 1;
		if (!retried)
			fprintf(stderr, "%s: retry after call %d failed (errno %d)\n",
			    spec.name, k, errno);
		CHECK(retried);
		auto final_view = j.reopen();
		CHECK(readers_ok(*final_view) && spec.classify(*final_view) == 1);
	}
}

/* ---- operations ---- */
static guest_delivery
guest_record(uint64_t id = 17)
{
	guest_delivery g{};
	g.delivery_id = id;
	g.vmid = 42;
	g.epoch = 99;
	g.program_id[0] = 0x31;
	g.source_id[0] = 0x32;
	g.journal_version = 4;
	g.payload_digest[0] = 7;
	return (g);
}

static int
phase_class(dir &d, const durable_delivery &r, int old_phase, int new_phase)
{
	int p = d.delivery_status(r);
	return (p == old_phase ? 0 : p == new_phase ? 1 : -1);
}

/* Count directory entries with the publication temporary prefix. */
static int
temporaries(dir &d)
{
	int n = 0, fd = dup(d.dirfd);
	DIR *dp = fdopendir(fd);
	rewinddir(dp);
	while (struct dirent *e = readdir(dp))
		n += strncmp(e->d_name, ".handoff-tmp.", 13) == 0;
	closedir(dp);
	return (n);
}

/* Regression (temporary unlink retried in place): when removing the
 * publication temporary after linkat() fails transiently, the same daemon
 * process must complete the publication and read it back, instead of
 * refusing the double-linked record with EPROTO until a restart. */
static void
test_temporary_unlink_retry(const durable_session_stop &stop)
{
	auto found_stop = [&](dir &d) {
		durable_session_stop found{};
		int r = d.fresh_session_stop_for_vm(42, 99, found);
		return (r == 1 && found.token == stop.token &&
		    found.source_session == stop.source_session);
	};
	gate_suspended = true;
	memcpy(gate_token, stop.token.data(), 16);
	for (int failures = 1; failures <= 3; ++failures) {
		journal j;
		tmp_unlink_failures = failures;
		tmp_unlink_attempts = 0;
		errno = 0;
		bool ok = j.d->begin_fresh_session_stop(stop);
		CHECK(ok && tmp_unlink_failures == 0 &&
		    tmp_unlink_attempts == (unsigned)failures + 1);
		/* Same process, same dir object: no restart in between. */
		CHECK(temporaries(*j.d) == 0 && found_stop(*j.d));
		CHECK(j.d->begin_fresh_session_stop(stop) && found_stop(*j.d));
		CHECK(readers_ok(*j.d));
	}
	{	/* persistent failure: reported, and a restart still recovers */
		journal j;
		tmp_unlink_failures = 1000;
		tmp_unlink_attempts = 0;
		errno = 0;
		CHECK(!j.d->begin_fresh_session_stop(stop) && errno == EIO);
		CHECK(tmp_unlink_attempts == 4 && temporaries(*j.d) == 1);
		tmp_unlink_failures = 0;
		auto fresh = j.reopen();
		CHECK(temporaries(*fresh) == 0 && found_stop(*fresh));
		CHECK(fresh->begin_fresh_session_stop(stop) && found_stop(*fresh));
	}
}

/* Regression (refused cleanup replayed): a CLEANUP request whose pending
 * record cannot be completed is answered with a NAK, so no failure point
 * may leave the pending record behind for recovery to replay after a
 * restart (formerly a failed close() or directory fsync() did). */
static void
test_cleanup_pending_refusal_not_durable(void)
{
	durable_cleanup cleanup{42, 99, 78};
	unsigned failed = 0;
	for (int k = 0;; ++k) {
		CHECK(k < 2000);
		journal j;
		fired = false;
		countdown = k;
		bool ok = j.d->record_cleanup_pending(cleanup);
		countdown = -1;
		auto fresh = j.reopen();
		std::vector<durable_cleanup> pending;
		CHECK(fresh->list_pending_cleanups(pending));
		if (!fired) {
			CHECK(ok && pending.size() == 1 &&
			    fresh->cleanup_status(cleanup) == 'p');
			break;
		}
		if (!ok) {
			++failed;
			if (!pending.empty() || fresh->cleanup_status(cleanup) != 0)
				fprintf(stderr, "cleanup pending: refused at call %d (%s) "
				    "but left a pending record\n", k, fired_call);
			CHECK(pending.empty() && fresh->cleanup_status(cleanup) == 0);
		}
	}
	CHECK(failed >= 3);	/* includes the late close and directory fsync */
}

int
main()
{
	alarm(280);
	main_thread = pthread_self();
	const durable_delivery in = guest_delivery_record(guest_record());
	durable_delivery out{};
	out.scope = 2;
	out.journal_version = 4;
	out.session_id[0] = 9;
	out.delivery_id = 51;
	out.vmid = 42;
	out.epoch = 99;
	out.program_id[0] = 0x41;
	out.source_id[0] = 0x42;
	out.peer_pid = 100;
	out.payload_digest[0] = 3;
	std::vector<op_spec> ops;
	ops.push_back({"record pending (new)", [](dir &) {},
	    [&](dir &d) { return d.record_delivery(in, delivery_phase::pending, true); },
	    [&](dir &d) { return phase_class(d, in, 0, 'p'); }});
	const char chain[] = {'p', 'a', 'i', 'x', 't'};
	for (int i = 1; i < 5; ++i) {
		char from = chain[i - 1], to = chain[i];
		ops.push_back({"advance guest phase", [&, i](dir &d) {
			for (int k = 0; k < i; ++k)
				CHECK(d.record_delivery(in, (delivery_phase)chain[k], k == 0));
		    }, [&, to](dir &d) { return d.record_delivery(in, (delivery_phase)to); },
		    [&, from, to](dir &d) { return phase_class(d, in, from, to); }});
	}
	ops.push_back({"retire terminal", [&](dir &d) {
		for (char p : chain)
			CHECK(d.record_delivery(in, (delivery_phase)p, p == 'p'));
	    }, [&](dir &d) { return d.retire_terminal_delivery(in); },
	    [&](dir &d) { return phase_class(d, in, 't', 0); }});
	ops.push_back({"outbound accept", [&](dir &d) {
		CHECK(d.record_delivery(out, delivery_phase::pending, true));
	    }, [&](dir &d) { return d.record_delivery(out, delivery_phase::accepted); },
	    [&](dir &d) { return phase_class(d, out, 'p', 'a'); }});
	ops.push_back({"outbound retire", [&](dir &d) {
		CHECK(d.record_delivery(out, delivery_phase::pending, true));
		CHECK(d.record_delivery(out, delivery_phase::accepted));
	    }, [&](dir &d) { return d.retire_accepted_outbound(out); },
	    [&](dir &d) { return phase_class(d, out, 'a', 0); }});
	durable_kill kill{4321, 42, 99, {}};
	kill.source_id[0] = 0x51;
	ops.push_back({"record kill", [](dir &) {},
	    [&](dir &d) { return d.record_kill(kill); },
	    [&](dir &d) {
		std::vector<durable_kill> k;
		if (!d.list_kills(k) || k.size() > 1) return (-1);
		return ((int)k.size());
	    }});
	ops.push_back({"record kill applied", [&](dir &d) {
		CHECK(d.record_kill(kill));
	    }, [&](dir &d) { return d.record_kill_applied(kill); },
	    [&](dir &d) {
		int a = d.kill_applied(kill);
		return (a < 0 ? -1 : a);
	    }});
	ops.push_back({"revoke source", [](dir &) {},
	    [&](dir &d) { return d.revoke_source(kill.source_id.data()); },
	    [&](dir &d) { return d.source_revoked(kill.source_id.data()); }});
	durable_cleanup cleanup{42, 99, 77};
	auto cleanup_class = [&](int from, int to) {
		return [&, from, to](dir &d) {
			int c = d.cleanup_status(cleanup);
			return (c == from ? 0 : c == to ? 1 : -1);
		};
	};
	ops.push_back({"cleanup pending", [](dir &) {},
	    [&](dir &d) { return d.record_cleanup_pending(cleanup); },
	    cleanup_class(0, 'p')});
	ops.push_back({"cleanup queued", [&](dir &d) {
		CHECK(d.record_cleanup_pending(cleanup));
	    }, [&](dir &d) { return d.record_cleanup_queued(cleanup); },
	    cleanup_class('p', 'a')});
	ops.push_back({"cleanup applied", [&](dir &d) {
		CHECK(d.record_cleanup_pending(cleanup));
		CHECK(d.record_cleanup_queued(cleanup));
	    }, [&](dir &d) { return d.record_cleanup_applied(cleanup); },
	    cleanup_class('a', 'g')});
	std::vector<unsigned char> elf = {0x7f, 'E', 'L', 'F', 1, 2, 3, 4, 5};
	uint8_t program[16] = {0x61}, source[16] = {0x62};
	ops.push_back({"publish identified spool", [](dir &) {},
	    [&](dir &d) {
		bool created;
		return d.write_identified_data(elf.data(), elf.size(), program,
		    &created, source);
	    },
	    [&](dir &d) {
		uint8_t digest[32], expected[32];
		SHA256(elf.data(), elf.size(), expected);
		if (!d.hash_identified_data(program, source, digest))
			return (errno == ENOENT ? 0 : -1);
		return (memcmp(digest, expected, 32) == 0 ? 1 : -1);
	    }});
	/* fresh-session stop fence (gate suspended by this stop's token) */
	durable_session_stop stop{};
	stop.token[0] = 0xa1;
	stop.source_session[0] = 0xb2;
	stop.vmid = 42;
	stop.epoch = 99;
	ops.push_back({"fresh-session stop fence", [&](dir &) {
		gate_suspended = true;
		memcpy(gate_token, stop.token.data(), 16);
	    }, [&](dir &d) { return d.begin_fresh_session_stop(stop); },
	    [&](dir &d) {
		durable_session_stop found{};
		int r = d.fresh_session_stop_for_vm(42, 99, found);
		if (r < 0) return (-1);
		if (r == 0) return (0);
		return (found.token == stop.token &&
		    found.source_session == stop.source_session ? 1 : -1);
	    }});
	/* guest kill rekey (old incarnation -> new) */
	durable_kill old_kill{4321, 42, 99, {}};
	old_kill.source_id[0] = 0x71;
	ops.push_back({"rekey guest kills", [&](dir &d) {
		CHECK(d.record_kill(old_kill));
	    }, [&](dir &d) { return d.rekey_guest_kills(42, 99, 43, 100); },
	    [&](dir &d) {
		std::vector<durable_kill> k;
		if (!d.list_kills(k) || k.size() != 1) return (-1);
		if (k[0].vmid == 42 && k[0].epoch == 99) return (0);
		if (k[0].vmid == 43 && k[0].epoch == 100 && k[0].pid == 4321) return (1);
		return (-1);
	    }});
	/* second kill joins an existing lineage */
	durable_kill second{4322, 42, 99, {}};
	second.source_id[0] = 0x72;
	ops.push_back({"record second kill", [&](dir &d) {
		CHECK(d.record_kill(old_kill));
	    }, [&](dir &d) { return d.record_kill(second); },
	    [&](dir &d) {
		std::vector<durable_kill> k;
		if (!d.list_kills(k) || k.empty() || k.size() > 2) return (-1);
		return ((int)k.size() - 1);
	    }});
	/* plain and source-bound spools */
	auto spool_class = [&](const char *suffix_hex) {
		return [&, suffix_hex](dir &d) {
			int found = 0, fd = openat(d.dirfd, ".", O_RDONLY | O_DIRECTORY);
			DIR *scan = fdopendir(fd);
			if (scan == nullptr) return (-1);
			while (struct dirent *e = __real_readdir(scan)) {
				if (strncmp(e->d_name, "elf.", 4) != 0) continue;
				if (suffix_hex != nullptr &&
				    strstr(e->d_name, suffix_hex) == nullptr) {
					found = -100;
					continue;
				}
				int f = openat(d.dirfd, e->d_name, O_RDONLY);
				unsigned char buf[64];
				ssize_t n = f >= 0 ? __real_read(f, buf, sizeof(buf)) : -1;
				if (f >= 0) __real_close(f);
				if (n != (ssize_t)elf.size() || memcmp(buf, elf.data(), n) != 0)
					found = -100;
				else
					++found;
			}
			closedir(scan);
			return (found == 0 ? 0 : found == 1 ? 1 : -1);
		};
	};
	ops.push_back({"publish plain spool", [](dir &) {},
	    [&](dir &d) { return d.write_data(elf.data(), elf.size()); },
	    spool_class(nullptr)});
	ops.push_back({"publish source-bound spool", [](dir &) {},
	    [&](dir &d) { return d.write_data_with_source(elf.data(), elf.size(),
		source); },
	    spool_class("62000000000000000000000000000000")});
	/* ---- host ingest consumer receipts (HCB1 cohort, HCR1 phases) ---- */
	durable_delivery ingress{};
	ingress.scope = 3;
	ingress.journal_version = 4;
	ingress.session_id[0] = 0x0a;
	ingress.delivery_id = 601;
	ingress.vmid = 7;
	ingress.epoch = 9;
	ingress.program_id[0] = 0xa1;
	ingress.source_id[0] = 0xb1;
	ingress.peer_uid = 0;
	ingress.peer_pid = 4242;
	ingress.payload_digest[0] = 0x44;
	durable_consumer_receipt member{};
	member.ingress = ingress;
	member.consumer_session[0] = 0xc1;
	member.consumer_uid = 0;
	member.consumer_pid = 5151;
	auto accepted_ingress = [&](dir &d) {
		CHECK(d.record_delivery(ingress, delivery_phase::pending, true));
		CHECK(d.record_delivery(ingress, delivery_phase::accepted));
	};
	auto cohort_class = [&](dir &d) {
		std::vector<durable_consumer_receipt> fixed;
		int c = d.consumer_cohort(ingress, {}, fixed);
		if (c < 0) return (-1);
		if (c == 0) return (0);
		return (fixed.size() == 1 &&
		    fixed[0].consumer_session == member.consumer_session ? 1 : -1);
	};
	auto receipt_class = [&](int from, int to) {
		return [&, from, to](dir &d) {
			std::vector<durable_consumer_receipt_state> r;
			if (!d.list_consumer_receipts(r) || r.size() > 1) return (-1);
			int phase = r.empty() ? 0 : (int)r[0].phase;
			return (phase == from ? 0 : phase == to ? 1 : -1);
		};
	};
	ops.push_back({"consumer cohort", accepted_ingress,
	    [&](dir &d) {
		std::vector<durable_consumer_receipt> fixed;
		return (d.consumer_cohort(ingress, {member}, fixed) == 1);
	    }, cohort_class});
	auto with_cohort = [&](dir &d) {
		accepted_ingress(d);
		std::vector<durable_consumer_receipt> fixed;
		CHECK(d.consumer_cohort(ingress, {member}, fixed) == 1);
	};
	ops.push_back({"consumer receipt pending", with_cohort,
	    [&](dir &d) {
		return (d.record_consumer_receipt(member,
		    consumer_receipt_phase::pending) ==
		    (int)consumer_receipt_phase::pending);
	    }, receipt_class(0, 'p')});
	ops.push_back({"recover consumer cohort", with_cohort,
	    [&](dir &d) {
		std::vector<durable_delivery_state> all;
		return (d.list_deliveries(all) && d.recover_consumer_cohorts(all));
	    }, receipt_class(0, 'p')});
	auto with_pending_receipt = [&](dir &d) {
		with_cohort(d);
		CHECK(d.record_consumer_receipt(member,
		    consumer_receipt_phase::pending) >= 0);
	};
	ops.push_back({"consumer receipt processed", with_pending_receipt,
	    [&](dir &d) {
		return (d.record_consumer_receipt(member,
		    consumer_receipt_phase::no_derived) ==
		    (int)consumer_receipt_phase::no_derived);
	    }, receipt_class('p', 'n')});
	ops.push_back({"consumer receipt executed", [&](dir &d) {
		with_pending_receipt(d);
		CHECK(d.record_consumer_receipt(member,
		    consumer_receipt_phase::no_derived) >= 0);
	    }, [&](dir &d) {
		return (d.record_consumer_receipt(member,
		    consumer_receipt_phase::executed_no_derived) ==
		    (int)consumer_receipt_phase::executed_no_derived);
	    }, receipt_class('n', 'N')});
	/* ---- refused publication: withdraw a pending token (spool absent) */
	durable_delivery orphan = out;
	orphan.delivery_id = 77;
	orphan.program_id[0] = 0x4e;
	ops.push_back({"withdraw pending token", [&](dir &d) {
		CHECK(d.record_delivery(orphan, delivery_phase::pending, true));
	    }, [&](dir &d) { return d.withdraw_pending_delivery(orphan); },
	    [&](dir &d) {
		int p = d.delivery_status(orphan);
		return (p == 'p' ? 0 : p == 0 ? 1 : -1);
	    }});
	/* ---- guest delivery rekey (exact record, new VM lifetime) ---- */
	ops.push_back({"rekey guest delivery", [&](dir &d) {
		CHECK(d.record_delivery(in, delivery_phase::pending, true));
	    }, [&](dir &d) {
		std::vector<durable_delivery_state> all;
		if (!d.list_deliveries(all) || all.size() != 1)
			return (false);
		return (d.rekey_guest_delivery(all[0], 43, 100));
	    }, [&](dir &d) {
		std::vector<durable_delivery_state> all;
		if (!d.list_deliveries(all) || all.size() != 1) return (-1);
		if (all[0].record.vmid == 42 && all[0].record.epoch == 99) return (0);
		return (all[0].record.vmid == 43 && all[0].record.epoch == 100 ? 1 : -1);
	    }});
	for (const auto &op : ops)
		sweep(op);
	test_temporary_unlink_retry(stop);
	test_cleanup_pending_refusal_not_durable();
	printf("journal-faults: %u operations, %u injection points, %u checks\n",
	    sweeps, points, harness_checks);
	return (0);
}
