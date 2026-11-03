/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Boundary shim for running the actual dtraced main() (dtraced.o) as a
 * disposable test process. This file defines no main(); it only wraps system
 * boundaries so that every fixed system location resolves inside the
 * private directory named by HT_ROOT:
 *
 *   /var/run/dtraced.pid      -> $HT_ROOT/dtraced.pid
 *   /var/ddtrace/sub.sock     -> $HT_ROOT/sub.sock (bind, remove, connect)
 *   /var/ddtrace              -> $HT_ROOT (O_NOFOLLOW open: the control
 *                                directory check)
 *
 * Fail-closed guards: any other open/mkdir/remove under /var, and any open
 * of a /dev node other than /dev/null (including the /dev/dtrace tree and
 * /dev/dttransport), fails with EACCES or ENOENT. execve never runs a
 * program: the re-exec and dtrace launch paths observe a failure or, for a
 * re-exec, flush counters and exit with status 73. daemon(3) never forks.
 *
 * Scenario controls (environment):
 *   HT_VM_GUEST      value of kern.vm_guest ("fail" makes sysctl fail)
 *   HT_PIDFILE       "exists" (EEXIST, other pid 4242) or "fail" (EACCES)
 *   HT_PIDWRITE      "fail" makes pidfile_write fail
 *   HT_DAEMON        "fail" makes daemon(3) fail
 *   HT_BIND          "fail" makes the control-socket bind fail
 *   HT_PEER_ROOT     "1" reports connected peers as uid 0 (LOCAL_PEERCRED)
 *   HT_ATTEST        "vmid:epoch:name" answers VM_GET_ATTESTATION on any
 *                    descriptor a forwarder passes (no vmm device is used)
 *   HT_VMDIR         emulated VMM/HyperTrace kernel state (multi-VM runs):
 *                    a VM is live while HT_VMDIR/vm.<vmid>.<epoch>.<name>
 *                    exists. VM_GET_ATTESTATION answers for a passed
 *                    descriptor whose inode is such a file (removing the
 *                    file models VMM destruction). /dev/dtrace/hypertrace
 *                    opens a private descriptor whose EPOCH_QUERY reports
 *                    that liveness and whose epoch gate (SUSPEND, RESUME,
 *                    GATE_QUERY) persists in HT_VMDIR/gate.<vmid>.<epoch>,
 *                    so it survives daemon restarts like kernel state.
 *                    HANDLE_QUERY answers "live" for any nonzero handle.
 *
 * Guest (minion) runs: open("/dev/dttransport") returns one end of a
 * socketpair served by a scripted driver thread in this process; no device
 * is opened. Its ioctls are answered from:
 *   HT_DTT_IDENTITY        "flags,vmid,epoch,old_vmid,old_epoch"
 *   HT_DTT_IDENTITY_AFTER  identity reported after SESSION_READY or COMMIT
 *                          (or after any record with HT_DTT_AFTER_ON=any)
 *   HT_DTT_CLEANUP         "flags,delivery,vmid,epoch,reserved"
 *   HT_DTT_CLEANUP_AFTER   cleanup state reported after the first record
 *                          the driver reads
 *   HT_DTT_BUSY            number of identity queries answered EAGAIN first
 *                          (ENXIO with HT_DTT_BUSY_ERRNO=ENXIO); an
 *                          unparsable identity is answered EIO
 *   HT_DTT_ANSWER          "1": answer VM-identity queries and accept each
 *                          complete guest ELF with a DTT_HOST_ELF receipt
 *   HT_DTT_HOST_DB         (with HT_DTT_ANSWER) file of guest uploads the
 *                          emulated host accepted and host programs injected
 *                          for the guest; DTT_INGRESS_STATUS (accepted or
 *                          absent) and DTT_STATUS (accepted with replay, or
 *                          unavailable) queries are answered from it
 *   HT_DTT_LOG             file receiving one line per record the guest
 *                          daemon writes to the transport ("kind delivery
 *                          vmid epoch"; with HT_DTT_LOG_IDS=1, ELF and
 *                          INSTALLED records add program and source IDs)
 *   HT_DTT_ACK             "1" (with HT_DTT_ANSWER): confirm each guest
 *                          KILL_APPLIED, INSTALLED and UNINSTALLED record
 *                          with the host's HOST_* acknowledgment
 *   HT_DTT_INJECT          path of a UNIX socket on which the driver accepts
 *                          host-side records to deliver to the guest daemon,
 *                          one command per line:
 *                            elf <delivery> <vmid> <epoch> <program32hex>
 *                                <source32hex> <file>   (chunked DTT_ELF)
 *                            kill <pid> <vmid> <epoch> <source32hex>
 *                            cleanup <delivery> <vmid> <epoch>
 *                            host-status <query> <delivery> <vmid> <epoch>
 *                                <phase> <revoked> <replay>
 *                          and answers "ok" or "error" per command
 *   HT_FAULT_FILE          scoped fault injection: when this file exists as
 *                          "sys N [entry]" or "oom N [entry]" at the start
 *                          of a matching entry point (entry: handle (the
 *                          default, client_request::handle), read_data,
 *                          send_elf, send_kill, send_cleanup, send_info,
 *                          process_inbound, process_outbound, process_base,
 *                          initialize (startup), finalize (shutdown)),
 *                          the N-th file-system call (openat, open, fsync,
 *                          renameat, linkat, unlinkat, fstat, fstatat,
 *                          mkdirat, read, pread, write, readdir, fdopendir,
 *                          flock, close, ioctl, pthread_create) or the N-th
 *                          allocation
 *                          (operator new) made by that thread inside that
 *                          entry fails (EIO, or std::bad_alloc). The file is
 *                          consumed; "<file>.fired" receives the failed
 *                          call's name. Other threads are never affected.
 *   HT_CALL_FAULT          process-wide call faults for any thread:
 *                          "name:n[,name:n...]" makes the n-th call (from
 *                          1) of that function fail once with EIO (kqueue,
 *                          kevent, listen, socket, accept4, fcntl, pdwait,
 *                          pdkill, pdfork, pipe2, socketpair, setsockopt,
 *                          poll, send, recv, recvmsg, shutdown,
 *                          getsockopt); "<HT_FAULT_FILE>.fired" names it
 *   HT_ENTRY_LOG           file receiving the name of each fault entry point
 *                          a run reaches (once per name)
 *   HT_PD_BIRTH            "1": answer PDIOC_GET_BIRTH_IDENTITY for process
 *                          descriptors (pid from pdgetpid, a fixed start
 *                          time), for kernels without that ioctl
 *   HT_EXEC_LOG            file receiving "path argv..." for each program a
 *                          launch would execute (the launch still fails,
 *                          or with HT_EXEC_FAKE=1 the child exits 0 instead
 *                          of executing anything; HT_EXEC_FAKE=report also
 *                          answers dtrace(1)'s launch report as installed
 *                          and runs HT_EXEC_FAKE_HOLD_MS before exiting)
 *   HT_EXEC_DTRACE         program that a launch of /usr/sbin/dtrace runs
 *                          instead, with the same arguments and environment
 *                          plus HT_DTRACE_SOCKET=<HT_ROOT>/sub.sock
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/procdesc.h>
#include <sys/un.h>
#include <dirent.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <sys/event.h>
#include <pthread.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <libutil.h>
#include <string>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <amd64/include/vmm_dev.h>
#include <dttransport.h>
#include <openssl/sha.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>
#include "dtraced.h"
#include "dtraced_wire.h"

extern "C" int __llvm_profile_write_file(void) __attribute__((weak));

static std::string
root_path(const char *leaf)
{
	const char *root = getenv("HT_ROOT");
	if (root == nullptr || strncmp(root, "/tmp/", 5) != 0)
		abort();	/* never run without a private root */
	return (std::string(root) + "/" + leaf);
}

static bool
env_is(const char *name, const char *value)
{
	const char *v = getenv(name);
	return (v != nullptr && strcmp(v, value) == 0);
}

static bool
forbidden(const char *path)
{
	if (strncmp(path, "/var/", 5) == 0 || strcmp(path, "/var") == 0)
		return (true);
	if (strncmp(path, "/dev/", 5) == 0 && strcmp(path, "/dev/null") != 0)
		return (true);
	return (false);
}

extern "C" int __real_sysctlbyname(const char *, void *, size_t *, const void *,
    size_t);
extern "C" int
__wrap_sysctlbyname(const char *name, void *old, size_t *oldlen, const void *n,
    size_t nlen)
{
	if (strcmp(name, "kern.vm_guest") == 0) {
		const char *v = getenv("HT_VM_GUEST");
		if (v == nullptr)
			v = "none";
		if (strcmp(v, "fail") == 0) {
			errno = ENOENT;
			return (-1);
		}
		size_t len = strlen(v) + 1;
		if (old == nullptr || *oldlen < len) {
			errno = ENOMEM;
			return (-1);
		}
		memcpy(old, v, len);
		*oldlen = len;
		return (0);
	}
	return (__real_sysctlbyname(name, old, oldlen, n, nlen));
}

extern "C" struct pidfh *__real_pidfile_open(const char *, mode_t, pid_t *);
extern "C" struct pidfh *
__wrap_pidfile_open(const char *path, mode_t mode, pid_t *other)
{
	if (env_is("HT_PIDFILE", "exists")) {
		*other = 4242;
		errno = EEXIST;
		return (nullptr);
	}
	if (env_is("HT_PIDFILE", "fail")) {
		errno = EACCES;
		return (nullptr);
	}
	if (strcmp(path, "/var/run/dtraced.pid") != 0)
		abort();
	return (__real_pidfile_open(root_path("dtraced.pid").c_str(), mode, other));
}

extern "C" int __real_pidfile_write(struct pidfh *);
extern "C" int
__wrap_pidfile_write(struct pidfh *pfh)
{
	if (env_is("HT_PIDWRITE", "fail")) {
		errno = EIO;
		return (-1);
	}
	return (__real_pidfile_write(pfh));
}

extern "C" int
__wrap_daemon(int, int)
{
	if (env_is("HT_DAEMON", "fail")) {
		errno = EPERM;
		return (-1);
	}
	return (0);	/* stay in the foreground under the test driver */
}

/* ---- scripted guest transport ---- */
extern "C" int __real_open(const char *, int, ...);
extern "C" int __real_bind(int, const struct sockaddr *, socklen_t);
/* The shim's own sockets bypass the call-fault wrappers. */
extern "C" int __real_socket(int, int, int);
extern "C" int __real_listen(int, int);
extern "C" int __real_socketpair(int, int, int, int *);
extern "C" int __real_fcntl(int, int, ...);
static std::mutex dtt_mtx;
static int dtt_daemon_fd = -1, dtt_driver_fd = -1;
static std::atomic<bool> dtt_after{false}, dtt_cleanup_after{false};
static std::atomic<int> dtt_busy{0};

static bool
parse_identity(const char *spec, struct dtt_vm_identity &id)
{
	unsigned flags, vmid, old_vmid;
	unsigned long long epoch, old_epoch;
	if (spec == nullptr || sscanf(spec, "%u,%u,%llu,%u,%llu", &flags, &vmid,
	    &epoch, &old_vmid, &old_epoch) != 5)
		return (false);
	id = {};
	id.flags = flags;
	id.vmid = (uint16_t)vmid;
	id.epoch = epoch;
	id.old_vmid = (uint16_t)old_vmid;
	id.old_epoch = old_epoch;
	return (true);
}

static bool
parse_cleanup(const char *spec, struct dtt_cleanup_state &c)
{
	unsigned flags, vmid, reserved;
	unsigned long long delivery, epoch;
	c = {};
	if (spec == nullptr)
		return (true);
	if (sscanf(spec, "%u,%llu,%u,%llu,%u", &flags, &delivery, &vmid, &epoch,
	    &reserved) != 5)
		return (false);
	c.flags = (uint16_t)flags;
	c.delivery_id = delivery;
	c.vmid = (uint16_t)vmid;
	c.epoch = epoch;
	c.reserved = reserved;
	return (true);
}

static std::mutex dtt_send_mtx;

static void
driver_send(int fd, const dtt_entry_t &e)
{
	std::lock_guard lock(dtt_send_mtx);
	size_t off = 0;
	while (off < sizeof(e)) {
		ssize_t n = write(fd, (const char *)&e + off, sizeof(e) - off);
		if (n <= 0)
			return;
		off += (size_t)n;
	}
}

/* HT_DTT_HOST_DB: the emulated host daemon's accepted guest uploads, one
 * line per HOST_ELF receipt ("delivery program source digest", hex), kept
 * in a file so it outlives guest daemon incarnations. */
static void
hexs(char *out, const uint8_t *in, size_t n)
{
	for (size_t i = 0; i < n; i++)
		snprintf(out + i * 2, 3, "%02x", in[i]);
}

/* tag "in": a guest upload the host accepted; "out": a host program
 * delivered to the guest (queued by bhyve, so the host record is accepted) */
static void
host_db_remember(const char *tag, uint64_t delivery, const uint8_t program_id[16],
    const uint8_t source_id[16], const uint8_t digest_bytes[32])
{
	const char *db = getenv("HT_DTT_HOST_DB");
	if (db == nullptr)
		return;
	char program[33], source[33], digest[65];
	hexs(program, program_id, 16);
	hexs(source, source_id, 16);
	hexs(digest, digest_bytes, 32);
	FILE *f = fopen(db, "a");
	if (f == nullptr)
		return;
	fprintf(f, "%s %016jx %s %s %s\n", tag, (uintmax_t)delivery, program,
	    source, digest);
	fclose(f);
}

static void
host_ingest_remember(const dtt_entry_t &r)
{
	host_db_remember("in", r.u.installed.delivery_id,
	    r.u.installed.program_id, r.u.installed.source_id,
	    r.u.installed.digest);
}

static bool
host_db_lookup(const char *tag, dtt_entry_t &r)
{
	const char *db = getenv("HT_DTT_HOST_DB");
	FILE *f = db == nullptr ? nullptr : fopen(db, "r");
	if (f == nullptr)
		return (false);
	char want[4 + 16 + 1 + 32 + 1 + 32 + 1], program[33], source[33];
	hexs(program, r.u.installed.program_id, 16);
	hexs(source, r.u.installed.source_id, 16);
	snprintf(want, sizeof(want), "%s %016jx %s %s", tag,
	    (uintmax_t)r.u.installed.delivery_id, program, source);
	char line[256];
	bool found = false;
	while (fgets(line, sizeof(line), f) != nullptr) {
		if (strncmp(line, want, strlen(want)) != 0)
			continue;
		const char *hex = line + strlen(want) + 1;
		for (size_t i = 0; i < 32; i++) {
			unsigned v;
			if (sscanf(hex + i * 2, "%2x", &v) != 1)
				break;
			r.u.installed.digest[i] = (uint8_t)v;
		}
		found = true;
	}
	fclose(f);
	return (found);
}

static void
dtt_driver(int fd)
{
	const char *log = getenv("HT_DTT_LOG");
	const bool answer = env_is("HT_DTT_ANSWER", "1");
	std::vector<unsigned char> assembly;
	for (;;) {
		dtt_entry_t e;
		size_t off = 0;
		while (off < sizeof(e)) {
			ssize_t n = read(fd, (char *)&e + off, sizeof(e) - off);
			if (n <= 0)
				return;
			off += (size_t)n;
		}
		if (answer && e.event_kind == DTT_VM_IDENTITY_QUERY) {
			/* bhyve answers with the current incarnation */
			struct dtt_vm_identity id;
			if (parse_identity(getenv("HT_DTT_IDENTITY"), id)) {
				dtt_entry_t r{};
				r.event_kind = DTT_VM_IDENTITY;
				r.u.installed.query_id = e.u.installed.query_id;
				r.u.installed.vmid = id.vmid;
				r.u.installed.epoch = id.epoch;
				driver_send(fd, r);
			}
		}
		if (answer && e.event_kind == DTT_ELF && e.u.elf.len <= DTT_MAXDATALEN) {
			/* the host accepts the complete identified ELF */
			assembly.insert(assembly.end(), e.u.elf.data,
			    e.u.elf.data + e.u.elf.len);
			if (!e.u.elf.hasmore) {
				dtt_entry_t r{};
				r.event_kind = DTT_HOST_ELF;
				r.u.installed.delivery_id = e.u.elf.delivery_id;
				r.u.installed.vmid = e.u.elf.vmid;
				r.u.installed.epoch = e.u.elf.epoch;
				memcpy(r.u.installed.program_id, e.u.elf.program_id, 16);
				memcpy(r.u.installed.source_id, e.u.elf.source_id, 16);
				SHA256(assembly.data(), assembly.size(), r.u.installed.digest);
				assembly.clear();
				host_ingest_remember(r);
				driver_send(fd, r);
			}
		}
		const bool host_db = getenv("HT_DTT_HOST_DB") != nullptr;
		if (answer && host_db && e.event_kind == DTT_INGRESS_STATUS) {
			/* the host daemon's ingest phase for the guest's token:
			 * accepted (with its digest) or absent */
			dtt_entry_t r{};
			r.event_kind = DTT_HOST_INGRESS_STATUS;
			r.u.installed.query_id = e.u.installed.query_id;
			r.u.installed.delivery_id = e.u.installed.delivery_id;
			memcpy(r.u.installed.program_id, e.u.installed.program_id, 16);
			memcpy(r.u.installed.source_id, e.u.installed.source_id, 16);
			struct dtt_vm_identity id;
			if (parse_identity(getenv("HT_DTT_IDENTITY"), id)) {
				r.u.installed.vmid = id.vmid;
				r.u.installed.epoch = id.epoch;
			}
			if (host_db_lookup("in", r))
				r.u.installed.phase = 'a';
			driver_send(fd, r);
		}
		if (answer && host_db && (e.event_kind == DTT_REKEY_DELIVERY_QUERY ||
		    e.event_kind == DTT_REKEY_INGRESS_QUERY ||
		    e.event_kind == DTT_REKEY_KILL_QUERY)) {
			/* the host's receipt for a record of the restored VM's
			 * previous lifetime (guest journal rekey) */
			dtt_entry_t r{};
			r.u.installed = e.u.installed;
			r.u.installed.replay = 0;
			bool kill = e.event_kind == DTT_REKEY_KILL_QUERY;
			r.event_kind = e.event_kind == DTT_REKEY_DELIVERY_QUERY ?
			    DTT_REKEY_DELIVERY_RECEIPT :
			    e.event_kind == DTT_REKEY_INGRESS_QUERY ?
			    DTT_REKEY_INGRESS_RECEIPT : DTT_REKEY_KILL_RECEIPT;
			bool known = host_db_lookup(kill ? "kill" :
			    e.event_kind == DTT_REKEY_INGRESS_QUERY ? "in" : "out", r);
			if (!known) {
				r.u.installed.phase = 'u';
				r.u.installed.revoked = 0;
				memset(r.u.installed.digest, 0, 32);
			} else if (kill) {
				r.u.installed.phase = 'a';
				r.u.installed.revoked = 1;
				memset(r.u.installed.digest, 0, 32);
			} else {
				r.u.installed.phase = 'a';
				r.u.installed.revoked = 0;
				memcpy(r.u.installed.digest, e.u.installed.digest, 32);
			}
			driver_send(fd, r);
		}
		if (answer && host_db && e.event_kind == DTT_STATUS) {
			/* the host's record of a program it delivered: accepted,
			 * replay granted with the exact digest; unknown tokens are
			 * answered "control socket unavailable" */
			dtt_entry_t r{};
			r.event_kind = DTT_HOST_STATUS;
			r.u.installed = e.u.installed;
			memset(r.u.installed.digest, 0, sizeof(r.u.installed.digest));
			r.u.installed.revoked = 0;
			r.u.installed.replay = 0;
			if (host_db_lookup("out", r)) {
				r.u.installed.phase = 'a';
				r.u.installed.replay = 1;
			} else {
				r.u.installed.phase = 'u';
				memset(r.u.installed.digest, 0,
				    sizeof(r.u.installed.digest));
			}
			driver_send(fd, r);
		}
		if (answer && (e.event_kind == DTT_KILL_APPLIED ||
		    e.event_kind == DTT_INSTALLED || e.event_kind == DTT_UNINSTALLED) &&
		    env_is("HT_DTT_ACK", "1")) {
			/* the host daemon persists the observation and confirms it */
			dtt_entry_t r = e;
			r.event_kind = e.event_kind == DTT_KILL_APPLIED ?
			    DTT_HOST_KILL_APPLIED : e.event_kind == DTT_INSTALLED ?
			    DTT_HOST_INSTALLED : DTT_HOST_UNINSTALLED;
			driver_send(fd, r);
		}
		if (e.event_kind == DTT_SESSION_READY ||
		    env_is("HT_DTT_AFTER_ON", "any"))
			dtt_after.store(true);
		dtt_cleanup_after.store(true);
		if (log != nullptr) {
			FILE *f = fopen(log, "a");
			if (f != nullptr) {
				fprintf(f, "%u %ju %u %ju", e.event_kind,
				    (uintmax_t)e.u.cleanup.delivery_id,
				    e.u.cleanup.vmid, (uintmax_t)e.u.cleanup.epoch);
				const uint8_t *ids =
				    e.event_kind == DTT_INSTALLED ?
				    e.u.installed.program_id :
				    e.event_kind == DTT_ELF ? e.u.elf.program_id :
				    nullptr;
				const uint8_t *source =
				    e.event_kind == DTT_INSTALLED ?
				    e.u.installed.source_id :
				    e.event_kind == DTT_ELF ? e.u.elf.source_id :
				    nullptr;
				if (ids != nullptr && env_is("HT_DTT_LOG_IDS", "1")) {
					fputc(' ', f);
					for (int i = 0; i < 16; i++)
						fprintf(f, "%02x", ids[i]);
					fputc(' ', f);
					for (int i = 0; i < 16; i++)
						fprintf(f, "%02x", source[i]);
				}
				fputc('\n', f);
				fclose(f);
			}
		}
	}
}

static bool
parse_hex16(const char *text, uint8_t out[16])
{
	if (text == nullptr || strlen(text) != 32)
		return (false);
	for (int i = 0; i < 16; i++) {
		unsigned v;
		if (sscanf(text + 2 * i, "%2x", &v) != 1)
			return (false);
		out[i] = (uint8_t)v;
	}
	return (true);
}

/* Host-side records for the guest daemon (HT_DTT_INJECT). */
static bool
inject_command(int daemon_side, const char *line)
{
	char verb[16] = {}, a[64] = {}, b[64] = {}, c[64] = {}, d[64] = {},
	    e5[64] = {}, f6[512] = {}, g7[64] = {};
	int n = sscanf(line, "%15s %63s %63s %63s %63s %63s %511s %63s", verb, a,
	    b, c, d, e5, f6, g7);
	dtt_entry_t r{};
	if (strcmp(verb, "elf") == 0 && n == 7) {
		std::vector<unsigned char> data;
		int fd = __real_open(f6, O_RDONLY);
		if (fd < 0)
			return (false);
		unsigned char buf[4096];
		ssize_t got;
		while ((got = read(fd, buf, sizeof(buf))) > 0)
			data.insert(data.end(), buf, buf + got);
		close(fd);
		uint32_t identifier = arc4random();
		size_t off = 0;
		do {
			dtt_entry_t x{};
			size_t len = data.size() - off;
			if (len > DTT_MAXDATALEN)
				len = DTT_MAXDATALEN;
			x.event_kind = DTT_ELF;
			x.u.elf.len = len;
			x.u.elf.totallen = data.size();
			x.u.elf.identifier = identifier;
			x.u.elf.delivery_id = strtoull(a, nullptr, 0);
			x.u.elf.vmid = (uint16_t)strtoul(b, nullptr, 0);
			x.u.elf.epoch = strtoull(c, nullptr, 0);
			if (!parse_hex16(d, x.u.elf.program_id) ||
			    !parse_hex16(e5, x.u.elf.source_id))
				return (false);
			memcpy(x.u.elf.data, data.data() + off, len);
			off += len;
			x.u.elf.hasmore = off < data.size();
			driver_send(daemon_side, x);
		} while (off < data.size());
		dtt_entry_t k{};
		k.u.installed.delivery_id = strtoull(a, nullptr, 0);
		if (!parse_hex16(d, k.u.installed.program_id) ||
		    !parse_hex16(e5, k.u.installed.source_id))
			return (false);
		SHA256(data.data(), data.size(), k.u.installed.digest);
		host_db_remember("out", k.u.installed.delivery_id,
		    k.u.installed.program_id, k.u.installed.source_id,
		    k.u.installed.digest);
		return (true);
	}
	if (strcmp(verb, "kill") == 0 && n == 5) {
		r.event_kind = DTT_KILL;
		r.u.kill.pid = (pid_t)strtol(a, nullptr, 0);
		r.u.kill.vmid = (uint16_t)strtoul(b, nullptr, 0);
		r.u.kill.epoch = strtoull(c, nullptr, 0);
		if (!parse_hex16(d, r.u.kill.source_id))
			return (false);
		{
			/* the host's KILL record (rekey receipts name the pid
			 * as the delivery and carry no program or digest) */
			const uint8_t zero[32] = {};
			host_db_remember("kill", (uint64_t)r.u.kill.pid, zero,
			    r.u.kill.source_id, zero);
		}
		driver_send(daemon_side, r);
		return (true);
	}
	if (strcmp(verb, "cleanup") == 0 && n == 4) {
		r.event_kind = DTT_CLEANUP_DTRACED;
		r.u.cleanup.delivery_id = strtoull(a, nullptr, 0);
		r.u.cleanup.vmid = (uint16_t)strtoul(b, nullptr, 0);
		r.u.cleanup.epoch = strtoull(c, nullptr, 0);
		driver_send(daemon_side, r);
		return (true);
	}
	if (strcmp(verb, "host-status") == 0 && n == 8) {
		r.event_kind = DTT_HOST_STATUS;
		r.u.installed.query_id = strtoull(a, nullptr, 0);
		r.u.installed.delivery_id = strtoull(b, nullptr, 0);
		r.u.installed.vmid = (uint16_t)strtoul(c, nullptr, 0);
		r.u.installed.epoch = strtoull(d, nullptr, 0);
		r.u.installed.phase = (uint8_t)strtoul(e5, nullptr, 0);
		r.u.installed.revoked = (uint8_t)strtoul(f6, nullptr, 0);
		r.u.installed.replay = (uint8_t)strtoul(g7, nullptr, 0);
		driver_send(daemon_side, r);
		return (true);
	}
	return (false);
}

static void
inject_listener(int daemon_side)
{
	const char *path = getenv("HT_DTT_INJECT");
	int ls = __real_socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sa{};
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
	(void)unlink(path);
	if (ls < 0 || __real_bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    __real_listen(ls, 4) != 0)
		return;
	for (;;) {
		int c = accept(ls, nullptr, nullptr);
		if (c < 0)
			return;
		std::string line;
		char ch;
		while (read(c, &ch, 1) == 1) {
			if (ch != '\n') {
				line += ch;
				continue;
			}
			bool ok = inject_command(daemon_side, line.c_str());
			(void)write(c, ok ? "ok\n" : "error\n", ok ? 3 : 6);
			line.clear();
		}
		close(c);
	}
}

static int
open_transport(int flags)
{
	int sv[2];
	if (__real_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
		return (-1);
	if ((flags & O_NONBLOCK) != 0)
		(void)__real_fcntl(sv[0], F_SETFL, O_NONBLOCK);
	{
		std::lock_guard lock(dtt_mtx);
		dtt_daemon_fd = sv[0];
		dtt_driver_fd = sv[1];
	}
	const char *busy = getenv("HT_DTT_BUSY");
	dtt_busy.store(busy != nullptr ? atoi(busy) : 0);
	std::thread(dtt_driver, sv[1]).detach();
	if (getenv("HT_DTT_INJECT") != nullptr)
		std::thread(inject_listener, sv[1]).detach();
	return (sv[0]);
}

static int
transport_ioctl(unsigned long request, void *arg)
{
	if (request == DTT_GET_VM_IDENTITY) {
		if (dtt_busy.load() > 0) {
			dtt_busy.fetch_sub(1);
			errno = env_is("HT_DTT_BUSY_ERRNO", "ENXIO") ? ENXIO : EAGAIN;
			return (-1);
		}
		struct dtt_vm_identity id;
		const char *after = getenv("HT_DTT_IDENTITY_AFTER");
		if (!parse_identity(dtt_after.load() && after != nullptr ? after :
		    getenv("HT_DTT_IDENTITY"), id)) {
			errno = EIO;
			return (-1);
		}
		memcpy(arg, &id, sizeof(id));
		return (0);
	}
	if (request == DTT_GET_CLEANUP_STATE) {
		struct dtt_cleanup_state c;
		const char *after = getenv("HT_DTT_CLEANUP_AFTER");
		if (!parse_cleanup(dtt_cleanup_after.load() && after != nullptr ?
		    after : getenv("HT_DTT_CLEANUP"), c)) {
			errno = ENXIO;
			return (-1);
		}
		memcpy(arg, &c, sizeof(c));
		return (0);
	}
	if (request == DTT_COMMIT_VM_REKEY) {
		dtt_after.store(true);
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

/* ---- request-scoped fault injection (HT_FAULT_FILE) ---- */
namespace dtraced { class dir; }
#include <new>
extern "C" int __real_open(const char *, int, ...);
static thread_local int fault_kind;	/* 0 none, 1 sys, 2 oom */
static thread_local long fault_countdown = -1;
static thread_local bool fault_in_request;
static thread_local bool fault_suspended;	/* inside the shim's own I/O */

/* The emulated kernel and other shim helpers use wrapped calls; they are not
 * daemon code and must never consume or receive an injected fault. */
struct shim_scope {
	bool previous;
	shim_scope() : previous(fault_suspended) { fault_suspended = true; }
	~shim_scope() { fault_suspended = previous; }
};

static void
fault_report(const char *call)
{
	std::string path = std::string(getenv("HT_FAULT_FILE")) + ".fired";
	int fd = __real_open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd >= 0) {
		(void)write(fd, call, strlen(call));
		(void)write(fd, "\n", 1);
		close(fd);
	}
}

static bool
fault_hit(int kind, const char *call)
{
	if (!fault_in_request || fault_suspended || fault_kind != kind ||
	    fault_countdown < 0)
		return (false);
	if (fault_countdown-- != 0)
		return (false);
	fault_kind = 0;
	fault_report(call);
	return (true);
}

/* Arm from the control file when this entry point matches it ("kind N" or
 * "kind N entry"; no entry name means "handle"). Nested entry points run in
 * the armed scope and keep counting. Returns true when this call opened the
 * scope. */
static thread_local int fault_depth, fault_armed_depth;

static void
fault_note_entry(const char *entry)
{
	/* HT_ENTRY_LOG: which entry points a run reaches, once per name and
	 * process, so a sweep only targets entries its step executes. */
	static std::mutex mtx;
	static std::vector<std::string> seen;
	const char *log = getenv("HT_ENTRY_LOG");
	if (log == nullptr)
		return;
	std::lock_guard lock(mtx);
	for (const auto &name : seen)
		if (name == entry)
			return;
	seen.emplace_back(entry);
	fault_suspended = true;
	int fd = __real_open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd >= 0) {
		std::string line = std::string(entry) + "\n";
		(void)write(fd, line.data(), line.size());
		close(fd);
	}
	fault_suspended = false;
}

static void
fault_enter(const char *entry)
{
	fault_note_entry(entry);
	++fault_depth;
	fault_in_request = true;
	if (fault_armed_depth != 0)
		return;
	const char *control = getenv("HT_FAULT_FILE");
	if (control == nullptr)
		return;
	char spec[96] = {};
	fault_suspended = true;
	int fd = __real_open(control, O_RDONLY);
	if (fd >= 0) {
		(void)read(fd, spec, sizeof(spec) - 1);
		close(fd);
	}
	fault_suspended = false;
	if (fd < 0)
		return;
	char kind[8] = {}, name[48] = "handle";
	long n = -1;
	int fields = sscanf(spec, "%7s %ld %47s", kind, &n, name);
	if (fields < 2 || n < 0 || strcmp(name, entry) != 0)
		return;
	(void)unlink(control);
	fault_kind = strcmp(kind, "oom") == 0 ? 2 : strcmp(kind, "sys") == 0 ? 1 : 0;
	fault_countdown = n;
	fault_armed_depth = fault_depth;
}

static void
fault_leave(void)
{
	if (fault_depth == fault_armed_depth) {
		fault_armed_depth = 0;
		fault_kind = 0;
	}
	if (--fault_depth == 0)
		fault_in_request = false;
}

static thread_local const char *fault_entry_current;	/* innermost entry */

struct fault_entry_scope {
	const char *outer;
	fault_entry_scope(const char *entry) : outer(fault_entry_current)
	{
		fault_entry_current = entry;
		fault_enter(entry);
	}
	~fault_entry_scope()
	{
		fault_leave();
		fault_entry_current = outer;
	}
};

#define FAULT_ENTRY(mangled, entry, ret, proto, args) \
	extern "C" ret __real_##mangled proto; \
	extern "C" ret __wrap_##mangled proto { \
		fault_entry_scope scope(entry); \
		return (__real_##mangled args); \
	}
FAULT_ENTRY(_ZN7dtraced14client_request6handleEv, "handle", bool,
    (void *self), (self))
FAULT_ENTRY(_ZN7dtraced3job8send_elfEv, "send_elf", bool, (void *self), (self))
FAULT_ENTRY(_ZN7dtraced3job9send_killERNS_5stateE, "send_kill", bool,
    (void *self, void *st), (self, st))
FAULT_ENTRY(_ZN7dtraced3job12send_cleanupERNS_5stateE, "send_cleanup", bool,
    (void *self, void *st), (self, st))
FAULT_ENTRY(_ZN7dtraced3job9send_infoERNS_5stateE, "send_info", bool,
    (void *self, void *st), (self, st))
FAULT_ENTRY(_ZN7dtraced3job9read_dataERNS_5stateE, "read_data", bool,
    (void *self, void *st), (self, st))
FAULT_ENTRY(_ZN7dtraced5state10initializeEiiiPPKcS2_S2_, "initialize", bool,
    (void *self, int ctrl, int nosha, int threads, const char **argv,
    const char *priv, const char *peer), (self, ctrl, nosha, threads, argv, priv, peer))
FAULT_ENTRY(_ZN7dtraced5state8finalizeEv, "finalize", bool, (void *self), (self))

/* Journal-operation entry points (dir methods called across objects).
 * These register-forwarding wrappers are valid for the amd64 SysV ABI and
 * only for methods whose arguments (with this and any hidden return slot)
 * are at most six integer-class values; every method listed qualifies. */
#define FAULT_DIR(mangled, entry) \
	extern "C" uint64_t __real_##mangled(uint64_t, uint64_t, uint64_t, \
	    uint64_t, uint64_t, uint64_t); \
	extern "C" uint64_t __wrap_##mangled(uint64_t a, uint64_t b, uint64_t c, \
	    uint64_t d, uint64_t e, uint64_t f) { \
		fault_entry_scope scope(entry); \
		return (__real_##mangled(a, b, c, d, e, f)); \
	}
FAULT_DIR(_ZN7dtraced3dir15record_deliveryERKNS_16durable_deliveryENS_14delivery_phaseEb, "record_delivery")
FAULT_DIR(_ZN7dtraced3dir11record_killERKNS_12durable_killERKNSt3__18functionIFbRKNS4_6vectorIS1_NS4_9allocatorIS1_EEEEEEE, "record_kill")
FAULT_DIR(_ZN7dtraced3dir19record_kill_appliedERKNS_12durable_killE, "record_kill_applied")
FAULT_DIR(_ZN7dtraced3dir13revoke_sourceEPKh, "revoke_source")
FAULT_DIR(_ZN7dtraced3dir22write_data_with_sourceEPKhmS2_, "write_data_with_source")
FAULT_DIR(_ZN7dtraced3dir10write_dataEPhm, "write_data")
FAULT_DIR(_ZN7dtraced3dir22record_cleanup_pendingERKNS_15durable_cleanupE, "record_cleanup_pending")
FAULT_DIR(_ZN7dtraced3dir21record_cleanup_queuedERKNS_15durable_cleanupE, "record_cleanup_queued")
FAULT_DIR(_ZN7dtraced3dir22record_cleanup_appliedERKNS_15durable_cleanupE, "record_cleanup_applied")
FAULT_DIR(_ZN7dtraced3dir23record_consumer_receiptERKNS_24durable_consumer_receiptENS_22consumer_receipt_phaseE, "record_consumer_receipt")
FAULT_DIR(_ZN7dtraced3dir25record_consumer_executionERKNS_24durable_consumer_receiptENS_22consumer_receipt_phaseEb, "record_consumer_execution")
FAULT_DIR(_ZN7dtraced3dir23record_consumer_programERKNS_24durable_consumer_receiptERKNS_9client_fdE, "record_consumer_program")
FAULT_DIR(_ZN7dtraced3dir24begin_fresh_session_stopERKNS_20durable_session_stopE, "begin_fresh_session_stop")
FAULT_DIR(_ZN7dtraced3dir27complete_fresh_session_stopERS0_RKNS_20durable_session_stopE, "complete_fresh_session_stop")
FAULT_DIR(_ZN7dtraced3dir25retire_fresh_session_acksERKNS_20durable_session_stopE, "retire_fresh_session_acks")
FAULT_DIR(_ZN7dtraced3dir26release_fresh_session_gateERKNS_20durable_session_stopE, "release_fresh_session_gate")
FAULT_DIR(_ZN7dtraced3dir24retire_terminal_deliveryERKNS_16durable_deliveryE, "retire_terminal_delivery")
FAULT_DIR(_ZN7dtraced3dir24retire_accepted_outboundERKNS_16durable_deliveryE, "retire_accepted_outbound")
FAULT_DIR(_ZN7dtraced3dir24recover_consumer_cohortsERKNSt3__16vectorINS_22durable_delivery_stateENS1_9allocatorIS3_EEEE, "recover_consumer_cohorts")
FAULT_DIR(_ZN7dtraced3dir27recover_consumer_executionsERKNSt3__16vectorINS_30durable_consumer_receipt_stateENS1_9allocatorIS3_EEEE, "recover_consumer_executions")
FAULT_DIR(_ZN7dtraced3dir24recover_consumer_processERKNS_24durable_consumer_receiptERNS_24collector_owner_registryE, "recover_consumer_process")
FAULT_DIR(_ZN7dtraced3dir24queue_recovered_consumerEPNS_9client_fdE, "queue_recovered_consumer")
FAULT_DIR(_ZN7dtraced3dir24queue_recovered_outboundERKNS_16durable_deliveryEtm, "queue_recovered_outbound")
FAULT_DIR(_ZN7dtraced3dir25guest_rekey_pair_completeERS0_tmtm, "guest_rekey_pair_complete")
FAULT_DIR(_ZN7dtraced3dir25checkpoint_collector_exitERKNSt3__15arrayIhLm96EEERNS_24collector_owner_registryE, "checkpoint_collector_exit")

/* HT_REVOKED_CHECK_HOLD=<path>: once <path> exists, the next
 * dir::source_revoked() answer to a client request is held: the wrapper removes <path>, creates
 * <path>.held and waits up to 3 s for <path>.release.  A KILL injected
 * meanwhile lands between a guest upload's revocation check and its
 * publication (client_request::handle_elfmsg()). */
extern "C" int __real__ZN7dtraced3dir14source_revokedEPKh(void *,
    const uint8_t *);
extern "C" int
__wrap__ZN7dtraced3dir14source_revokedEPKh(void *self, const uint8_t *source)
{
	int revoked = __real__ZN7dtraced3dir14source_revokedEPKh(self, source);
	const char *hold = getenv("HT_REVOKED_CHECK_HOLD");
	if (hold == nullptr || fault_entry_current == nullptr ||
	    strcmp(fault_entry_current, "handle") != 0 || unlink(hold) != 0)
		return (revoked);
	int error = errno;
	std::string held = std::string(hold) + ".held";
	std::string release = std::string(hold) + ".release";
	int fd = __real_open(held.c_str(), O_WRONLY | O_CREAT, 0600);
	if (fd >= 0)
		close(fd);
	for (int i = 0; i < 300 && access(release.c_str(), F_OK) != 0; i++)
		usleep(10000);
	errno = error;
	return (revoked);
}
FAULT_DIR(_ZN7dtraced3dir32checkpoint_consumer_process_exitERKNS_24durable_consumer_receiptERNS_24collector_owner_registryE, "checkpoint_consumer_process_exit")
FAULT_DIR(_ZN7dtraced3dir17populate_existingEv, "populate_existing")
FAULT_DIR(_ZN7dtraced3dir15list_deliveriesERNSt3__16vectorINS_22durable_delivery_stateENS1_9allocatorIS3_EEEE, "list_deliveries")
FAULT_DIR(_ZN7dtraced3dir22list_consumer_receiptsERNSt3__16vectorINS_30durable_consumer_receipt_stateENS1_9allocatorIS3_EEEE, "list_consumer_receipts")
FAULT_DIR(_ZN7dtraced3dir10list_killsERNSt3__16vectorINS_12durable_killENS1_9allocatorIS3_EEEE, "list_kills")
FAULT_DIR(_ZN7dtraced3dir21list_pending_cleanupsERNSt3__16vectorINS_15durable_cleanupENS1_9allocatorIS3_EEEE, "list_pending_cleanups")
FAULT_DIR(_ZN7dtraced3dir19list_derived_claimsERNSt3__16vectorINS_21durable_derived_claimENS1_9allocatorIS3_EEEE, "list_derived_claims")
FAULT_DIR(_ZN7dtraced3dir24resolve_derived_outboundERS0_PKhS3_RNS_30durable_consumer_receipt_stateE, "resolve_derived_outbound")
FAULT_DIR(_ZN7dtraced3dir28verify_host_delivery_payloadERKNS_16durable_deliveryEPNSt3__16vectorIhNS4_9allocatorIhEEEE, "verify_host_delivery_payload")
FAULT_DIR(_ZN7dtraced3dir23verify_pending_outboundERKNS_16durable_deliveryE, "verify_pending_outbound")
FAULT_DIR(_ZN7dtraced3dir23fresh_session_consumersERS0_RKNS_20durable_session_stopERNSt3__16vectorINS_29host_ingress_program_evidenceENS5_9allocatorIS7_EEEE, "fresh_session_consumers")
FAULT_DIR(_ZN7dtraced3dir27fresh_consumer_stop_receiptERS0_RKNS_20durable_session_stopERKNS_29host_ingress_program_evidenceEb, "fresh_consumer_stop_receipt")
FAULT_DIR(_ZN7dtraced3dir18source_transaction15publish_derivedERKNS_21durable_derived_claimEPKhmPb, "publish_derived")

/* The directory watchers call these through a function pointer; the
 * wrappers keep the exact type (UBSan -fsanitize=function checks it). */
FAULT_ENTRY(_ZN7dtraced15process_inboundERNS_3dirEP6dirent, "process_inbound",
    bool, (dtraced::dir &d, struct dirent *f), (d, f))
FAULT_ENTRY(_ZN7dtraced16process_outboundERNS_3dirEP6dirent, "process_outbound",
    bool, (dtraced::dir &d, struct dirent *f), (d, f))
FAULT_ENTRY(_ZN7dtraced12process_baseERNS_3dirEP6dirent, "process_base", bool,
    (dtraced::dir &d, struct dirent *f), (d, f))

/* Process-wide call faults (HT_CALL_FAULT): the n-th call of a function,
 * counted across all threads, fails once. */
struct call_fault {
	const char *name;
	std::atomic<long> calls{0};
	long target = 0;
};
static call_fault call_faults[] = {
	{"kqueue"}, {"kevent"}, {"listen"}, {"socket"}, {"accept4"}, {"fcntl"},
	{"pdwait"}, {"pdkill"}, {"pdfork"}, {"pipe2"}, {"socketpair"},
	{"setsockopt"}, {"poll"}, {"send"}, {"recv"}, {"recvmsg"},
	{"shutdown"}, {"getsockopt"},
};
static std::once_flag call_faults_once;

static void
call_faults_load(void)
{
	const char *spec = getenv("HT_CALL_FAULT");
	if (spec == nullptr)
		return;
	std::string all(spec);
	size_t pos = 0;
	while (pos < all.size()) {
		size_t end = all.find(',', pos);
		std::string item = all.substr(pos, end == std::string::npos ?
		    std::string::npos : end - pos);
		size_t colon = item.find(':');
		if (colon != std::string::npos)
			for (auto &f : call_faults)
				if (item.compare(0, colon, f.name) == 0)
					f.target = atol(item.c_str() + colon + 1);
		if (end == std::string::npos)
			break;
		pos = end + 1;
	}
}

static bool
call_fault_hit(const char *name)
{
	if (fault_suspended)
		return (false);
	std::call_once(call_faults_once, call_faults_load);
	for (auto &f : call_faults) {
		if (strcmp(f.name, name) != 0 || f.target <= 0)
			continue;
		if (f.calls.fetch_add(1) + 1 != f.target)
			return (false);
		if (getenv("HT_FAULT_FILE") != nullptr) {
			fault_suspended = true;
			fault_report(name);
			fault_suspended = false;
		}
		return (true);
	}
	return (false);
}

#define CALL_FAULT(name, ret, failret, proto, args) \
	extern "C" ret __real_##name proto; \
	extern "C" ret __wrap_##name proto { \
		if (call_fault_hit(#name)) { errno = EIO; return (failret); } \
		return (__real_##name args); \
	}
CALL_FAULT(kqueue, int, -1, (void), ())
CALL_FAULT(kevent, int, -1, (int a, const struct kevent *b, int c,
    struct kevent *d, int e, const struct timespec *f), (a, b, c, d, e, f))
CALL_FAULT(listen, int, -1, (int a, int b), (a, b))
CALL_FAULT(socket, int, -1, (int a, int b, int c), (a, b, c))
CALL_FAULT(accept4, int, -1, (int a, struct sockaddr *b, socklen_t *c, int d),
    (a, b, c, d))
CALL_FAULT(pdwait, int, -1, (int a, int *b, int c, struct __wrusage *d,
    struct __siginfo *e), (a, b, c, d, e))
CALL_FAULT(pdkill, int, -1, (int a, int b), (a, b))
CALL_FAULT(pdfork, pid_t, -1, (int *a, int b), (a, b))
CALL_FAULT(pipe2, int, -1, (int *a, int b), (a, b))
CALL_FAULT(socketpair, int, -1, (int a, int b, int c, int *d), (a, b, c, d))
CALL_FAULT(setsockopt, int, -1, (int a, int b, int c, const void *d,
    socklen_t e), (a, b, c, d, e))
CALL_FAULT(poll, int, -1, (struct pollfd *a, nfds_t b, int c), (a, b, c))
CALL_FAULT(send, ssize_t, -1, (int a, const void *b, size_t c, int d), (a, b, c, d))
CALL_FAULT(recv, ssize_t, -1, (int a, void *b, size_t c, int d), (a, b, c, d))
CALL_FAULT(recvmsg, ssize_t, -1, (int a, struct msghdr *b, int c), (a, b, c))
CALL_FAULT(shutdown, int, -1, (int a, int b), (a, b))

extern "C" int __real_fcntl(int, int, ...);
extern "C" int
__wrap_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	va_start(ap, cmd);
	intptr_t arg = va_arg(ap, intptr_t);
	va_end(ap);
	if (call_fault_hit("fcntl")) {
		errno = EIO;
		return (-1);
	}
	return (__real_fcntl(fd, cmd, arg));
}

#define FAULT_SYS(name, ret, proto, args) \
	extern "C" ret __real_##name proto; \
	extern "C" ret __wrap_##name proto { \
		if (fault_hit(1, #name)) { errno = EIO; return ((ret)-1); } \
		return (__real_##name args); \
	}
FAULT_SYS(fsync, int, (int a), (a))
FAULT_SYS(renameat, int, (int a, const char *b, int c, const char *d), (a, b, c, d))
FAULT_SYS(linkat, int, (int a, const char *b, int c, const char *d, int e), (a, b, c, d, e))
FAULT_SYS(unlinkat, int, (int a, const char *b, int c), (a, b, c))
FAULT_SYS(fstat, int, (int a, struct stat *b), (a, b))
FAULT_SYS(fstatat, int, (int a, const char *b, struct stat *c, int d), (a, b, c, d))
FAULT_SYS(mkdirat, int, (int a, const char *b, mode_t c), (a, b, c))
FAULT_SYS(read, ssize_t, (int a, void *b, size_t c), (a, b, c))
FAULT_SYS(pread, ssize_t, (int a, void *b, size_t c, off_t d), (a, b, c, d))
FAULT_SYS(write, ssize_t, (int a, const void *b, size_t c), (a, b, c))
FAULT_SYS(flock, int, (int a, int b), (a, b))

extern "C" int __real_pthread_create(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
extern "C" int
__wrap_pthread_create(pthread_t *t, const pthread_attr_t *a,
    void *(*fn)(void *), void *arg)
{
	if (fault_hit(1, "pthread_create"))
		return (EAGAIN);	/* std::thread throws system_error */
	return (__real_pthread_create(t, a, fn, arg));
}

extern "C" int __real_close(int);
extern "C" int
__wrap_close(int fd)
{
	int r = __real_close(fd);
	if (fault_hit(1, "close")) {
		errno = EIO;	/* closed, but the error is reported */
		return (-1);
	}
	return (r);
}

extern "C" struct dirent *__real_readdir(DIR *);
extern "C" struct dirent *
__wrap_readdir(DIR *d)
{
	if (fault_hit(1, "readdir")) {
		errno = EIO;
		return (nullptr);
	}
	return (__real_readdir(d));
}

extern "C" DIR *__real_fdopendir(int);
extern "C" DIR *
__wrap_fdopendir(int fd)
{
	if (fault_hit(1, "fdopendir")) {
		errno = EIO;
		return (nullptr);
	}
	return (__real_fdopendir(fd));
}

extern "C" int __real_openat(int, const char *, int, ...);
extern "C" int
__wrap_openat(int dir, const char *path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	int mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	va_end(ap);
	if (fault_hit(1, "openat")) {
		errno = EIO;
		return (-1);
	}
	return (__real_openat(dir, path, flags, mode));
}

extern "C" void *__real__Znwm(size_t);
extern "C" void *
__wrap__Znwm(size_t n)
{
	if (fault_hit(2, "operator new"))
		throw std::bad_alloc();
	return (__real__Znwm(n));
}

/* ---- emulated VMM / HyperTrace kernel state (HT_VMDIR) ---- */
static std::mutex ht_mtx;
extern "C" int __real_open(const char *, int, ...);

/* /dev/dtrace/hypertrace descriptors are opens of HT_VMDIR/.device, so a
 * reused descriptor number is never mistaken for the device. */
static std::string
ht_device_path(void)
{
	return (std::string(getenv("HT_VMDIR")) + "/.device");
}

static bool
ht_is_device(int fd)
{
	shim_scope scope;
	struct stat a, b;
	return (fd >= 0 && fstat(fd, &a) == 0 &&
	    stat(ht_device_path().c_str(), &b) == 0 && a.st_ino == b.st_ino &&
	    a.st_dev == b.st_dev);
}

/* Find the VM file for a live (vmid, epoch), or the one whose inode is the
 * descriptor's. Returns false when no such VM is live. */
static bool
ht_vm_lookup(int fd, unsigned want_vmid, unsigned long long want_epoch,
    struct hypertrace_vm_attestation *out)
{
	const char *vmdir = getenv("HT_VMDIR");
	struct stat sb;
	if (vmdir == nullptr || (fd >= 0 && fstat(fd, &sb) != 0))
		return (false);
	DIR *d = opendir(vmdir);
	if (d == nullptr)
		return (false);
	bool found = false;
	while (struct dirent *e = readdir(d)) {
		unsigned vmid;
		unsigned long long epoch;
		char name[64] = {};
		if (sscanf(e->d_name, "vm.%u.%llu.%63s", &vmid, &epoch, name) != 3)
			continue;
		if (fd >= 0) {
			struct stat vs;
			std::string path = std::string(vmdir) + "/" + e->d_name;
			if (stat(path.c_str(), &vs) != 0 || vs.st_ino != sb.st_ino ||
			    vs.st_dev != sb.st_dev)
				continue;
		} else if (vmid != want_vmid || epoch != want_epoch)
			continue;
		if (out != nullptr) {
			*out = {};
			out->vmid = (uint16_t)vmid;
			out->epoch = epoch;
			strlcpy(out->name, name, sizeof(out->name));
		}
		found = true;
		break;
	}
	closedir(d);
	return (found);
}

static std::string
ht_gate_path(unsigned vmid, unsigned long long epoch)
{
	char leaf[64];
	snprintf(leaf, sizeof(leaf), "/gate.%u.%llu", vmid, epoch);
	return (std::string(getenv("HT_VMDIR")) + leaf);
}

/* gate file: 1 byte suspended + 16 byte owner token */
static void
ht_gate_load(unsigned vmid, unsigned long long epoch, bool &suspended,
    uint8_t token[16])
{
	uint8_t b[17] = {};
	int fd = __real_open(ht_gate_path(vmid, epoch).c_str(), O_RDONLY);
	if (fd >= 0) {
		(void)read(fd, b, sizeof(b));
		close(fd);
	}
	suspended = b[0] != 0;
	memcpy(token, b + 1, 16);
}

static void
ht_gate_store(unsigned vmid, unsigned long long epoch, bool suspended,
    const uint8_t token[16])
{
	uint8_t b[17];
	b[0] = suspended ? 1 : 0;
	memcpy(b + 1, token, 16);
	std::string path = ht_gate_path(vmid, epoch);
	std::string tmp = path + ".tmp";
	int fd = __real_open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, b, sizeof(b)) != (ssize_t)sizeof(b))
		abort();
	close(fd);
	if (rename(tmp.c_str(), path.c_str()) != 0)
		abort();
}

static int
ht_device_ioctl(unsigned long request, void *arg)
{
	shim_scope scope;
	std::lock_guard lock(ht_mtx);
	if (request == HYPERTRACE_IOC_EPOCH_QUERY) {
		auto *q = static_cast<struct hypertrace_epoch_query *>(arg);
		q->live = ht_vm_lookup(-1, q->vmid, q->epoch, nullptr) ? 1 : 0;
		return (0);
	}
	if (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY ||
	    request == HYPERTRACE_IOC_EPOCH_SUSPEND ||
	    request == HYPERTRACE_IOC_EPOCH_RESUME) {
		auto *g = static_cast<struct hypertrace_epoch_gate *>(arg);
		bool suspended;
		uint8_t owner[16];
		ht_gate_load(g->vmid, g->epoch, suspended, owner);
		if (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
			g->suspended = suspended ? 1 : 0;
			memcpy(g->token, owner, 16);
			return (0);
		}
		if (!ht_vm_lookup(-1, g->vmid, g->epoch, nullptr)) {
			errno = ESRCH;
			return (-1);
		}
		if (request == HYPERTRACE_IOC_EPOCH_SUSPEND && !suspended &&
		    memcmp(g->previous_token, owner, 16) == 0) {
			ht_gate_store(g->vmid, g->epoch, true, g->token);
			return (0);
		}
		if (request == HYPERTRACE_IOC_EPOCH_RESUME && suspended &&
		    memcmp(g->token, owner, 16) == 0) {
			ht_gate_store(g->vmid, g->epoch, false, owner);
			return (0);
		}
		errno = ESTALE;
		return (-1);
	}
	if (request == HYPERTRACE_IOC_HANDLE_QUERY) {
		auto *h = static_cast<dtrace_handle_lifetime_t *>(arg);
		h->retired = 0;
		h->reserved = 0;
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(ap, int) : 0;
	va_end(ap);
	if (fault_hit(1, "open")) {
		errno = EIO;
		return (-1);
	}
	if (strcmp(path, "/dev/dttransport") == 0 &&
	    getenv("HT_DTT_IDENTITY") != nullptr)
		return (open_transport(flags));
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0 &&
	    getenv("HT_VMDIR") != nullptr) {
		int fd = __real_open(ht_device_path().c_str(),
		    O_RDONLY | O_CREAT | (flags & O_CLOEXEC), 0600);
		return (fd);
	}
	/* Only the control directory check opens it with O_NOFOLLOW; the
	 * default -D directory stays refused. */
	if (strcmp(path, DTRACED_SOCKDIR) == 0 && (flags & O_NOFOLLOW) != 0)
		return (__real_open(root_path(".").c_str(), flags, mode));
	if (forbidden(path)) {
		errno = strncmp(path, "/dev/", 5) == 0 ? ENOENT : EACCES;
		return (-1);
	}
	return (__real_open(path, flags, mode));
}

extern "C" int __real_mkdir(const char *, mode_t);
extern "C" int
__wrap_mkdir(const char *path, mode_t mode)
{
	if (forbidden(path)) {
		errno = EACCES;
		return (-1);
	}
	return (__real_mkdir(path, mode));
}

extern "C" int __real_remove(const char *);
extern "C" int
__wrap_remove(const char *path)
{
	if (strcmp(path, DTRACED_SOCKPATH) == 0)
		return (__real_remove(root_path("sub.sock").c_str()));
	if (forbidden(path)) {
		errno = EACCES;
		return (-1);
	}
	return (__real_remove(path));
}

static bool
redirect(const struct sockaddr *addr, struct sockaddr_un &local)
{
	const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
	if (addr->sa_family != AF_UNIX || strcmp(un->sun_path, DTRACED_SOCKPATH) != 0)
		return (false);
	memset(&local, 0, sizeof(local));
	local.sun_family = AF_UNIX;
	if (strlcpy(local.sun_path, root_path("sub.sock").c_str(),
	    sizeof(local.sun_path)) >= sizeof(local.sun_path))
		abort();
	return (true);
}

extern "C" int __real_bind(int, const struct sockaddr *, socklen_t);
extern "C" int
__wrap_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_un local;
	if (redirect(addr, local)) {
		if (env_is("HT_BIND", "fail")) {
			errno = EADDRINUSE;
			return (-1);
		}
		return (__real_bind(fd, (struct sockaddr *)&local, sizeof(local)));
	}
	return (__real_bind(fd, addr, len));
}

extern "C" int __real_connect(int, const struct sockaddr *, socklen_t);
extern "C" int
__wrap_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_un local;
	if (redirect(addr, local))
		return (__real_connect(fd, (struct sockaddr *)&local, sizeof(local)));
	return (__real_connect(fd, addr, len));
}

extern "C" int __real_getsockopt(int, int, int, void *, socklen_t *);
extern "C" int
__wrap_getsockopt(int fd, int level, int name, void *value, socklen_t *len)
{
	if (call_fault_hit("getsockopt")) {
		errno = EIO;
		return (-1);
	}
	int r = __real_getsockopt(fd, level, name, value, len);
	if (r == 0 && level == SOL_LOCAL && name == LOCAL_PEERCRED &&
	    env_is("HT_PEER_ROOT", "1"))
		((struct xucred *)value)->cr_uid = 0;
	return (r);
}

/* HT_EXEC_FAKE=report: dtrace(1)'s launch report for a guest launch with
 * -N identifiers (HYPERTRACE_LAUNCH_REPORT=1): read the identifier list on
 * stdin, select the first, report it installed, keep running for
 * HT_EXEC_FAKE_HOLD_MS (default 500), then exit 0. Raw I/O only (child of a
 * threaded process). */
extern "C" int __real_close(int);
static void
fake_launch_report(char *const envp[])
{
	/* exec(2) closes every close-on-exec descriptor; the daemon's exec
	 * status pipe reaches EOF only then */
	for (int fd = 3; fd < 4096; fd++) {
		int flags = __real_fcntl(fd, F_GETFD);
		if (flags >= 0 && (flags & FD_CLOEXEC) != 0)
			(void)__real_close(fd);
	}
	bool report = false;
	for (size_t i = 0; envp != nullptr && envp[i] != nullptr; i++)
		report |= strcmp(envp[i], "HYPERTRACE_LAUNCH_REPORT=1") == 0;
	if (report) {
		unsigned char count_wire[8];
		size_t got = 0;
		while (got < sizeof(count_wire)) {
			ssize_t n = read(STDIN_FILENO, count_wire + got,
			    sizeof(count_wire) - got);
			if (n <= 0)
				_exit(1);
			got += (size_t)n;
		}
		uint64_t count = dtraced_wire_get_u64(count_wire);
		char selected[DTRACED_PROGIDENTLEN], ident[DTRACED_PROGIDENTLEN];
		for (uint64_t k = 0; k < count; k++) {
			got = 0;
			while (got < sizeof(ident)) {
				ssize_t n = read(STDIN_FILENO, ident + got,
				    sizeof(ident) - got);
				if (n <= 0)
					_exit(1);
				got += (size_t)n;
			}
			if (k == 0)
				memcpy(selected, ident, sizeof(selected));
		}
		dtraced_launch_result_t result{};
		result.magic = DTRACED_LAUNCH_MAGIC;
		result.installed = 1;
		memcpy(result.source_ident, selected, sizeof(selected));
		unsigned char wire[DTRACED_LAUNCH_WIRE_SIZE];
		dtraced_wire_encode_launch(wire, &result);
		static const char del[sizeof("DEL ident")] = "DEL ident";
		if (write(STDOUT_FILENO, del, sizeof(del)) != (ssize_t)sizeof(del) ||
		    write(STDOUT_FILENO, selected, sizeof(selected)) !=
		    (ssize_t)sizeof(selected) ||
		    write(STDOUT_FILENO, wire, sizeof(wire)) != (ssize_t)sizeof(wire))
			_exit(1);
	}
	const char *hold = getenv("HT_EXEC_FAKE_HOLD_MS");
	struct timespec ts = {0, 500 * 1000000L};
	if (hold != nullptr) {
		long ms = atol(hold);
		ts.tv_sec = ms / 1000;
		ts.tv_nsec = (ms % 1000) * 1000000L;
	}
	(void)nanosleep(&ts, nullptr);
	if (__llvm_profile_write_file != nullptr)
		(void)__llvm_profile_write_file();
	_exit(0);
}

extern "C" int __real_execve(const char *, char *const[], char *const[]);

/* HT_EXEC_DTRACE: dtrace(1) as a test program, reaching this daemon. */
static int
exec_test_dtrace(const char *program, char *const argv[], char *const envp[])
{
	static char socket_env[PATH_MAX];
	char *environment[8];
	size_t n = 0;
	const char *root = getenv("HT_ROOT");

	if (root == nullptr || snprintf(socket_env, sizeof(socket_env),
	    "HT_DTRACE_SOCKET=%s/sub.sock", root) >= (int)sizeof(socket_env)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	for (; envp != nullptr && envp[n] != nullptr && n < 6; n++)
		environment[n] = envp[n];
	environment[n++] = socket_env;
	environment[n] = nullptr;
	return (__real_execve(program, argv, environment));
}

extern "C" int
__wrap_execve(const char *path, char *const argv[], char *const envp[])
{
	if (argv != nullptr && argv[0] != nullptr && strcmp(path, argv[0]) == 0 &&
	    strcmp(path, "/usr/sbin/dtrace") != 0 && path[0] == '/') {
		/* re-exec of this test daemon */
		if (__llvm_profile_write_file != nullptr)
			(void)__llvm_profile_write_file();
		_exit(73);
	}
	const char *test_dtrace = getenv("HT_EXEC_DTRACE");
	if (test_dtrace != nullptr && strcmp(path, "/usr/sbin/dtrace") == 0)
		return (exec_test_dtrace(test_dtrace, argv, envp));
	const char *log = getenv("HT_EXEC_LOG");
	if (log != nullptr) {
		/* Record the program a launch would run; nothing is executed. */
		std::string line = path;
		for (size_t i = 0; argv != nullptr && argv[i] != nullptr; i++)
			line += std::string(" ") + argv[i];
		line += "\n";
		int fd = __real_open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (fd >= 0) {
			(void)write(fd, line.data(), line.size());
			close(fd);
		}
		if (env_is("HT_EXEC_FAKE", "report"))
			fake_launch_report(envp);
		if (env_is("HT_EXEC_FAKE", "1")) {
			/* A launched program that ran and exited at once. */
			if (__llvm_profile_write_file != nullptr)
				(void)__llvm_profile_write_file();
			_exit(0);
		}
	}
	errno = ENOENT;
	return (-1);
}

/* pdopenpid(2): kernels without it answer ENOSYS. A previous incarnation's
 * tracing children are process-descriptor children (PD_CLOEXEC) and die
 * with it, so a recorded child that no longer exists is ESRCH, exactly what
 * the real call reports for it. A live process is left to the real call. */
extern "C" int __real_pdopenpid(pid_t, int);
extern "C" int
__wrap_pdopenpid(pid_t pid, int flags)
{
	int fd = __real_pdopenpid(pid, flags);
	if (fd < 0 && errno == ENOSYS && ::kill(pid, 0) != 0 && errno == ESRCH)
		errno = ESRCH;
	else if (fd < 0)
		errno = ENOSYS;
	return (fd);
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	{
		std::lock_guard lock(dtt_mtx);
		if (fd >= 0 && fd == dtt_daemon_fd) {
			shim_scope scope;
			return (transport_ioctl(request, arg));
		}
	}
	if (fault_hit(1, "ioctl")) {
		errno = EIO;
		return (-1);
	}
	if (getenv("HT_VMDIR") != nullptr && ht_is_device(fd))
		return (ht_device_ioctl(request, arg));
	if (request == PDIOC_GET_BIRTH_IDENTITY && env_is("HT_PD_BIRTH", "1")) {
		pid_t pid;
		if (pdgetpid(fd, &pid) != 0)
			return (-1);
		struct pd_birth_identity b{};
		b.pid = pid;
		b.start_sec = 1;
		b.start_usec = 2;
		memcpy(arg, &b, sizeof(b));
		return (0);
	}
	if (request == VM_GET_ATTESTATION && getenv("HT_VMDIR") != nullptr) {
		shim_scope scope;
		struct hypertrace_vm_attestation a{};
		if (!ht_vm_lookup(fd, 0, 0, &a)) {
			errno = ENXIO;	/* the VMM instance is gone */
			return (-1);
		}
		memcpy(arg, &a, sizeof(a));
		return (0);
	}
	if (request == VM_GET_ATTESTATION) {
		const char *spec = getenv("HT_ATTEST");
		struct hypertrace_vm_attestation a{};
		unsigned vmid = 0;
		unsigned long long epoch = 0;
		char name[sizeof(a.name)] = {};
		if (spec == nullptr || sscanf(spec, "%u:%llu:%63s", &vmid, &epoch,
		    name) != 3) {
			errno = ENOTTY;
			return (-1);
		}
		a.vmid = (uint16_t)vmid;
		a.epoch = epoch;
		strlcpy(a.name, name, sizeof(a.name));
		memcpy(arg, &a, sizeof(a));
		return (0);
	}
	return (__real_ioctl(fd, request, arg));
}
