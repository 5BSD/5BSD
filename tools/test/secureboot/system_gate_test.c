/* SPDX-License-Identifier: BSD-2-Clause */
/* Actual kernel operations, only in disposable Secure Boot guests. */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/wait.h>
#include <bsm/audit.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_system_proto.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "system_gate_test.h"

#define CHECK(test) do { \
	if (!(test)) { \
		printf("SYSTEM_GATE_FAIL line=%d errno=%d: %s\n", \
		    __LINE__, errno, #test); \
		return (1); \
	} \
} while (0)

static int
connect_system(void)
{
	struct mac_capability_connect_args request = {0};
	int fd, error;

	fd = open("/dev/mac_capability", O_RDWR);
	if (fd < 0)
		return (-1);
	strlcpy(request.name, "system", sizeof(request.name));
	error = ioctl(fd, MAC_CAPABILITY_CONNECT, &request) == -1 ? errno : 0;
	close(fd);
	return (error != 0 ? (errno = error, -1) : request.fd);
}

static int
operation(int fd, uint32_t op, uint32_t gates, int *token)
{
	struct sys_request request = { .op = op, .gates = gates };
	struct mac_capability_call_args call = {
	    .req = &request, .req_len = sizeof(request),
	    .reply_fds = token, .reply_nfds = token != NULL ? 1 : 0,
	};

	return (ioctl(fd, MAC_CAPABILITY_CALL, &call));
}

static int
adjust(int fd)
{
	/* Zero adjustment exercises authorization without stepping the clock. */
	struct sys_adjtime_request request = { .op = SYS_OP_ADJTIME };
	struct sys_adjtime_reply reply;
	struct mac_capability_call_args call = {
	    .req = &request, .req_len = sizeof(request),
	    .reply = &reply, .reply_len = sizeof(reply),
	};

	return (ioctl(fd, MAC_CAPABILITY_CALL, &call));
}

static int
denial_test(bool require_connection, bool clock_claimed)
{
	struct timeval zero = {0}, now;
	struct timespec realtime;
	struct timex ntp = { .modes = MOD_OFFSET };
	int fd, result, error;

	int condition, after;
	long legacy;

	CHECK(geteuid() == 0 && getpid() != 1);
	CHECK(auditon(A_GETCOND, &condition, sizeof(condition)) == 0);
	CHECK(condition == AUC_AUDITING || condition == AUC_NOAUDIT);
	CHECK(auditon(A_OLDGETCOND, &legacy, sizeof(legacy)) == 0);
	CHECK(legacy == condition);
	CHECK(auditon(A_SETCOND, &condition, sizeof(condition)) == -1 && errno == EPERM);
	CHECK(auditon(A_OLDSETCOND, &legacy, sizeof(legacy)) == -1 && errno == EPERM);
	CHECK(auditon(A_GETCOND, &after, sizeof(after)) == 0 && after == condition);
	const char audit_result[] = "\nAUDIT_CONDITION_PASS status readable, administration denied, condition unchanged\n";
	CHECK(write(STDOUT_FILENO, audit_result, sizeof(audit_result) - 1) ==
	    (ssize_t)(sizeof(audit_result) - 1));
	fd = connect_system();
	if (fd == -1) {
		CHECK(!require_connection && (errno == EPERM || errno == EACCES));
		puts("SYSTEM_GATE_ACCESS_DENIED kernel service acquisition");
	} else {
		errno = 0;
		result = operation(fd, SYS_OP_CLAIM, SYS_GATE_SETTIME, NULL);
		error = errno;
		if (result != -1 || error != EPERM) {
			printf("SYSTEM_GATE_FAIL claim returned %d errno=%d\n", result, error);
			return (1);
		}
		CHECK(adjust(fd) == -1 && errno == EPERM);
		close(fd);
	}
	CHECK(gettimeofday(&now, NULL) == 0);
	CHECK(clock_gettime(CLOCK_REALTIME, &realtime) == 0);
	if (clock_claimed) {
		CHECK(adjtime(&zero, NULL) == -1 && errno == EPERM);
		CHECK(settimeofday(&now, NULL) == -1 && errno == EPERM);
		CHECK(clock_settime(CLOCK_REALTIME, &realtime) == -1 && errno == EPERM);
		CHECK(ntp_adjtime(&ntp) == -1 && errno == EPERM);
	} else {
		/* Only inside the disposable guest: ordinary root keeps clock APIs. */
		CHECK(adjtime(&zero, NULL) == 0);
		CHECK(settimeofday(&now, NULL) == 0);
		CHECK(clock_settime(CLOCK_REALTIME, &realtime) == 0);
		CHECK(ntp_adjtime(&ntp) >= 0);
	}
	puts("SYSTEM_GATE_DENY_PASS root cannot manufacture System authority");
	return (0);
}

int
system_gate_denial_test(void)
{

	return (denial_test(true, false));
}

static int
audit_trail_denial(void)
{
	char path[] = "/tmp/audit-denial.XXXXXX";
	const char payload[] = "audit trail must not change";
	char actual[sizeof(payload)];
	struct stat before, after;
	int fd, current_before, current_after, condition, condition_after;
	uint64_t frees_before, frees_after;
	size_t size;
	const unsigned attempts = 512;

	fd = mkstemp(path);
	CHECK(fd >= 0);
	CHECK(write(fd, payload, sizeof(payload)) == (ssize_t)sizeof(payload));
	CHECK(fstat(fd, &before) == 0);
	CHECK(auditon(A_GETCOND, &condition, sizeof(condition)) == 0);
	size = sizeof(current_before);
	CHECK(sysctlbyname("vm.uma.NAMEI.stats.current", &current_before, &size, NULL, 0) == 0 && size == sizeof(current_before));
	size = sizeof(frees_before);
	CHECK(sysctlbyname("vm.uma.NAMEI.stats.frees", &frees_before, &size, NULL, 0) == 0 && size == sizeof(frees_before));
	for (unsigned i = 0; i < attempts; i++)
		CHECK(auditctl(path) == -1 && errno == EPERM);
	size = sizeof(frees_after);
	CHECK(sysctlbyname("vm.uma.NAMEI.stats.frees", &frees_after, &size, NULL, 0) == 0 && size == sizeof(frees_after));
	size = sizeof(current_after);
	CHECK(sysctlbyname("vm.uma.NAMEI.stats.current", &current_after, &size, NULL, 0) == 0 && size == sizeof(current_after));
	printf("AUDIT_TRAIL_ALLOCATIONS attempts=%u live_before=%d live_after=%d frees_before=%" PRIu64 " frees_after=%" PRIu64 "\n",
	    attempts, current_before, current_after, frees_before, frees_after);
	CHECK(current_after <= current_before);
	CHECK(frees_after >= frees_before && frees_after - frees_before >= attempts);
	CHECK(fstat(fd, &after) == 0 && after.st_size == before.st_size &&
	    after.st_ino == before.st_ino && after.st_dev == before.st_dev);
	CHECK(pread(fd, actual, sizeof(actual), 0) == (ssize_t)sizeof(actual));
	CHECK(memcmp(actual, payload, sizeof(payload)) == 0);
	CHECK(auditon(A_GETCOND, &condition_after, sizeof(condition_after)) == 0 && condition_after == condition);
	CHECK(close(fd) == 0 && unlink(path) == 0);
	const char result[] = "\nAUDIT_TRAIL_DENIAL_PASS repeated refusal, pathname cleanup, file and condition unchanged\n";
	CHECK(write(STDOUT_FILENO, result, sizeof(result) - 1) == (ssize_t)(sizeof(result) - 1));
	return (0);
}

int
system_gate_capsule_test(void)
{

	/* Capsule may isolate the dispatcher device before this child exists.
	 * Static PID 1 tests separately require direct access to exercise gates. */
	CHECK(denial_test(false, true) == 0);
	return (audit_trail_denial());
}

int
system_gate_reauthorize_test(int token)
{

	CHECK(getpid() != 1 && fcntl(token, F_GETFD) >= 0);
	CHECK(operation(token, SYS_OP_AUTHORIZE, 0, NULL) == -1 && errno == EALREADY);
	CHECK(adjust(token) == -1 && errno == EPERM);
	return (0);
}

static int
inherited_claim(int owner, int token, int barrier)
{
	int extra = -1, fd, status;
	char byte, token_arg[32];
	pid_t child;

	CHECK(read(barrier, &byte, 1) == 1);
	close(barrier);
	CHECK(denial_test(true, true) == 0);
	/* Fork preserves the nonce, but must not inherit PID 1's ownership. */
	CHECK(operation(owner, SYS_OP_CLAIM, SYS_GATE_SETTIME, NULL) == -1 && errno == EPERM);
	CHECK(operation(owner, SYS_OP_MINT, SYS_GATE_SETTIME, &extra) == -1 && errno == EPERM);
	CHECK(operation(owner, SYS_OP_RELEASE, SYS_GATE_SETTIME, NULL) == -1 && errno == EPERM);
	close(owner);
	fd = connect_system();
	CHECK(fd >= 0);
	CHECK(adjust(fd) == -1 && errno == EPERM);
	CHECK(operation(token, SYS_OP_AUTHORIZE, 0, NULL) == 0);
	CHECK(operation(token, SYS_OP_AUTHORIZE, 0, NULL) == 0);
	CHECK(adjust(token) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(fd);
		CHECK(fcntl(token, F_SETFD, 0) == 0);
		snprintf(token_arg, sizeof(token_arg), "%d", token);
		execl("/sbin/secureboot-init", "secureboot-init",
		    "--system-gate-reauthorize", token_arg, (char *)NULL);
		_exit(99);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
	CHECK(adjust(token) == 0); /* Failed reactivation did not replace the owner. */
	puts("SYSTEM_GATE_REAUTHORIZE_PASS same nonce repeats; new exec needs fresh token");
	close(token);
	CHECK(adjust(fd) == -1 && errno == EPERM);
	close(fd);
	return (0);
}

/* An explicit isolation claim remains effective for ordinary runtime state. */
static int
ordinary_sysctl_isolation(void)
{
	int owner, original, changed, actual, status;
	size_t size;
	pid_t child;

	owner = connect_system();
	CHECK(owner >= 0);
	size = sizeof(original);
	CHECK(sysctlbyname("net.inet.tcp.log_in_vain", &original, &size,
	    NULL, 0) == 0 && size == sizeof(original));
	CHECK(operation(owner, SYS_OP_CLAIM, SYS_GATE_SYSCTL, NULL) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(owner);
		changed = original == 0 ? 1 : 0;
		errno = 0;
		_exit(sysctlbyname("net.inet.tcp.log_in_vain", NULL, NULL,
		    &changed, sizeof(changed)) == -1 && errno == EPERM ? 0 : 1);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
	size = sizeof(actual);
	CHECK(sysctlbyname("net.inet.tcp.log_in_vain", &actual, &size,
	    NULL, 0) == 0 && size == sizeof(actual) && actual == original);
	CHECK(operation(owner, SYS_OP_RELEASE, SYS_GATE_SYSCTL, NULL) == 0);
	close(owner);
	puts("SYSTEM_GATE_ORDINARY_SYSCTL_PASS explicit isolation denies root write");
	return (0);
}

static int
authority_operation(int command, int fd, void *data)
{

	return (syscall(SYS_cap_process, command, fd, 0, data));
}

/* Keep the token open: denial must follow authority loss, not fd teardown. */
static int
bound_authorization_child(int grant, int token, int ready, int proceed,
    bool clear_authority)
{
	struct cap_authority_info info;
	int fd, value;
	size_t size = sizeof(value);
	char byte;

	CHECK(authority_operation(CAP_AUTH_INSTALL, grant, NULL) == 0);
	CHECK(authority_operation(CAP_AUTH_INFO, -1, &info) == 0 && info.valid);
	CHECK(close(grant) == 0);
	fd = connect_system();
	CHECK(fd >= 0);
	CHECK(operation(token, SYS_OP_AUTHORIZE, 0, NULL) == 0);
	CHECK(adjust(fd) == 0); /* Separate, unbound service connection. */
	CHECK(sysctlbyname("net.inet.tcp.log_in_vain", &value, &size,
	    NULL, 0) == 0 && size == sizeof(value));
	CHECK(sysctlbyname("net.inet.tcp.log_in_vain", NULL, NULL,
	    &value, sizeof(value)) == 0);
	CHECK(write(ready, "R", 1) == 1);
	CHECK(read(proceed, &byte, 1) == 1 && byte == 'G');
	if (clear_authority)
		CHECK(authority_operation(CAP_AUTH_CLEAR, -1, NULL) == 0);
	CHECK(authority_operation(CAP_AUTH_INFO, -1, &info) == 0 && !info.valid);
	CHECK(fcntl(token, F_GETFD) >= 0);
	CHECK(operation(token, SYS_OP_AUTHORIZE, 0, NULL) == -1 && errno == EPERM);
	CHECK(adjust(fd) == -1 && errno == EPERM);
	CHECK(sysctlbyname("net.inet.tcp.log_in_vain", NULL, NULL,
	    &value, sizeof(value)) == -1 && errno == EPERM);
	CHECK(close(token) == 0 && close(fd) == 0);
	CHECK(close(ready) == 0 && close(proceed) == 0);
	return (0);
}

static int
bound_authorization_test(void)
{
	struct cap_authority_spec spec = {CAP_AUTH_VERSION, CAP_AUTH_MANAGED, 0, 0};
	struct cap_authority_bind binding = {0};
	struct cap_authority_revoke revoke = {0};
	int issuer, grant, owner, token, ready[2], proceed[2], status;
	pid_t child;
	char byte;

	for (int clear_authority = 0; clear_authority < 2; clear_authority++) {
		issuer = authority_operation(CAP_AUTH_ISSUER_CREATE, -1, NULL);
		CHECK(issuer >= 0);
		grant = authority_operation(CAP_AUTH_ISSUE, issuer, &spec);
		CHECK(grant >= 0);
		owner = connect_system();
		CHECK(owner >= 0);
		CHECK(operation(owner, SYS_OP_CLAIM,
		    SYS_GATE_SYSCTL | SYS_GATE_SETTIME, NULL) == 0);
		token = -1;
		CHECK(operation(owner, SYS_OP_MINT,
		    SYS_GATE_SYSCTL | SYS_GATE_SETTIME, &token) == 0 && token >= 0);
		binding.token_fd = grant;
		binding.capability_fd = token;
		CHECK(authority_operation(CAP_AUTH_BIND, issuer, &binding) == 0);
		CHECK(pipe(ready) == 0 && pipe(proceed) == 0);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			close(issuer); close(owner);
			close(ready[0]); close(proceed[1]);
			_exit(bound_authorization_child(grant, token, ready[1],
			    proceed[0], clear_authority != 0));
		}
		close(ready[1]); close(proceed[0]);
		CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
		if (!clear_authority) {
			revoke.token_fd = grant;
			CHECK(authority_operation(CAP_AUTH_REVOKE, issuer, &revoke) == 0);
		}
		CHECK(write(proceed[1], "G", 1) == 1);
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 0);
		CHECK(close(ready[0]) == 0 && close(proceed[1]) == 0);
		CHECK(close(token) == 0 && close(owner) == 0);
		CHECK(close(grant) == 0 && close(issuer) == 0);
	}
	puts("SYSTEM_GATE_AUTHORITY_PASS revoked and cleared authority deny cached grants");
	return (0);
}

/* Global accounting changes are confined to the disposable guest. */
static int
ordinary_accounting(void)
{
	static const struct {
		const char *name;
		int test_value;
	} controls[] = {
		{"kern.acct_suspend", 3},
		{"kern.acct_resume", 5},
		{"kern.acct_chkfreq", 16},
	};
	char path[] = "/tmp/bip-accounting.XXXXXX";
	struct stat st;
	size_t size;
	int saved, observed, value;
	pid_t child, worker;
	int fd, status;

	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		CHECK(geteuid() == 0 && getpid() != 1);
		for (size_t i = 0; i < nitems(controls); i++) {
			size = sizeof(saved);
			CHECK(sysctlbyname(controls[i].name, &saved, &size,
			    NULL, 0) == 0 && size == sizeof(saved));
			value = controls[i].test_value;
			CHECK(sysctlbyname(controls[i].name, NULL, NULL,
			    &value, sizeof(value)) == 0);
			size = sizeof(observed);
			CHECK(sysctlbyname(controls[i].name, &observed, &size,
			    NULL, 0) == 0 && size == sizeof(observed));
			CHECK(sysctlbyname(controls[i].name, NULL, NULL,
			    &saved, sizeof(saved)) == 0);
			CHECK(observed == value);
		}
		value = 0;
		CHECK(sysctlbyname("kern.acct_chkfreq", NULL, NULL,
		    &value, sizeof(value)) == -1 && errno == EINVAL);
		fd = mkstemp(path);
		CHECK(fd >= 0);
		CHECK(close(fd) == 0);
		CHECK(acct(path) == 0);
		worker = fork();
		CHECK(worker >= 0);
		if (worker == 0)
			_exit(0);
		CHECK(waitpid(worker, &status, 0) == worker);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(acct(NULL) == 0);
		CHECK(stat(path, &st) == 0 && st.st_size > 0);
		CHECK(unlink(path) == 0);
		CHECK(setuid(65534) == 0);
		CHECK(acct(NULL) == -1 && errno == EPERM);
		for (size_t i = 0; i < nitems(controls); i++) {
			value = controls[i].test_value;
			CHECK(sysctlbyname(controls[i].name, NULL, NULL,
			    &value, sizeof(value)) == -1 && errno == EPERM);
		}
		_exit(0);
	}
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	puts("SYSTEM_ACCOUNTING_PASS ordinary control, tunables and records; unprivileged denial");
	return (0);
}

/* Use reported source names, not a device-specific hardware bit allow-list. */
static int
entropy_hardware_sources(char *out, size_t capacity)
{
	char sources[4096], *cursor, *name;
	size_t size = sizeof(sources);

	CHECK(sysctlbyname("kern.random.harvest.mask_symbolic", sources, &size,
	    NULL, 0) == 0 && size > 0 && size <= sizeof(sources));
	CHECK(sources[size - 1] == '\0');
	out[0] = '\0';
	cursor = sources;
	while ((name = strsep(&cursor, ",")) != NULL) {
		if (strncmp(name, "PURE_", 5) != 0)
			continue;
		CHECK(strlcat(out, name, capacity) < capacity);
		CHECK(strlcat(out, ",", capacity) < capacity);
	}
	return (0);
}

/* Disposable guest only: restore the harvesting mask before comparisons. */
static int
ordinary_entropy_control(void)
{
	unsigned int saved, cleared = 0;
	char hardware_before[4096], hardware_after[4096];
	int bypass, status;
	size_t size;
	pid_t child;

	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		CHECK(geteuid() == 0 && getpid() != 1);
		size = sizeof(saved);
		CHECK(sysctlbyname("kern.random.harvest.mask", &saved, &size,
		    NULL, 0) == 0 && size == sizeof(saved));
		CHECK(sysctlbyname("kern.random.harvest.mask", NULL, NULL,
		    &saved, sizeof(saved)) == 0);
		CHECK(entropy_hardware_sources(hardware_before, sizeof(hardware_before)) == 0);
		/* This fixture must actually expose a source to exercise preservation. */
		CHECK(hardware_before[0] != '\0');
		CHECK(sysctlbyname("kern.random.harvest.mask", NULL, NULL,
		    &cleared, sizeof(cleared)) == 0);
		int observed = entropy_hardware_sources(hardware_after, sizeof(hardware_after));
		CHECK(sysctlbyname("kern.random.harvest.mask", NULL, NULL,
		    &saved, sizeof(saved)) == 0);
		CHECK(observed == 0 && strcmp(hardware_before, hardware_after) == 0);
		size = sizeof(bypass);
		CHECK(sysctlbyname("kern.random.initial_seeding.bypass_before_seeding",
		    &bypass, &size, NULL, 0) == 0 && size == sizeof(bypass));
		CHECK(sysctlbyname("kern.random.initial_seeding.bypass_before_seeding",
		    NULL, NULL, &bypass, sizeof(bypass)) == -1 && errno == EPERM);
		CHECK(setuid(65534) == 0);
		CHECK(sysctlbyname("kern.random.harvest.mask", NULL, NULL,
		    &saved, sizeof(saved)) == -1 && errno == EPERM);
		_exit(0);
	}
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	puts("SYSTEM_ENTROPY_CONTROL_PASS ordinary harvest write; hardware sources preserved; unprivileged and seed-bypass writes denied");
	return (0);
}

int
system_gate_test(void)
{
	int owner, token = -1, barrier[2], status;
	pid_t child;

	CHECK(getpid() == 1);
	/* Before claims, ordinary clock calls work but token self-issuance fails. */
	child = fork();
	CHECK(child >= 0);
	if (child == 0)
		_exit(system_gate_denial_test());
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		execl("/sbin/secureboot-init", "secureboot-init", "--system-gate-deny", (char *)NULL);
		_exit(99);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	owner = connect_system();
	CHECK(owner >= 0);
	CHECK(operation(owner, SYS_OP_CLAIM, SYS_GATE_SETTIME, NULL) == 0);
	CHECK(operation(owner, SYS_OP_MINT, SYS_GATE_SETTIME, &token) == 0 && token >= 0);
	CHECK(pipe(barrier) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(barrier[1]);
		_exit(inherited_claim(owner, token, barrier[0]));
	}
	close(barrier[0]);
	/* Ensure the child's close is the final token reference before it runs. */
	close(token);
	CHECK(write(barrier[1], "g", 1) == 1);
	close(barrier[1]);
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(owner);
	CHECK(ordinary_sysctl_isolation() == 0);
	CHECK(bound_authorization_test() == 0);
	CHECK(ordinary_accounting() == 0);
	CHECK(ordinary_entropy_control() == 0);
	puts("SYSTEM_GATE_PASS bootstrap ownership; explicit token works and revokes");
	return (0);
}
