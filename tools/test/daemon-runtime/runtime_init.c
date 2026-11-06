/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable VM PID 1 only. Never invoke as the host's init. */
#include <sys/types.h>
#include <sys/procctl.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#define RUNTIME_MAX_CASE_TIMEOUT 86400U

/* Local TCP/UDP fixtures need lo0; QEMU still has no network adapter. */
static int
configure_loopback(void)
{
	struct ifaliasreq address;
	struct ifreq flags;
	struct sockaddr_in *sin;
	int fd, error = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return (-1);
	memset(&address, 0, sizeof(address));
	strlcpy(address.ifra_name, "lo0", sizeof(address.ifra_name));
	sin = (struct sockaddr_in *)&address.ifra_addr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin = (struct sockaddr_in *)&address.ifra_mask;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xff000000U);
	if (ioctl(fd, SIOCAIFADDR, &address) == -1) {
		error = errno;
		goto out;
	}
	memset(&flags, 0, sizeof(flags));
	strlcpy(flags.ifr_name, "lo0", sizeof(flags.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &flags) == -1) {
		error = errno;
		goto out;
	}
	flags.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &flags) == -1)
		error = errno;
out:
	close(fd);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/* The per-part reaper owns workers even when they create another session. */
static int
terminate_part(pid_t child)
{
	struct timespec start, now, pause_time = { .tv_nsec = 100000000 };
	struct procctl_reaper_kill request = {
		.rk_sig = SIGKILL,
		.rk_flags = REAPER_KILL_SUBTREE,
		.rk_subtree = child,
	};
	struct procctl_reaper_status status;
	struct procctl_reaper_pids pids;
	bool pending;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		if (procctl(P_PID, getpid(), PROC_REAP_KILL, &request) == -1 &&
		    errno != ESRCH) {
			perror("kill test subtree");
			return (-1);
		}
		if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &status) == -1)
			return (-1);
		memset(&pids, 0, sizeof(pids));
		pids.rp_count = status.rs_descendants + 1;
		pids.rp_pids = calloc(pids.rp_count, sizeof(*pids.rp_pids));
		if (pids.rp_pids == NULL)
			return (-1);
		if (procctl(P_PID, getpid(), PROC_REAP_GETPIDS, &pids) == -1) {
			free(pids.rp_pids);
			return (-1);
		}
		pending = false;
		for (unsigned i = 0; i < pids.rp_count; i++) {
			const struct procctl_reaper_pidinfo *info = &pids.rp_pids[i];
			if (!(info->pi_flags & REAPER_PIDINFO_VALID) ||
			    info->pi_subtree != child)
				continue;
			pending = true;
			/* Orphans become our children after their ancestor exits. */
			(void)waitpid(info->pi_pid, NULL, WNOHANG);
		}
		free(pids.rp_pids);
		if (!pending)
			return (0);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 30) {
			fprintf(stderr, "test subtree %d did not exit\n", child);
			return (-1);
		}
		nanosleep(&pause_time, NULL);
	}
}

/* Each body and cleanup gets a separate process group and bounded lifetime. */
static int
run_supervised_part(const char *program, const char *part, const char *path,
    const char *result, unsigned timeout)
{
	struct timespec start, now, pause_time = { .tv_nsec = 100000000 };
	pid_t child;
	int status;

	child = fork();
	if (child == -1)
		return (-1);
	if (child == 0) {
		if (setsid() == -1 || chdir(path) == -1)
			_exit(126);
		execl(program, program, "-s", "/tests", "-r", result, part, NULL);
		_exit(127);
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		pid_t waited = waitpid(child, &status, WNOHANG);
		if (waited == child) {
			int cleaned = terminate_part(child);
			return (cleaned == 0 && WIFEXITED(status) &&
			    WEXITSTATUS(status) == 0 ? 0 : -1);
		}
		if (waited == -1 && errno != EINTR) {
			(void)terminate_part(child);
			return (-1);
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= timeout) {
			(void)terminate_part(child);
			printf("RUNTIME_CASE_FAIL %s:%s timeout=%u\n", program, part, timeout);
			return (-1);
		}
		nanosleep(&pause_time, NULL);
	}
}

/* init's descendants share a special subtree; use a dedicated real reaper. */
static int
run_part(const char *program, const char *part, const char *path,
    const char *result, unsigned timeout)
{
	pid_t supervisor, waited;
	int status;

	supervisor = fork();
	if (supervisor == -1)
		return (-1);
	if (supervisor == 0) {
		if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == -1) {
			perror("acquire test reaper");
			_exit(126);
		}
		_exit(run_supervised_part(program, part, path, result, timeout) == 0 ?
		    0 : 1);
	}
	do {
		waited = waitpid(supervisor, &status, 0);
	} while (waited == -1 && errno == EINTR);
	return (waited == supervisor && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0 ? 0 : -1);
}

static int
run_case(const char *program, const char *name, unsigned timeout, bool cleanup)
{
	char path[300], result[320], part[140], line[1024] = "missing result";
	int status, cleanup_status = 0;
	FILE *file;
	bool passed = false;

	snprintf(path, sizeof(path), "/tmp/%s_%s", strrchr(program, '/') + 1, name);
	if (mkdir(path, 0700) == -1) {
		perror(path);
		return (-1);
	}
	snprintf(result, sizeof(result), "%s/result", path);
	status = run_part(program, name, path, result, timeout);
	file = fopen(result, "r");
	if (file != NULL) {
		passed = fgets(line, sizeof(line), file) != NULL &&
		    strcmp(line, "passed\n") == 0 && fgetc(file) == EOF && !ferror(file);
		fclose(file);
	}
	/* ATF cleanup is required even after a failed, skipped or timed-out body. */
	if (cleanup) {
		snprintf(part, sizeof(part), "%s:cleanup", name);
		snprintf(result, sizeof(result), "%s/cleanup-result", path);
		cleanup_status = run_part(program, part, path, result, timeout);
		printf("RUNTIME_CLEANUP_%s %s:%s\n",
		    cleanup_status == 0 ? "PASS" : "FAIL", program, name);
	}
	if (status != 0 || cleanup_status != 0 || !passed) {
		printf("RUNTIME_CASE_FAIL %s:%s status=%d cleanup=%d result=%s\n",
		    program, name, status, cleanup_status, line);
		return (-1);
	}
	printf("RUNTIME_CASE_PASS %s:%s\n", program, name);
	return (0);
}

int
main(int argc, char **argv)
{
	char fstype[] = "fstype", devfs[] = "devfs", fspath[] = "fspath",
	     dev[] = "/dev";
	struct iovec iov[] = { { .iov_base = fstype, .iov_len = 7 },
		{ .iov_base = devfs, .iov_len = 6 },
		{ .iov_base = fspath, .iov_len = 7 },
		{ .iov_base = dev, .iov_len = 5 } };
	int fd, failed = 0;
	/* Read-only host preflight; no mounts, descriptors or guest setup. */
	if (argc == 2 && strcmp(argv[1], "--describe") == 0) {
		printf("{\"format\":1,\"case_metadata_version\":1,"
		    "\"maximum_case_timeout\":%u,\"cleanup\":true}\n",
		    RUNTIME_MAX_CASE_TIMEOUT);
		return (0);
	}
	if (argc != 1)
		return (64);
	if (getpid() != 1)
		return (64);
	(void)nmount(iov, 4, 0);
	fd = open("/dev/console", O_RDWR);
	if (fd >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	{
		const char *names[] = { "kern.eventtimer.timer", "kern.timecounter.hardware" };
		char value[128];
		size_t length;
		for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			length = sizeof(value);
			if (sysctlbyname(names[i], value, &length, NULL, 0) == 0)
				printf("RUNTIME_CLOCK %s=%s\n", names[i], value);
			else
				perror(names[i]);
		}
	}
	setenv("HOME", "/root", 1);
	setenv("TMPDIR", "/tmp", 1);
	puts("RUNTIME_VM_START");
	if (configure_loopback() == -1) {
		perror("configure lo0");
		failed = 1;
	}
	char tmpfs[] = "tmpfs", tmp[] = "/tmp";
	struct iovec tmpiov[] = { { .iov_base = fstype,
				      .iov_len = sizeof(fstype) },
		{ .iov_base = tmpfs, .iov_len = sizeof(tmpfs) },
		{ .iov_base = fspath, .iov_len = sizeof(fspath) },
		{ .iov_base = tmp, .iov_len = sizeof(tmp) } };
	if (nmount(tmpiov, 4, 0) == -1) {
		perror("mount /tmp");
		failed = 1;
	}
	setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
	FILE *extra = fopen("/tests/case-metadata", "r");
	if (extra == NULL) {
		perror("case-metadata");
		failed = 1;
	} else {
		char program[128], test_case[128];
		unsigned timeout, cleanup, count = 0;
		int fields;
		while ((fields = fscanf(extra, "%127s %127s %u %u", program,
		    test_case, &timeout, &cleanup)) == 4) {
			if (timeout == 0 || timeout > RUNTIME_MAX_CASE_TIMEOUT || cleanup > 1 ||
			    strncmp(program, "/tests/", 7) != 0) {
				failed = 1;
				break;
			}
			count++;
			if (run_case(program, test_case, timeout, cleanup != 0) == -1)
				failed = 1;
		}
		if (fields != EOF || ferror(extra) || count == 0)
			failed = 1;
		fclose(extra);
	}
	if (!failed && access("/tests/oes-admission-boot", F_OK) == 0) {
		/* rc normally supplies writable runtime mounts; this fixture skips rc. */
		char run_path[] = "/Capabilities/Run", var_path[] = "/var";
		char coalition_path[] = "/Capabilities/System/CoalitionLifecycle.cap";
		char *paths[] = { run_path, var_path, coalition_path };

		for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
			tmpiov[3].iov_base = paths[i];
			tmpiov[3].iov_len = strlen(paths[i]) + 1;
			if (nmount(tmpiov, 4, 0) == -1) {
				perror(paths[i]);
				failed = 1;
			}
		}
		if (mkdir("/var/run", 0755) == -1 || mkdir("/var/log", 0755) == -1) {
			perror("OES runtime directories");
			failed = 1;
		}
		if (failed)
			goto done;
		pid_t prepare = fork();
		int prepare_status;
		if (prepare == 0) {
			execl("/tests/oes-unregistered", "/tests/oes-unregistered",
			    "prepare-coalition", NULL);
			_exit(127);
		}
		if (prepare == -1 || waitpid(prepare, &prepare_status, 0) != prepare ||
		    !WIFEXITED(prepare_status) || WEXITSTATUS(prepare_status) != 0) {
			puts("COALITION_LIFECYCLE_FAIL preparation");
			failed = 1;
			goto done;
		}
		puts("RUNTIME_FIXTURES_PASS");
		setenv("SWITCHBOARD_SKIP_RC", "1", 1);
		setenv("SWITCHBOARD_BUNDLE_DIR_SYSTEM", "/Capabilities/System", 1);
		setenv("SWITCHBOARD_BUNDLE_DIR_USER", "/Capabilities/Apps", 1);
		setenv("SWITCHBOARD_RUN_DIR", "/Capabilities/Run", 1);
		/* Preserve PID 1: only Capsule may mint the boot authority issuer. */
		execl("/tests/capsule", "/tests/capsule", NULL);
		perror("OES admission Capsule handoff");
		failed = 1;
	}
done:
	puts(failed ? "RUNTIME_VM_FAIL" : "RUNTIME_VM_PASS");
	/* Let the serial transmitter finish before kernel shutdown messages. */
	if (tcdrain(STDOUT_FILENO) == -1) {
		perror("console drain");
		puts("RUNTIME_VM_FAIL");
	}
	sync();
	reboot(RB_POWEROFF);
	for (;;)
		pause();
}
