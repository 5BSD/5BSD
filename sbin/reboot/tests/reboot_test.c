/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the real command without signaling or rebooting the test host. */
int reboot_main(int, char **);
#define main reboot_main
#include "../reboot.c"
#undef main
#include <atf-c.h>
#include <stdarg.h>

/* P: lifecycle request, C: catatonia, I: legacy init, T/K: termination,
 * S: sync, R: kernel reboot. The pipe includes events from the exec child. */
static int events;
static bool plane_accepts, protected_init;
static int expected_flags;

static void
event(char c)
{
	if (write(events, &c, 1) != 1)
		_exit(99);
}

int __wrap_reboot(int);
int __wrap_kill(pid_t, int);
void __wrap_sync(void);
unsigned __wrap_sleep(unsigned);
int __wrap_execl(const char *, const char *, ...);
uid_t __wrap_geteuid(void);
struct utmpx *__wrap_pututxline(const struct utmpx *);
int __wrap_sysctlbyname(const char *, void *, size_t *, const void *, size_t);

int
__wrap_reboot(int flags)
{
	event('R');
	/* Verify that fallback preserves the requested transition flags. */
	_exit(flags == expected_flags ? 0 : 98);
}

int
__wrap_kill(pid_t pid, int sig)
{
	if (pid == 1 && sig == SIGTSTP) {
		event('I');
		if (!protected_init)
			return (0);
	} else if (pid == -1 && sig == SIGTERM) {
		event('T');
	} else if (pid == -1 && sig == SIGKILL) {
		event('K');
	} else {
		_exit(97);
	}
	errno = protected_init ? EPERM : ESRCH;
	return (-1);
}

void
__wrap_sync(void)
{
	event('S');
}
unsigned
__wrap_sleep(unsigned n __unused)
{
	return (0);
}
uid_t
__wrap_geteuid(void)
{
	return (0);
}
struct utmpx *
__wrap_pututxline(const struct utmpx *u __unused)
{
	return (NULL);
}
int
__wrap_sysctlbyname(const char *name, void *out, size_t *len,
    const void *in __unused, size_t ilen __unused)
{
	if (strcmp(name, "vm.stats.vm.v_swappgsin") != 0 ||
	    *len != sizeof(uint64_t))
		return (errno = ENOENT, -1);
	*(uint64_t *)out = 0;
	return (0);
}

int
__wrap_execl(const char *path, const char *arg, ...)
{
	va_list ap;
	const char *verb;

	if (strcmp(path, _PATH_CAPSULECTL) != 0 || strcmp(arg, "capsulectl") != 0)
		_exit(95);
	va_start(ap, arg);
	verb = va_arg(ap, const char *);
	event(strcmp(verb, "catatonia") == 0 ? 'C' : 'P');
	va_end(ap);
	_exit(plane_accepts ? 0 : 127);
}

static void
run(bool accept, bool shield, bool fast, bool quick, bool nosync,
    const char *expected)
{
	char output[32];
	char program[] = "reboot", options[] = "-flnp", synced[] = "-flp";
	char quick_option[] = "-q";
	char *args[] = { program, nosync ? options : synced, NULL, NULL };
	int pipefd[2], status;
	pid_t child;
	ssize_t n;
	size_t used = 0;

	ATF_REQUIRE_EQ(0, pipe(pipefd));
	ATF_REQUIRE((child = fork()) >= 0);
	if (child == 0) {
		close(pipefd[0]);
		events = pipefd[1];
		plane_accepts = accept;
		protected_init = shield;
		expected_flags = RB_POWEROFF | (nosync ? RB_NOSYNC : 0);
		setprogname(fast ? "fastboot" : "reboot");
		optreset = optind = 1;
		if (quick)
			args[2] = quick_option;
		exit(reboot_main(quick ? 3 : 2, args));
	}
	close(pipefd[1]);
	while ((n = read(pipefd[0], output + used, sizeof(output) - 1 - used)) > 0)
		used += n;
	output[used] = '\0';
	close(pipefd[0]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_MSG(WEXITSTATUS(status) == 0, "command exit status %d",
	    WEXITSTATUS(status));
	ATF_CHECK_STREQ(expected, output);
}

ATF_TC_WITHOUT_HEAD(accepted_shutdown);
ATF_TC_BODY(accepted_shutdown, tc)
{
	run(true, true, false, false, true, "P");
}
ATF_TC_WITHOUT_HEAD(legacy_fallback);
ATF_TC_BODY(legacy_fallback, tc)
{
	run(false, false, false, false, true, "PCITKR");
}
ATF_TC_WITHOUT_HEAD(protected_fallback);
ATF_TC_BODY(protected_fallback, tc)
{
	run(false, true, false, false, true, "PCITKR");
}
ATF_TC_WITHOUT_HEAD(fast_shutdown);
ATF_TC_BODY(fast_shutdown, tc)
{
	run(false, false, true, false, true, "CITKR");
}
ATF_TC_WITHOUT_HEAD(quick_shutdown);
ATF_TC_BODY(quick_shutdown, tc)
{
	run(false, true, false, true, true, "R");
}

ATF_TC_WITHOUT_HEAD(synced_fallback);
ATF_TC_BODY(synced_fallback, tc)
{
	run(false, false, false, false, false, "SPCITSKR");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, synced_fallback);
	ATF_TP_ADD_TC(tp, accepted_shutdown);
	ATF_TP_ADD_TC(tp, legacy_fallback);
	ATF_TP_ADD_TC(tp, protected_fallback);
	ATF_TP_ADD_TC(tp, fast_shutdown);
	ATF_TP_ADD_TC(tp, quick_shutdown);
	return (atf_no_error());
}
