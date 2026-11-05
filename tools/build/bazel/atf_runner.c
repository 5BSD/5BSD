/* SPDX-License-Identifier: BSD-2-Clause */
/* Execute one declared ATF shell or program case under the Bazel test protocol. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
required(const char *key)
{
	const char *value = getenv(key);
	if (value == NULL || *value == '\0') {
		fprintf(stderr, "missing test setting: %s\n", key);
		exit(1);
	}
	return (value);
}

static void
join(char *out, const char *root, const char *leaf)
{
	int n = snprintf(out, PATH_MAX, "%s/%s", root, leaf);
	if (n < 0 || n >= PATH_MAX) {
		fprintf(stderr, "test path too long\n");
		exit(1);
	}
}

static void
setting(const char *key, const char *value)
{
	if (setenv(key, value, 1) != 0) {
		perror(key);
		exit(1);
	}
}

/* Installed-image qualification opts in through argv, never inherited PATH. */
static const char *
installed_path(int argc, char **argv)
{
    struct stat st;
    char *copy, *next, *directory;

    if (argc == 1)
        return (NULL);
    if (argc != 3 || strcmp(argv[1], "--installed-path") != 0) {
        fprintf(stderr, "usage: atf_runner [--installed-path absolute-search-path]\n");
        exit(1);
    }
    copy = strdup(argv[2]);
    if (copy == NULL) {
        perror("strdup");
        exit(1);
    }
    next = copy;
    while ((directory = strsep(&next, ":")) != NULL) {
        if (directory[0] != '/' || stat(directory, &st) != 0 ||
            !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "installed PATH entry must be an existing absolute directory: %s\n", directory);
            free(copy);
            exit(1);
        }
    }
    free(copy);
    return (argv[2]);
}

/* Zero preserves the outer Bazel deadline for cases not yet migrated. */
static int
phase_timeout(const char *key, unsigned int *seconds)
{
	const char *value = getenv(key);
	char *end;
	unsigned long parsed;

	*seconds = 0;
	if (value == NULL)
		return (0);
	if (*value == '\0' || strspn(value, "0123456789") != strlen(value))
		goto invalid;
	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno != 0 || *end != '\0' || parsed > INT_MAX)
		goto invalid;
	*seconds = (unsigned int)parsed;
	return (0);
invalid:
	fprintf(stderr, "invalid phase timeout: %s\n", key);
	return (-1);
}

static void
child_changed(int signo)
{
	(void)signo;
}

/* Block SIGCHLD before fork so exit between waitpid and waiting cannot be lost.
 * Each phase has a process group; timeout kills descendants before cleanup.
 * The monotonic deadline is retained across interrupts.  -2 means timeout.
 */
static int
run_phase(const char *executable, char **arguments, unsigned int seconds,
    int stdin_tty)
{
	pid_t child, waited;
	int status = -1, saved_errno, result = -1;
	int master = -1, slave = -1;
	char terminal_path[PATH_MAX];
	sigset_t signals, previous;
	struct sigaction action, old_action;
	struct timespec deadline, now, remaining;

	sigemptyset(&signals);
	sigaddset(&signals, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &signals, &previous) != 0) {
		perror("sigprocmask");
		return (-1);
	}
	memset(&action, 0, sizeof(action));
	action.sa_handler = child_changed;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGCHLD, &action, &old_action) != 0) {
		(void)sigprocmask(SIG_SETMASK, &previous, NULL);
		return (-1);
	}
	if (seconds != 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
			goto restore;
		deadline.tv_sec += seconds;
	}
	if (stdin_tty) {
		master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
			perror("allocate stdin pseudo-terminal");
			goto restore;
		}
		saved_errno = ptsname_r(master, terminal_path, sizeof(terminal_path));
		if (saved_errno != 0) {
			errno = saved_errno;
			perror("ptsname_r");
			goto restore;
		}
		slave = open(terminal_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (slave < 0) {
			perror(terminal_path);
			goto restore;
		}
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		goto restore;
	}
	if (child == 0) {
		if (setpgid(0, 0) != 0 ||
		    sigaction(SIGCHLD, &old_action, NULL) != 0 ||
		    sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
			_exit(127);
		if (stdin_tty) {
			/* master can occupy fd 0 if the caller closed stdin. */
			(void)close(master);
			if (dup2(slave, STDIN_FILENO) < 0)
				_exit(127);
			if (slave != STDIN_FILENO)
				(void)close(slave);
		}
		execv(executable, arguments);
		perror(executable);
		_exit(127);
	}
	if (slave >= 0) {
		(void)close(slave);
		slave = -1;
	}
	/* Either parent or child may establish the group first. */
	if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
		perror("setpgid");
		goto terminate;
	}
	for (;;) {
		waited = waitpid(child, &status, seconds != 0 ? WNOHANG : 0);
		if (waited == child) {
			result = status;
			break;
		}
		if (waited < 0) {
			if (errno == EINTR)
				continue;
			perror("waitpid");
			break;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			break;
		remaining.tv_sec = deadline.tv_sec - now.tv_sec;
		remaining.tv_nsec = deadline.tv_nsec - now.tv_nsec;
		if (remaining.tv_nsec < 0) {
			remaining.tv_sec--;
			remaining.tv_nsec += 1000000000;
		}
		if (remaining.tv_sec < 0 ||
		    (remaining.tv_sec == 0 && remaining.tv_nsec == 0)) {
			result = -2;
			break;
		}
		if (sigtimedwait(&signals, NULL, &remaining) < 0 &&
		    errno != EINTR && errno != EAGAIN) {
			perror("sigtimedwait");
			break;
		}
	}
terminate:
	/* Also remove descendants of a phase which exited normally. */
	(void)kill(-child, SIGKILL);
	if (result < 0) {
		(void)kill(child, SIGKILL);
		while (waitpid(child, &status, 0) < 0 && errno == EINTR)
			continue;
	}
restore:
	saved_errno = errno;
	if (slave >= 0)
		(void)close(slave);
	if (master >= 0)
		(void)close(master);
	(void)sigaction(SIGCHLD, &old_action, NULL);
	if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
		return (-1);
	errno = saved_errno;
	return (result);
}

/* Bazel's action status is distinct from an individual ATF case outcome. */
static void
xml_text(FILE *stream, const char *text)
{
	for (; *text != '\0'; text++) {
		switch (*text) {
		case '&': fputs("&amp;", stream); break;
		case '<': fputs("&lt;", stream); break;
		case '>': fputs("&gt;", stream); break;
		case '"': fputs("&quot;", stream); break;
		case '\'': fputs("&apos;", stream); break;
		default: fputc((unsigned char)*text, stream); break;
		}
	}
}

static int
report_result(const char *test_case, const char *outcome, const char *reason)
{
	const char *path = getenv("XML_OUTPUT_FILE");
	FILE *stream;
	int error;

	printf("ATF case %s: %s%s%s\n", test_case, outcome,
	    reason != NULL ? ": " : "", reason != NULL ? reason : "");
	if (path == NULL || *path == '\0') {
		/* Uninstrumented installed-image callers still require a pass. */
		if (reason != NULL)
			fprintf(stderr, "nonpassing ATF outcome requires XML reporting\n");
		return (reason != NULL);
	}
	stream = fopen(path, "w");
	if (stream == NULL) {
		perror(path);
		return (1);
	}
	fprintf(stream, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	    "<testsuites><testsuite name=\"atf\" tests=\"1\" failures=\"0\" "
	    "errors=\"0\" skipped=\"%d\"><testcase name=\"", reason != NULL);
	xml_text(stream, test_case);
	fputs("\">", stream);
	if (reason != NULL) {
		fputs("<skipped message=\"", stream);
		xml_text(stream, outcome);
		fputs(": ", stream);
		xml_text(stream, reason);
		fputs("\"/>", stream);
	}
	fputs("</testcase></testsuite></testsuites>\n", stream);
	error = ferror(stream);
	if (fclose(stream) != 0 || error) {
		fprintf(stderr, "cannot write ATF XML result: %s\n", path);
		return (1);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	const char *execution_path = installed_path(argc, argv);
	char root[PATH_MAX], bin[PATH_MAX], shell[PATH_MAX], interpreter[PATH_MAX];
	char data[PATH_MAX], libs[PATH_MAX], suite[PATH_MAX], body[PATH_MAX];
	char result[PATH_MAX], loader_path[PATH_MAX], *line = NULL;
	size_t line_capacity = 0;
	ssize_t line_length;
	const char *outcome = NULL, *reason = NULL;
	char key[64], config_path[PATH_MAX], *end, **arguments;
	long config_count;
	size_t argument_count = 0;
	const char *test_case = required("BSD_ATF_CASE");
	const char *harness = required("BSD_ATF_HARNESS");
	const char *interface = required("BSD_ATF_INTERFACE");
	const char *required_user = getenv("BSD_ATF_REQUIRED_USER");
	const char *executable;
	const char *loader = getenv("BSD_ATF_LOADER");
	const char *stdin_mode = getenv("BSD_ATF_STDIN_TTY");
	int stdin_tty = stdin_mode != NULL && strcmp(stdin_mode, "1") == 0;
	int use_loader = loader != NULL && strcmp(loader, "1") == 0;
	int shell_interface;
	char temporary[PATH_MAX];
	int status, cleanup_status = 0;
	unsigned int body_seconds, cleanup_seconds;
	const char *cleanup = getenv("BSD_ATF_CLEANUP");
	char *cleanup_case;
	FILE *stream;

	if (required_user != NULL && *required_user != '\0') {
		if (strcmp(required_user, "root") == 0 && geteuid() != 0)
			return (report_result(test_case, "skipped", "requires user root"));
		if (strcmp(required_user, "unprivileged") == 0 && geteuid() == 0)
			return (report_result(test_case, "skipped", "requires an unprivileged user"));
		if (strcmp(required_user, "root") != 0 &&
		    strcmp(required_user, "unprivileged") != 0) {
			fprintf(stderr, "invalid required-user setting: %s\n", required_user);
			return (1);
		}
	}

	if (stdin_mode != NULL && strcmp(stdin_mode, "0") != 0 && !stdin_tty) {
		fprintf(stderr, "invalid stdin pseudo-terminal setting\n");
		return (1);
	}
	shell_interface = strcmp(interface, "shell") == 0;
	if (!shell_interface && strcmp(interface, "program") != 0) {
		fprintf(stderr, "invalid ATF interface: %s\n", interface);
		return (1);
	}
	if ((loader != NULL && strcmp(loader, "0") != 0 && !use_loader) ||
	    (use_loader && shell_interface)) {
		fprintf(stderr, "invalid explicit ATF loader configuration\n");
		return (1);
	}
	join(root, required("TEST_SRCDIR"), required("TEST_WORKSPACE"));
	join(loader_path, root, "atf-loader/loader");
	join(bin, root, "atf-runtime/bin");
	join(shell, bin, "sh");
	join(interpreter, bin, "atf-sh");
	join(data, root, "atf-runtime/share");
	join(libs, root, "atf-runtime/lib");
	join(suite, root, "atf-suite");
	join(body, suite, harness);
	join(temporary, required("TEST_TMPDIR"), "atf.XXXXXX");
	if (mkdtemp(temporary) == NULL) {
		perror("mkdtemp");
		return (1);
	}
	join(result, temporary, "atf.result");
	setting("PATH", execution_path != NULL ? execution_path : bin);
	setting("ATF_LIBEXECDIR", bin);
	setting("ATF_PKGDATADIR", data);
	setting("ATF_SHELL", shell);
	setting("LD_LIBRARY_PATH", libs);
	setting("TMPDIR", temporary);
	setting("HOME", temporary);
	/* Match Kyua isolation: defaults are C, but cases may select a category. */
	const char *locale_vars[] = { "LANG", "LC_ALL", "LC_COLLATE", "LC_CTYPE",
	    "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", NULL };
	for (size_t i = 0; locale_vars[i] != NULL; i++) {
		if (unsetenv(locale_vars[i]) != 0) {
			perror("unsetenv locale");
			return (1);
		}
	}
	setting("TZ", "UTC");
	char locale_path[PATH_MAX];
	join(locale_path, root, "atf-runtime/locale");
	setting("PATH_LOCALE", locale_path);
	if (chdir(temporary) != 0) {
		perror(temporary);
		return (1);
	}
	config_count = strtol(required("BSD_ATF_CONFIG_COUNT"), &end, 10);
	if (*end != '\0' || config_count < 0 || config_count > 1024) {
		fprintf(stderr, "invalid ATF configuration count\n");
		return (1);
	}
	arguments = calloc(10 + 2 * (size_t)config_count, sizeof(*arguments));
	if (arguments == NULL) {
		perror("calloc");
		return (1);
	}
	executable = use_loader ? loader_path : (shell_interface ? interpreter : body);
	arguments[argument_count++] = (char *)executable;
	if (use_loader) {
		arguments[argument_count++] = "--";
		arguments[argument_count++] = body;
		fprintf(stderr, "ATF explicit loader: %s\n", loader_path);
	} else if (shell_interface)
		arguments[argument_count++] = body;
	arguments[argument_count++] = "-s";
	arguments[argument_count++] = suite;
	arguments[argument_count++] = "-r";
	arguments[argument_count++] = result;
	for (long i = 0; i < config_count; i++) {
		snprintf(key, sizeof(key), "BSD_ATF_CONFIG_PATH_%ld", i);
		join(config_path, root, required(key));
		snprintf(key, sizeof(key), "BSD_ATF_CONFIG_NAME_%ld", i);
		arguments[argument_count++] = "-v";
		if (asprintf(&arguments[argument_count++], "%s=%s",
		    required(key), config_path) < 0) {
			perror("asprintf");
			return (1);
		}
	}
	arguments[argument_count++] = (char *)test_case;
	if (cleanup != NULL && strcmp(cleanup, "0") != 0 &&
	    strcmp(cleanup, "1") != 0) {
		fprintf(stderr, "invalid ATF cleanup setting\n");
		return (1);
	}
	if (phase_timeout("BSD_ATF_BODY_TIMEOUT", &body_seconds) != 0 ||
	    phase_timeout("BSD_ATF_CLEANUP_TIMEOUT", &cleanup_seconds) != 0)
		return (1);
	status = run_phase(executable, arguments, body_seconds, stdin_tty);
	/* A failed body still needs cleanup; retain its original result. */
	if (cleanup != NULL && strcmp(cleanup, "1") == 0) {
		if (asprintf(&cleanup_case, "%s:cleanup", test_case) < 0) {
			perror("asprintf");
			return (1);
		}
		arguments[argument_count - 1] = cleanup_case;
		cleanup_status = run_phase(executable, arguments, cleanup_seconds, stdin_tty);
		free(cleanup_case);
	}
	if (status == -2 || cleanup_status == -2) {
		fprintf(stderr, "ATF case %s %s timed out\n", test_case,
		    cleanup_status == -2 ? "cleanup" : "body");
		return (1);
	}
	if (cleanup_status == -1 || !WIFEXITED(cleanup_status) ||
	    WEXITSTATUS(cleanup_status) != 0) {
		fprintf(stderr, "ATF case %s cleanup failed (wait status %d)\n",
		    test_case, cleanup_status);
		return (1);
	}
	stream = fopen(result, "r");
	if (stream == NULL) {
		perror(result);
		return (1);
	}
	line_length = getline(&line, &line_capacity, stream);
	if (line_length > 0 && line[line_length - 1] == '\n' &&
	    memchr(line, '\0', (size_t)line_length) == NULL &&
	    fgetc(stream) == EOF && !ferror(stream)) {
		line[line_length - 1] = '\0';
		if (strcmp(line, "passed") == 0)
			outcome = "passed";
		else if (strncmp(line, "expected_failure: ", 18) == 0) {
			outcome = "expected_failure";
			reason = line + 18;
		} else if (strncmp(line, "skipped: ", 9) == 0) {
			outcome = "skipped";
			reason = line + 9;
		}
		/* Reject empty reasons and control bytes, including embedded NULs. */
		if (reason != NULL && *reason == '\0')
			outcome = NULL;
		for (const unsigned char *p = (unsigned char *)line; *p; p++)
			if (*p < 32 && *p != '\t')
				outcome = NULL;
	}
	fclose(stream);
	if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "ATF case %s failed (wait status %d): %s\n",
		    test_case, status, line != NULL ? line : "no result");
		free(line);
		return (1);
	}
	if (outcome == NULL) {
		fprintf(stderr, "ATF case %s has a failed, unsupported or malformed result; "
		    "see %s: %s\n", test_case, result, line != NULL ? line : "");
		free(line);
		return (1);
	}
	status = report_result(test_case, outcome, reason);
	free(line);
	return (status);
}
