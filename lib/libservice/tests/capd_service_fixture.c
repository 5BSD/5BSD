/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Deterministic managed-service fixture for capability stack tests.
 */

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_bootstrap.h>
#include <serviced_svc_proto.h>

static char result_cwd[PATH_MAX];
static int result_dir_fd = -1;
static volatile sig_atomic_t enter_requested;

static void
request_capmode(int signal __unused)
{

	enter_requested = 1;
}

static int
legacy_ready_only(void)
{
	struct mac_capability_recvmsg_args ra;
	struct mac_capability_sendmsg_args sa;
	struct svc_req_hdr req;
	struct svc_reply reply;
	const uint64_t token = UINT64_C(0x5245414459);

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_READY;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = token;
	if (ioctl(service_channel_fd(), MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);
	for (;;) {
		memset(&reply, 0, sizeof(reply));
		memset(&ra, 0, sizeof(ra));
		ra.payload = &reply;
		ra.payload_len = sizeof(reply);
		if (ioctl(service_channel_fd(), MAC_CAPABILITY_RECVMSG, &ra) ==
		    -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (ra.reply_token != token)
			continue;
		if (ra.payload_len != sizeof(reply) || ra.nfds != 0) {
			errno = EPROTO;
			return (-1);
		}
		if (reply.status != 0) {
			errno = reply.status;
			return (-1);
		}
		return (0);
	}
}

static void
prepare_results(void)
{

	if (getcwd(result_cwd, sizeof(result_cwd)) == NULL)
		err(1, "getcwd");
	result_dir_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (result_dir_fd == -1)
		err(1, "open current directory");
}

static void
write_result(const char *path, const char *format, ...)
{
	va_list ap;
	FILE *out;
	const char *relative;
	int fd;

	relative = path;
	if (path[0] == '/' &&
	    strncmp(path, result_cwd, strlen(result_cwd)) == 0 &&
	    path[strlen(result_cwd)] == '/')
		relative = path + strlen(result_cwd) + 1;
	fd = openat(result_dir_fd, relative,
	    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		err(1, "openat %s", path);
	out = fdopen(fd, "w");
	if (out == NULL)
		err(1, "fdopen %s", path);
	va_start(ap, format);
	if (vfprintf(out, format, ap) < 0)
		err(1, "write %s", path);
	va_end(ap);
	if (fclose(out) == EOF)
		err(1, "close %s", path);
}

static void hold(void) __dead2;
static void
hold(void)
{

	for (;;)
		pause();
}

static void
require_confined_endpoint(int fd)
{

	errno = 0;
	if (cap_xfer_limit(fd, CAP_XFER_ONCE) != -1 || errno != ENOTCAPABLE)
		errx(1, "peer endpoint is not transfer-confined");
}

static int
scenario_ready(const char *result)
{

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	write_result(result, "CAPD-TEST/1 event=ready channel_fd=%d\n",
	    service_channel_fd());
	hold();
}

static int
scenario_provider(const char *registered, const char *result)
{
	char label[128], message[256];
	ssize_t n;
	int client;

	if (service_init() == -1)
		err(1, "service_init");
	/* Registration precedes READY so dependents cannot race the name. */
	if (service_register("org.test.ls-provider") == -1)
		err(1, "service_register");
	if (service_ready() == -1)
		err(1, "service_ready");
	write_result(registered,
	    "CAPD-TEST/1 event=registered name=org.test.ls-provider\n");
	client = service_accept(label, sizeof(label));
	if (client == -1)
		err(1, "service_accept");
	require_confined_endpoint(client);
	if (service_send(client, "hello", 6) == -1)
		err(1, "service_send");
	n = service_recv(client, message, sizeof(message), NULL);
	if (n == -1)
		err(1, "service_recv");
	write_result(result,
	    "CAPD-TEST/1 event=exchange client_label=%s message=%.*s confined=yes\n",
	    label, (int)n, message);
	close(client);
	hold();
}

static int
scenario_client(const char *result)
{
	char message[256];
	ssize_t n;
	int peer;

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	peer = service_lookup("org.test.ls-provider");
	if (peer == -1)
		err(1, "service_lookup");
	require_confined_endpoint(peer);
	n = service_recv(peer, message, sizeof(message), NULL);
	if (n == -1)
		err(1, "service_recv");
	if (service_send(peer, "world", 6) == -1)
		err(1, "service_send");
	write_result(result,
	    "CAPD-TEST/1 event=exchange greeting=%.*s confined=yes\n",
	    (int)n, message);
	close(peer);
	hold();
}

static int
scenario_lookup_missing(const char *result)
{
	int fd, saved_errno;

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	errno = 0;
	fd = service_lookup("no.such.service");
	saved_errno = errno;
	write_result(result,
	    "CAPD-TEST/1 event=lookup fd=%d errno=%d\n", fd, saved_errno);
	hold();
}

static int
scenario_register(const char *name, const char *result)
{
	int rc, saved_errno;

	if (service_init() == -1)
		err(1, "service_init");
	errno = 0;
	rc = service_register(name);
	saved_errno = errno;
	if (service_ready() == -1)
		err(1, "service_ready");
	write_result(result,
	    "CAPD-TEST/1 event=register pid=%jd name=%s rc=%d errno=%d\n",
	    (intmax_t)getpid(), name, rc, saved_errno);
	hold();
}

static int
scenario_self_lookup(const char *name, const char *result)
{
	int fd, saved_errno;

	if (service_init() == -1)
		err(1, "service_init");
	if (service_register(name) == -1)
		err(1, "service_register");
	if (service_ready() == -1)
		err(1, "service_ready");
	errno = 0;
	fd = service_lookup(name);
	saved_errno = errno;
	write_result(result,
	    "CAPD-TEST/1 event=self-lookup fd=%d errno=%d\n",
	    fd, saved_errno);
	if (fd != -1)
		close(fd);
	hold();
}

static int
scenario_token_inventory(const char *result)
{
	struct stat sb;
	pid_t pid;
	int confined, fd, fork_hidden, status, valid;

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	confined = 0;
	valid = 0;
	for (fd = 6; fd <= 8; fd++) {
		if (fstat(fd, &sb) == 0) {
			valid++;
			errno = 0;
			if (cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 &&
			    errno == ENOTCAPABLE)
				confined++;
		}
	}
	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		for (fd = 6; fd <= 8; fd++) {
			errno = 0;
			if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
				_exit(1);
		}
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid)
		err(1, "waitpid");
	fork_hidden = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 3 : 0;
	write_result(result,
	    "channel_fd=%d\ntoken_fds=6,7,8\nvalid_tokens=%d\n"
	    "confined_tokens=%d\nfork_hidden_tokens=%d\n",
	    service_channel_fd(), valid, confined, fork_hidden);
	hold();
}

static int
scenario_token_activate(const char *target, const char *result)
{
	int after_errno, before_errno, fd, token_fd, consumed;

	if (service_init() == -1)
		err(1, "service_init");
	token_fd = 6;
	fd = open(target, O_RDONLY);
	before_errno = fd == -1 ? errno : 0;
	if (fd != -1)
		close(fd);
	if (service_authorize_capabilities() == -1)
		err(1, "service_authorize_capabilities");
	/* Check before open() can reuse the consumed descriptor number. */
	errno = 0;
	consumed = fcntl(token_fd, F_GETFD) == -1 && errno == EBADF;
	fd = open(target, O_RDONLY);
	after_errno = fd == -1 ? errno : 0;
	write_result(result,
	    "before_denied=%d\nauthorize=ok\ntoken_consumed=%d\n"
	    "after_open=%s\nafter_errno=%d\n",
	    before_errno == EACCES || before_errno == EPERM, consumed,
	    fd >= 0 ? "ok" : "failed", after_errno);
	if (fd != -1)
		close(fd);
	if (service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_manifest_report(int argc, char **argv)
{
	const char *empty, *mode;

	if (argc != 5)
		errx(1, "manifest-report requires result and two literal arguments");
	if (service_init() == -1)
		err(1, "service_init");
	mode = getenv("APP_MODE");
	empty = getenv("EMPTY");
	write_result(argv[2],
	    "argc=3\narg1=%s\narg2=%s\nmode=%s\nempty=%s\n",
	    argv[3], argv[4], mode == NULL ? "missing" : mode,
	    empty == NULL ? "missing" : empty);
	if (service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_authorize_tokens(const char *result)
{
	if (service_init() == -1)
		err(1, "service_init");
	if (service_authorize_capabilities() == -1)
		err(1, "service_authorize_capabilities");
	write_result(result, "fds=6,7,8\nauthorized=yes\n");
	if (service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_capability_services(const char *result)
{
	static const char *const names[] = {
	    "mount", "node", "accounting", "identity"
	};
	struct mac_capability_info_args info;
	FILE *out;
	size_t i;
	int confined, fd;

	if (service_init() == -1)
		err(1, "service_init");
	if (getenv("ORACLED_TOKEN_FDS") != NULL ||
	    getenv("ORACLED_CAPABILITY_FDS") != NULL ||
	    getenv("SERVICED_COMPONENT_FDS") != NULL)
		errx(1, "legacy descriptor environment leaked");
	if (getenv(SERVICE_BOOTSTRAP_ENV) == NULL ||
	    strcmp(getenv(SERVICE_BOOTSTRAP_ENV), "5") != 0)
		errx(1, "bootstrap environment descriptor discovery missing");
	out = fopen(result, "w");
	if (out == NULL)
		err(1, "fopen %s", result);
	for (i = 0; i < nitems(names); i++) {
		fd = service_capability_fd(names[i]);
		if (fd == -1)
			err(1, "service_capability_fd %s", names[i]);
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    strcmp(info.name, names[i]) != 0)
			errx(1, "wrong capability service descriptor for %s",
			    names[i]);
		errno = 0;
		confined = cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 &&
		    errno == ENOTCAPABLE;
		fprintf(out, "%s=valid confined=%d\n", names[i], confined);
	}
	if (fclose(out) == EOF)
		err(1, "close %s", result);
	if (service_capability_fd("channel") != -1 || errno != EINVAL)
		errx(1, "invalid capability service name was accepted");
	if (service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_unregister(const char *name, const char *registered,
    const char *result)
{

	if (service_init() == -1 || service_register(name) == -1)
		err(1, "register initialization");
	write_result(registered, "register_status=0\n");
	if (service_unregister(name) == -1)
		err(1, "service_unregister");
	write_result(result, "unregister_status=0\n");
	if (service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_protect(const char *result)
{

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	if (service_protect(SERVICE_PROTECT_EXTERNAL) == -1)
		err(1, "service_protect");
	write_result(result,
	    "CAPD-TEST/1 event=protected pid=%jd protected=yes\n",
	    (intmax_t)getpid());
	hold();
}

static int
scenario_compat_ready(const char *argv0)
{
	const char *name;
	char path[256];

	if (service_init() == -1 || service_ready() == -1)
		err(1, "service initialization");
	name = strrchr(argv0, '/');
	name = name == NULL ? argv0 : name + 1;
	if (snprintf(path, sizeof(path), "%s.ready", name) >=
	    (int)sizeof(path))
		errx(1, "ready result path is too long");
	write_result(path, "ready\n");
	hold();
}

static int
scenario_compat_lookup(void)
{
	char result_path[256], target_path[256], target[256];
	const char *label;
	FILE *input;
	int fd, rc, saved_errno;

	if (service_init() == -1)
		err(1, "service_init");
	label = service_label();
	if (label == NULL || label[0] == '\0')
		errx(1, "service label is unavailable");
	if (snprintf(target_path, sizeof(target_path), "%s.target", label) >=
	    (int)sizeof(target_path) ||
	    snprintf(result_path, sizeof(result_path), "%s.result", label) >=
	    (int)sizeof(result_path))
		errx(1, "lookup fixture path is too long");
	input = fopen(target_path, "r");
	if (input == NULL)
		err(1, "fopen %s", target_path);
	if (fgets(target, sizeof(target), input) == NULL)
		errx(1, "empty lookup target");
	(void)fclose(input);
	target[strcspn(target, "\r\n")] = '\0';
	if (service_ready() == -1)
		err(1, "service readiness");
	errno = 0;
	fd = service_lookup(target);
	saved_errno = errno;
	rc = fd == -1 ? 1 : 0;
	write_result(result_path, "fd=%d\nerrno=%d\nrc=%d\n",
	    fd, saved_errno, rc);
	if (fd != -1)
		close(fd);
	return (rc);
}

static int
scenario_readiness_gate(const char *protocol_result,
    const char *capmode_result)
{

	if (service_init() == -1)
		err(1, "service_init");
	if (signal(SIGUSR1, request_capmode) == SIG_ERR)
		err(1, "signal");
	if (legacy_ready_only() == -1)
		err(1, "legacy READY");
	write_result(protocol_result, "pid=%jd protocol_ready=1\n",
	    (intmax_t)getpid());
	while (!enter_requested)
		pause();
	if (cap_enter() == -1)
		err(1, "cap_enter");
	write_result(capmode_result, "pid=%jd capmode=1\n",
	    (intmax_t)getpid());
	hold();
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: capd_service_fixture ready result\n"
	    "       capd_service_fixture provider registered result\n"
	    "       capd_service_fixture client result\n"
	    "       capd_service_fixture lookup-missing result\n"
	    "       capd_service_fixture register name result\n"
	    "       capd_service_fixture self-lookup name result\n"
	    "       capd_service_fixture token-inventory result\n"
	    "       capd_service_fixture token-activate target result\n"
	    "       capd_service_fixture manifest-report result arg1 arg2\n"
	    "       capd_service_fixture authorize-tokens result\n"
	    "       capd_service_fixture capability-services result\n"
	    "       capd_service_fixture unregister name registered result\n"
	    "       capd_service_fixture protect result\n"
	    "       capd_service_fixture compat-ready\n"
	    "       capd_service_fixture compat-lookup\n"
	    "       capd_service_fixture readiness-gate protocol capmode\n");
	exit(64);
}

int
main(int argc, char **argv)
{

	prepare_results();
	if (argc == 3 && strcmp(argv[1], "ready") == 0)
		return (scenario_ready(argv[2]));
	if (argc == 4 && strcmp(argv[1], "provider") == 0)
		return (scenario_provider(argv[2], argv[3]));
	if (argc == 3 && strcmp(argv[1], "client") == 0)
		return (scenario_client(argv[2]));
	if (argc == 3 && strcmp(argv[1], "lookup-missing") == 0)
		return (scenario_lookup_missing(argv[2]));
	if (argc == 4 && strcmp(argv[1], "register") == 0)
		return (scenario_register(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "self-lookup") == 0)
		return (scenario_self_lookup(argv[2], argv[3]));
	if (argc == 3 && strcmp(argv[1], "token-inventory") == 0)
		return (scenario_token_inventory(argv[2]));
	if (argc == 4 && strcmp(argv[1], "token-activate") == 0)
		return (scenario_token_activate(argv[2], argv[3]));
	if (argc >= 2 && strcmp(argv[1], "manifest-report") == 0)
		return (scenario_manifest_report(argc, argv));
	if (argc == 3 && strcmp(argv[1], "authorize-tokens") == 0)
		return (scenario_authorize_tokens(argv[2]));
	if (argc == 3 && strcmp(argv[1], "capability-services") == 0)
		return (scenario_capability_services(argv[2]));
	if (argc == 5 && strcmp(argv[1], "unregister") == 0)
		return (scenario_unregister(argv[2], argv[3], argv[4]));
	if (argc == 3 && strcmp(argv[1], "protect") == 0)
		return (scenario_protect(argv[2]));
	if (argc == 2 && strcmp(argv[1], "compat-ready") == 0)
		return (scenario_compat_ready(argv[0]));
	if (argc == 2 && strcmp(argv[1], "compat-lookup") == 0)
		return (scenario_compat_lookup());
	if (argc == 4 && strcmp(argv[1], "readiness-gate") == 0)
		return (scenario_readiness_gate(argv[2], argv[3]));
	usage();
}
