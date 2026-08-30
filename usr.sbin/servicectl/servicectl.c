/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl — command-line interface to serviced(8).
 *
 * Each invocation opens a connection to serviced's control socket,
 * sends one command, prints the result, and exits.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/* Operator disable list; must match SERVICED_DISABLED_PATH in serviced.h. */
#define	SERVICED_DISABLED_PATH	"/Capabilities/Config/serviced/disabled"

/* Env override wins (for tests), else the capability-plane default. */
static const char *
disabled_path(void)
{
	const char *env = getenv("SERVICED_DISABLED_PATH");

	return ((env != NULL && env[0] != '\0') ? env : SERVICED_DISABLED_PATH);
}

/*
 * Ensure the parent directory of the disable list exists (e.g.
 * /Capabilities/db/serviced) so the atomic temp+rename can create the file
 * on a fresh system.  Best-effort: a real failure surfaces at mkstemp.
 */
static void
ensure_parent_dir(const char *path)
{
	char dir[PATH_MAX], *slash;

	if (strlcpy(dir, path, sizeof(dir)) >= sizeof(dir))
		return;
	slash = strrchr(dir, '/');
	if (slash == NULL || slash == dir)
		return;
	*slash = '\0';
	/* Create each missing component from the first slash onward. */
	for (char *p = dir + 1; *p != '\0'; p++) {
		if (*p == '/') {
			*p = '\0';
			(void)mkdir(dir, 0755);
			*p = '/';
		}
	}
	(void)mkdir(dir, 0755);
}

#include <libservice.h>

#include "serviced_ctl.h"
#include "servicectl.h"

/*
 * Capability control path (docs/capability-authority-model.md, P3): resolve
 * SERVICED_CONTROL_NAME over the ambient discovery plane a login session
 * inherits and issue the request/reply as a single libservice call.  Authority
 * is the SVC_RIGHTS_ADMIN on the grant (an admin login session), not a socket
 * peer credential.  Returns 0 and sets *status_out on a completed RPC; returns
 * -1 (capability plane unavailable / transport error) so the caller can fall
 * back to the getpeereid socket during the dual-path rollout.
 */
static int
sctl_rpc_capability(uint32_t op, uint32_t flags, const char *payload,
    char *summary, size_t sumlen, int *status_out)
{
	struct service_session *session;
	struct service_message message;
	struct service_reply reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct sctl_request *req;
	const struct sctl_reply *rhdr;
	char reqbuf[sizeof(struct sctl_request) + SERVICED_CTL_MAX_PAYLOAD];
	char rplbuf[sizeof(struct sctl_reply) + SERVICED_CTL_SUMMARY_MAX];
	size_t payload_length;
	int fd;

	payload_length = payload != NULL ? strlen(payload) : 0;
	if (payload_length > SERVICED_CTL_MAX_PAYLOAD)
		errx(EX_USAGE, "request payload exceeds protocol limit");

	if (service_open(SERVICED_CONTROL_NAME, &fd) != 0)
		return (-1);
	if (service_session_create(fd, &session) != 0) {
		(void)close(fd);
		return (-1);
	}

	req = (struct sctl_request *)reqbuf;
	memset(req, 0, sizeof(*req));
	req->version = SERVICED_CTL_VERSION;
	req->op = op;
	req->flags = flags;
	req->datalen = (uint32_t)payload_length;
	if (payload_length > 0)
		memcpy(reqbuf + sizeof(*req), payload, payload_length);

	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = reqbuf;
	message.length = sizeof(*req) + payload_length;

	memset(&reply, 0, sizeof(reply));
	reply.size = sizeof(reply);
	reply.data = rplbuf;
	reply.capacity = sizeof(rplbuf);

	options.timeout_ms = 30000;

	if (service_session_call(session, &message, &reply, &options) != 0) {
		service_session_close(session);
		return (-1);
	}
	if (reply.length < sizeof(struct sctl_reply)) {
		service_session_close(session);
		errx(1, "short control reply");
	}
	rhdr = (const struct sctl_reply *)rplbuf;
	if (rhdr->flags > SERVICED_CTL_SUMMARY_MAX ||
	    reply.length != sizeof(struct sctl_reply) + (size_t)rhdr->flags) {
		service_session_close(session);
		errx(1, "invalid control reply summary length");
	}
	if (rhdr->flags > 0 && summary != NULL && sumlen > 0) {
		size_t tocopy = rhdr->flags;

		if (tocopy >= sumlen)
			tocopy = sumlen - 1;
		memcpy(summary, rplbuf + sizeof(struct sctl_reply), tocopy);
		summary[tocopy] = '\0';
	}
	*status_out = (int)rhdr->status;
	service_session_close(session);
	return (0);
}

/*
 * Send a request over the capability control plane (system.serviced) and return
 * the status code (0 = success).  The getpeereid control socket was retired
 * (docs/capability-authority-model.md), so this is the only transport: a context
 * with no ambient discovery channel — i.e. not an admin login session — cannot
 * reach serviced's control plane.
 */
static int
sctl_rpc(uint32_t op, uint32_t flags, const char *payload,
    char *summary, size_t sumlen)
{
	int status;

	if (sctl_rpc_capability(op, flags, payload, summary, sumlen,
	    &status) != 0)
		errx(EX_UNAVAILABLE,
		    "cannot reach serviced control plane (system.serviced): "
		    "no admin discovery channel");
	return (status);
}

static int
cmd_status(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_STATUS, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("status: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("serviced: running\n");
	return (0);
}

static int
cmd_services(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_SERVICES, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("services: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	return (0);
}

static int
cmd_reload(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_RELOAD, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("reload: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("reload: ok\n");
	return (0);
}

static int
cmd_start(const char *label)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_START_SVC, 0, label,
	    summary, sizeof(summary));
	if (error != 0) {
		warnx("start: %s", summary[0] != '\0' ?
		    summary : strerror(error));
		return (1);
	}
	printf("%s\n", summary[0] != '\0' ? summary : "start: ok");
	return (0);
}

static int
cmd_stop(const char *label)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_STOP_SVC, 0, label,
	    summary, sizeof(summary));
	if (error != 0) {
		warnx("stop: %s", summary[0] != '\0' ?
		    summary : strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s\n", summary);
	else
		printf("stop: ok\n");
	return (0);
}

/*
 * restart = stop, then start, driving the same serviced control ops the stop
 * and start verbs use (toward service(8) parity).  serviced's stop is
 * asynchronous — the unit passes through STOPPING before it reaches STOPPED —
 * so a start issued immediately can race the shutdown and be refused with
 * EALREADY ("not stopped").  Retry the start briefly so restart is reliable
 * without serviced needing a dedicated restart op.  A unit already stopped is
 * fine: the stop reports EALREADY and we proceed to start it.
 */
static int
cmd_restart(const char *label)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error, attempt;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_STOP_SVC, 0, label, summary, sizeof(summary));
	/*
	 * EALREADY means the unit was already stopped or already stopping —
	 * both are fine for a restart.  Any other error (ENOENT, EPERM for a
	 * core unit, ...) is fatal and reported as the stop failure.
	 */
	if (error != 0 && error != EALREADY) {
		warnx("restart: %s", summary[0] != '\0' ?
		    summary : strerror(error));
		return (1);
	}

	/* Poll for up to ~15s (comfortably past the default 5s stop timeout and
	 * its SIGKILL escalation) for the unit to reach STOPPED, then start. */
	for (attempt = 0; attempt < 150; attempt++) {
		summary[0] = '\0';
		error = sctl_rpc(SCTL_OP_START_SVC, 0, label,
		    summary, sizeof(summary));
		if (error == 0) {
			printf("%s\n", summary[0] != '\0' ?
			    summary : "restart: ok");
			return (0);
		}
		/* Still shutting down: wait for STOPPED and retry. */
		if (error == EALREADY) {
			usleep(100000);
			continue;
		}
		break;
	}

	warnx("restart: %s", summary[0] != '\0' ? summary : strerror(error));
	return (1);
}

static bool
valid_bundle_id(const char *id)
{
	size_t i, n;

	n = strlen(id);
	if (n == 0 || n >= 256)
		return (false);
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)id[i];

		if (!isalnum(c) && c != '.' && c != '-' && c != '_')
			return (false);
	}
	return (true);
}

/*
 * Rewrite the disable list with id added (add) or removed, atomically via a
 * temp file and rename(2).  Sets *changed when the effective set differs.  The
 * list is a plain one-identity-per-line file under /Capabilities.
 */
static int
disabled_edit(const char *id, bool add, bool *changed)
{
	FILE *in, *out;
	const char *path = disabled_path();
	char tmp[PATH_MAX], *line = NULL;
	size_t cap = 0;
	int fd;
	bool present = false;

	*changed = false;
	ensure_parent_dir(path);
	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >= (int)sizeof(tmp))
		return (errno = ENAMETOOLONG, -1);
	fd = mkstemp(tmp);
	if (fd == -1)
		return (-1);
	out = fdopen(fd, "w");
	if (out == NULL) {
		close(fd);
		unlink(tmp);
		return (-1);
	}
	in = fopen(path, "re");
	if (in != NULL) {
		while (getline(&line, &cap, in) != -1) {
			char *s = line;

			while (*s == ' ' || *s == '\t')
				s++;
			s[strcspn(s, " \t\r\n")] = '\0';
			if (*s == '\0' || *s == '#')
				continue;
			if (strcmp(s, id) == 0) {
				present = true;
				if (!add)
					continue;	/* drop it */
			}
			fprintf(out, "%s\n", s);
		}
		free(line);
		fclose(in);
	}
	if (add && !present) {
		fprintf(out, "%s\n", id);
		*changed = true;
	} else if (!add && present)
		*changed = true;
	if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
		fclose(out);
		unlink(tmp);
		return (-1);
	}
	if (fclose(out) != 0) {
		unlink(tmp);
		return (-1);
	}
	if (rename(tmp, path) == -1) {
		unlink(tmp);
		return (-1);
	}
	return (0);
}

static int
cmd_enable_disable(const char *id, bool disable)
{
	const char *verb = disable ? "disable" : "enable";
	char summary[SERVICED_CTL_SUMMARY_MAX];
	bool changed;
	int error;

	if (!valid_bundle_id(id))
		errx(EX_USAGE, "%s: invalid bundle identity '%s'", verb, id);
	if (disabled_edit(id, disable, &changed) == -1) {
		warn("%s: updating %s", verb, disabled_path());
		return (1);
	}
	if (!changed)
		printf("%s: %s already %sd\n", verb, id, verb);
	/* Apply immediately: a reload re-scans and honors the updated list. */
	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_RELOAD, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("%s: recorded, but reload failed: %s -- run "
		    "'servicectl reload'", verb, strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("%s: %s\n", verb, id);
	return (0);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: servicectl command [args]\n"
	    "\n"
	    "commands:\n"
	    "  status              show serviced status and service list\n"
	    "  services            list loaded services\n"
	    "  reload              reload service bundles\n"
	    "  start <label>       start a loaded service\n"
	    "  stop <label>        stop a running service\n"
	    "  restart <label>     stop then start a service\n"
	    "  enable <bundle-id>  clear a bundle's operator-disabled state\n"
	    "  disable <bundle-id> keep a bundle installed but unregistered\n"
	    "  install <path.cap>  install a .cap bundle to /Capabilities/\n"
	    "  verify <path.cap> [...] validate bundles and dependencies\n"
	    "  deps <program>      suggest component manifest dependencies\n"
	    "  bundles             list all registered bundles\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *cmd;
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	cmd = argv[0];

	if (strcmp(cmd, "status") == 0 && argc == 1)
		return (cmd_status());
	if (strcmp(cmd, "services") == 0 && argc == 1)
		return (cmd_services());
	if (strcmp(cmd, "reload") == 0 && argc == 1)
		return (cmd_reload());
	if (strcmp(cmd, "start") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "start requires a service label");
		return (cmd_start(argv[1]));
	}
	if (strcmp(cmd, "stop") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "stop requires a service label");
		return (cmd_stop(argv[1]));
	}
	if (strcmp(cmd, "restart") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "restart requires a service label");
		return (cmd_restart(argv[1]));
	}
	if (strcmp(cmd, "enable") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "enable requires a bundle identity");
		return (cmd_enable_disable(argv[1], false));
	}
	if (strcmp(cmd, "disable") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "disable requires a bundle identity");
		return (cmd_enable_disable(argv[1], true));
	}
	if (strcmp(cmd, "install") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "install requires a .cap bundle path");
		return (cmd_install(argv[1]));
	}
	if (strcmp(cmd, "verify") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "verify requires a .cap bundle path");
		return (cmd_verify(argc - 1, argv + 1));
	}
	if (strcmp(cmd, "deps") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "deps requires an executable path");
		return (cmd_deps(argv[1]));
	}
	if (strcmp(cmd, "bundles") == 0 && argc == 1)
		return (cmd_bundles());

	warnx("unknown command: %s", cmd);
	usage();
	return (1);
}
