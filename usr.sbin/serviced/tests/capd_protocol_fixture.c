/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Purpose-built protocol peer for capability-daemon integration tests.
 * Keeping malformed-wire and managed-service behavior here makes it part of
 * the normal build, with the same headers and compiler policy as the daemons.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <serviced_ctl.h>

static int
connect_local(const char *path)
{
	struct sockaddr_un un;
	int fd;

	if (strlen(path) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, path, sizeof(un.sun_path));
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static ssize_t
read_full(int fd, void *buf, size_t len)
{
	size_t off;
	ssize_t n;

	for (off = 0; off < len; off += (size_t)n) {
		n = read(fd, (char *)buf + off, len - off);
		if (n == 0)
			break;
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
	}
	return ((ssize_t)off);
}

static int
control_oversized(const char *path)
{
	struct sctl_request req;
	struct sctl_reply reply;
	ssize_t n;
	int fd;

	fd = connect_local(path);
	if (fd == -1)
		err(1, "connect %s", path);
	memset(&req, 0, sizeof(req));
	req.version = SERVICED_CTL_VERSION;
	req.op = SCTL_OP_START_SVC;
	req.datalen = SERVICED_CTL_MAX_PAYLOAD + 1;
	if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req))
		err(1, "write request");
	n = read_full(fd, &reply, sizeof(reply));
	if (n == 0)
		puts("rejected");
	else if (n == (ssize_t)sizeof(reply))
		printf("status=%u\n", reply.status);
	else if (n == -1)
		err(1, "read reply");
	else
		errx(1, "short reply: %zd", n);
	close(fd);
	return (0);
}

static int
control_deny(const char *path, const char *outpath)
{
	struct sctl_request req;
	struct sctl_reply reply;
	struct passwd *pw;
	FILE *out;
	ssize_t n;
	int connerr, fd;

	pw = getpwnam("nobody");
	if (pw == NULL)
		errx(1, "nobody account not found");
	if (setgid(pw->pw_gid) == -1 || setuid(pw->pw_uid) == -1)
		err(1, "drop privileges");
	if (setuid(0) != -1)
		errx(1, "privileges could be regained");

	fd = connect_local(path);
	connerr = fd == -1 ? errno : 0;
	out = fopen(outpath, "w");
	if (out == NULL)
		err(1, "fopen %s", outpath);
	if (connerr != 0) {
		fprintf(out, "connect_errno=%d\nstatus=-1\n", connerr);
		fclose(out);
		return (0);
	}

	memset(&req, 0, sizeof(req));
	req.version = SERVICED_CTL_VERSION;
	req.op = SCTL_OP_RELOAD;
	if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
		fprintf(out, "connect_errno=0\nstatus=-2\n");
	} else {
		n = read_full(fd, &reply, sizeof(reply));
		if (n == (ssize_t)sizeof(reply))
			fprintf(out, "connect_errno=0\nstatus=%u\n",
			    reply.status);
		else
			fprintf(out, "connect_errno=0\nstatus=-3\n");
	}
	fclose(out);
	close(fd);
	return (0);
}

static int
control_invalid(const char *path, const char *kind)
{
	static const char embedded_nul[] = { 'u', '\0', 'n', 'i', 't' };
	struct sctl_request req;
	struct sctl_reply reply;
	const void *payload;
	ssize_t n;
	int fd;

	fd = connect_local(path);
	if (fd == -1)
		err(1, "connect %s", path);
	memset(&req, 0, sizeof(req));
	req.version = SERVICED_CTL_VERSION;
	req.op = SCTL_OP_START_SVC;
	payload = NULL;
	if (strcmp(kind, "flags") == 0)
		req.flags = 1;
	else if (strcmp(kind, "nul") == 0) {
		req.datalen = sizeof(embedded_nul);
		payload = embedded_nul;
	} else
		errx(2, "unknown invalid request kind: %s", kind);
	if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req) ||
	    (payload != NULL && write(fd, payload, req.datalen) !=
	    (ssize_t)req.datalen))
		err(1, "write request");
	n = read_full(fd, &reply, sizeof(reply));
	if (n != (ssize_t)sizeof(reply))
		errx(1, "short reply: %zd", n);
	printf("status=%u\n", reply.status);
	close(fd);
	return (0);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capd_protocol_fixture control-oversized socket\n"
	    "       capd_protocol_fixture control-deny socket output\n"
	    "       capd_protocol_fixture control-invalid socket flags|nul\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "control-oversized") == 0)
		return (control_oversized(argv[2]));
	if (argc == 4 && strcmp(argv[1], "control-deny") == 0)
		return (control_deny(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "control-invalid") == 0)
		return (control_invalid(argv[2], argv[3]));
	usage();
}
