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

#include <libservice.h>
#include <kldmgr_protocol.h>
#include <rebootctl_protocol.h>
#include <serviced_ctl.h>

static struct service_context *service_context;

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
	req.op = SCTL_OP_CHECK;
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

static FILE *
wait_for_input(const char *path)
{
	FILE *fp;
	unsigned int i;

	for (i = 0; i < 100; i++) {
		fp = fopen(path, "r");
		if (fp != NULL)
			return (fp);
		usleep(100000);
	}
	return (NULL);
}

static int
wait_for_service(const char *name)
{
	unsigned int i;
	int fd;

	for (i = 0; i < 100; i++) {
		if (service_connect(service_context, name, &fd) == 0)
			return (fd);
		usleep(100000);
	}
	return (-1);
}

static int
kld_client(const char *inpath, const char *outpath)
{
	char op[32], name[KLDMGR_NAME_MAX];
	struct {
		struct kldmgr_msg msg;
		struct kldmgr_module_request module;
	} req;
	struct service_session *session;
	struct service_message message;
	struct service_reply service_reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	FILE *in, *out;
	int fd, raw_op;

	if (service_acquire(&service_context) == -1)
		err(1, "initialize managed service");
	in = wait_for_input(inpath);
	if (in == NULL)
		err(1, "open %s", inpath);
	out = fopen(outpath, "w");
	if (out == NULL)
		err(1, "fopen %s", outpath);
	memset(op, 0, sizeof(op));
	memset(name, 0, sizeof(name));
	raw_op = 0;
	if (fscanf(in, "%31s %127s %d", op, name, &raw_op) < 1)
		errx(1, "invalid command file");
	fclose(in);
	if (service_enter_capability_mode(service_context) == -1 ||
	    service_ready(service_context) == -1)
		err(1, "enter managed service sandbox");

	fd = wait_for_service("org.5bsd.system.kldmgr");
	if (fd == -1)
		err(1, "service_lookup kldmgrd");
	if (service_session_create(fd, &session) == -1)
		err(1, "create kld client");
	options.timeout_ms = 30000;
	memset(&req, 0, sizeof(req));
	if (strcmp(op, "list") == 0)
		req.msg.opcode = KLDMGR_OP_LIST;
	else if (strcmp(op, "load") == 0)
		req.msg.opcode = KLDMGR_OP_LOAD;
	else if (strcmp(op, "unload") == 0)
		req.msg.opcode = KLDMGR_OP_UNLOAD;
	else if (strcmp(op, "raw") == 0)
		req.msg.opcode = (uint16_t)raw_op;
	else
		errx(1, "unknown kld operation: %s", op);
	req.msg.magic = KLDMGR_MAGIC;
	req.msg.version = KLDMGR_ABI_VERSION;
	strlcpy(req.module.name, name, sizeof(req.module.name));
	if (req.msg.opcode == KLDMGR_OP_LIST) {
		char buf[sizeof(struct kldmgr_msg) +
		    sizeof(struct kldmgr_list_reply) +
		    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
		const struct kldmgr_msg *header;
		const struct kldmgr_list_reply *reply;
		uint32_t i, count;

		memset(&message, 0, sizeof(message));
		message.size = sizeof(message);
		message.data = &req;
		message.length = sizeof(req.msg);
		memset(&service_reply, 0, sizeof(service_reply));
		service_reply.size = sizeof(service_reply);
		service_reply.data = buf;
		service_reply.capacity = sizeof(buf);
		if (service_session_call(session, &message, &service_reply,
		    &options) == -1)
			err(1, "call kld list");
		if (service_reply.length < sizeof(*header) + sizeof(*reply))
			errx(1, "short kld list reply: %zu",
			    service_reply.length);
		header = (const void *)buf;
		reply = (const void *)(header + 1);
		count = reply->count;
		fprintf(out, "status=%d\ncount=%u\n",
		    header->status == 0 ? 0 : 1, count);
		for (i = 0; i < count &&
		    sizeof(*header) + sizeof(*reply) +
		    (i + 1) * sizeof(reply->entries[0]) <=
		    service_reply.length; i++) {
			fprintf(out, "module.%u.id=%d\nmodule.%u.name=%s\n",
			    i, reply->entries[i].id, i, reply->entries[i].name);
		}
	} else {
		struct {
			struct kldmgr_msg msg;
			struct kldmgr_id_reply id;
		} reply;
		int status;

		memset(&message, 0, sizeof(message));
		message.size = sizeof(message);
		message.data = &req;
		message.length = sizeof(req);
		memset(&service_reply, 0, sizeof(service_reply));
		service_reply.size = sizeof(service_reply);
		service_reply.data = &reply;
		service_reply.capacity = sizeof(reply);
		if (service_session_call(session, &message, &service_reply,
		    &options) == -1) {
			status = 1;
			reply.id.id = -1;
		} else {
			if (service_reply.length < sizeof(reply.msg))
				errx(1, "short kld reply: %zu",
				    service_reply.length);
			status = reply.msg.status == 0 ? 0 :
			    reply.msg.status == -ENOENT ? 2 :
			    reply.msg.status == -EACCES ? 3 : 1;
		}
		fprintf(out, "status=%d\nid=%d\n", status, reply.id.id);
	}
	fclose(out);
	service_session_close(session);
	for (;;)
		pause();
}

static int
reboot_client(const char *operation, const char *outpath)
{
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_request request;
	} req;
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_status_reply status;
	} reply;
	struct service_session *session;
	struct service_message message;
	struct service_reply service_reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	FILE *out;
	int fd;

	if (service_acquire(&service_context) == -1)
		err(1, "initialize managed service");
	out = fopen(outpath, "w");
	if (out == NULL)
		err(1, "fopen %s", outpath);
	if (service_enter_capability_mode(service_context) == -1 ||
	    service_ready(service_context) == -1)
		err(1, "enter managed service sandbox");
	memset(&req, 0, sizeof(req));
	if (strcmp(operation, "status") == 0)
		req.msg.opcode = REBOOTCTL_OP_STATUS;
	else if (strcmp(operation, "reboot") == 0)
		req.msg.opcode = REBOOTCTL_OP_REBOOT;
	else if (strcmp(operation, "unknown") == 0)
		req.msg.opcode = 99;
	else if (strcmp(operation, "invalid-flags") == 0) {
		req.msg.opcode = REBOOTCTL_OP_REBOOT;
		req.request.howto = UINT32_MAX;
	} else
		errx(1, "unknown reboot operation: %s", operation);
	req.msg.magic = REBOOTCTL_MAGIC;
	req.msg.version = REBOOTCTL_ABI_VERSION;
	if (service_connect(service_context, "org.5bsd.system.reboot",
	    &fd) == -1)
		err(1, "service_lookup rebootd");
	if (service_session_create(fd, &session) == -1)
		err(1, "create reboot client");
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = &req;
	message.length = sizeof(req.msg) +
	    (req.msg.opcode == REBOOTCTL_OP_STATUS ? 0 :
	    sizeof(req.request));
	memset(&service_reply, 0, sizeof(service_reply));
	service_reply.size = sizeof(service_reply);
	service_reply.data = &reply;
	service_reply.capacity = sizeof(reply);
	options.timeout_ms = 30000;
	if (service_session_call(session, &message, &service_reply,
	    &options) == -1)
		fprintf(out, "1\n");
	else {
		int status;

		status = reply.msg.status == 0 ? 0 :
		    reply.msg.status == -EACCES ? 3 : 1;
		fprintf(out, "%d\n", status);
	}
	fclose(out);
	service_session_close(session);
	for (;;)
		pause();
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capd_protocol_fixture control-oversized socket\n"
	    "       capd_protocol_fixture control-deny socket output\n"
	    "       capd_protocol_fixture kld [input output]\n"
	    "       capd_protocol_fixture reboot operation output\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "control-oversized") == 0)
		return (control_oversized(argv[2]));
	if (argc == 4 && strcmp(argv[1], "control-deny") == 0)
		return (control_deny(argv[2], argv[3]));
	if ((argc == 2 || argc == 4) && strcmp(argv[1], "kld") == 0)
		return (kld_client(argc == 4 ? argv[2] : "cmd.in",
		    argc == 4 ? argv[3] : "result.out"));
	if (argc == 4 && strcmp(argv[1], "reboot") == 0)
		return (reboot_client(argv[2], argv[3]));
	usage();
}
