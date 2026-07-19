/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Process-boundary security and lifecycle tests for meshd(8).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ipc_proto.h"

#define main meshd_daemon_main
#include "meshd.c"
#undef main

static void
meshd_child_exit(int status)
{

	/* exit(3) lets coverage-instrumented children commit their own profile. */
	exit(status);
}

static void
bearer_write_frame(int fd, uint16_t type, uint16_t domain,
    const uint8_t *payload, size_t plen)
{
	uint8_t hdr[IPC_HDR_SIZE];

	ipc_hdr_encode(hdr, (uint32_t)plen, type, domain);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(fd, hdr, sizeof(hdr)));
	if (plen != 0)
		ATF_REQUIRE_EQ((ssize_t)plen, write(fd, payload, plen));
}

static void
bearer_write_discovery_event(int fd, uint32_t request_id, uint16_t event,
    uint16_t uuid, uint16_t value_handle)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	ipc_put_le16(body, event);
	ipc_put_le16(body + 2, uuid);
	ipc_put_le16(body + 20, value_handle);
	bearer_write_frame(fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    sizeof(payload));
}

static void
bearer_write_reply(int fd, uint32_t request_id, uint16_t status,
    uint16_t flags)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVER_REPLY_SIZE];
	size_t plen = IPC_OP_PREFIX_SIZE;

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, request_id, status, flags);
	if (status == IPC_ERR_NONE && flags == 0) {
		ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_DISCOVER);
		payload[IPC_OP_PREFIX_SIZE + 2] = 0;
		ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 4, 23);
		plen = sizeof(payload);
	}
	bearer_write_frame(fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload, plen);
}

static void
bearer_write_ack(int fd, uint32_t request_id, uint16_t status)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE];

	ipc_op_prefix_encode(payload, request_id, status, 0);
	bearer_write_frame(fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    sizeof(payload));
}

static void
write_config(const char *path)
{
	FILE *f;

	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fprintf(f,
	    "device_uuid 00112233445566778899aabbccddeeff\n"
	    "netkey 7dd7364cd842ad18c17c2b820c84c3d6\n"
	    "appkey 63964771734fbd76e3b40519d1d94a48\n"
	    "unicast_addr 0x0001\n"
	    "default_ttl 7\n") > 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE_EQ(0, chmod(path, 0600));
}

static pid_t
spawn_meshd(const char *config, const char *sock, const char *state,
    const char *manager)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char *argv[] = {
		    __DECONST(char *, "meshd"), __DECONST(char *, "-d"),
		    __DECONST(char *, "-f"), __DECONST(char *, config),
		    __DECONST(char *, "-s"), __DECONST(char *, sock),
		    __DECONST(char *, "-S"), __DECONST(char *, state),
		    __DECONST(char *, "-M"), __DECONST(char *, manager),
		    __DECONST(char *, "-B"),
		    __DECONST(char *, "/nonexistent/meshd-blued.sock"), NULL
		};
		int nullfd;

		nullfd = open("/dev/null", O_WRONLY);
		if (nullfd >= 0) {
			(void)dup2(nullfd, STDERR_FILENO);
			(void)close(nullfd);
		}
		meshd_child_exit(meshd_daemon_main(12, argv));
	}
	return (pid);
}

static int
wait_for_socket(const char *path)
{
	struct stat sb;
	int i;

	for (i = 0; i < 300; i++) {
		if (lstat(path, &sb) == 0 && S_ISSOCK(sb.st_mode))
			return (0);
		usleep(10000);
	}
	return (-1);
}

static int
connect_control(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		(void)close(fd);
		return (-1);
	}
	return (fd);
}

static int
run_meshd_startup_case(int argc, char **argv)
{
	pid_t child;
	int nullfd, status;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		nullfd = open("/dev/null", O_WRONLY);
		if (nullfd >= 0) {
			(void)dup2(nullfd, STDERR_FILENO);
			(void)close(nullfd);
		}
		optind = 1;
		optreset = 1;
		meshd_child_exit(meshd_daemon_main(argc, argv));
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(startup_failure_matrix);
ATF_TC_BODY(startup_failure_matrix, tc)
{
	char conf[128], corrupt[128], manager[128], state[128];
	char prog[] = "meshd", help[] = "-h", debug[] = "-d", fopt[] = "-f";
	char sopt[] = "-s", stateopt[] = "-S", manageropt[] = "-M";
	char beareropt[] = "-B", missingconf[] = "/nonexistent/meshd.conf";
	char missingsock[] = "/nonexistent/meshd.sock";
	char missingbearer[] = "/nonexistent/blued.sock";
	char *helpv[] = { prog, help };
	char *missingv[] = { prog, debug, fopt, missingconf };
	char *bindv[] = { prog, debug, fopt, conf, sopt, missingsock,
	    stateopt, state, manageropt, manager, beareropt, missingbearer };
	char *corruptv[] = { prog, debug, fopt, conf, sopt, missingsock,
	    stateopt, corrupt, manageropt, manager, beareropt, missingbearer };
	int fd;

	snprintf(conf, sizeof(conf), "/tmp/meshd-start-conf-%d", (int)getpid());
	snprintf(state, sizeof(state), "/tmp/meshd-start-state-%d", (int)getpid());
	snprintf(manager, sizeof(manager), "/tmp/meshd-start-mgr-%d", (int)getpid());
	snprintf(corrupt, sizeof(corrupt), "/tmp/meshd-start-bad-%d", (int)getpid());
	write_config(conf);
	ATF_CHECK_EQ(1, run_meshd_startup_case(2, helpv));
	ATF_CHECK_EQ(1, run_meshd_startup_case(4, missingv));
	ATF_CHECK_EQ(1, run_meshd_startup_case(12, bindv));
	fd = open(corrupt, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(4, write(fd, "junk", 4));
	close(fd);
	ATF_CHECK_EQ(1, run_meshd_startup_case(12, corruptv));
	(void)unlink(conf); (void)unlink(state); (void)unlink(manager);
	(void)unlink(corrupt);
}

static void
control_command(const char *sock, const char *command, char *reply,
    size_t reply_len)
{
	struct pollfd pfd;
	ssize_t n;
	int fd;

	fd = connect_control(sock);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(command),
	    write(fd, command, strlen(command)));
	pfd.fd = fd;
	pfd.events = POLLIN;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 3000));
	n = read(fd, reply, reply_len - 1);
	ATF_REQUIRE(n > 0);
	reply[n] = '\0';
	ATF_REQUIRE_EQ(0, close(fd));
}

static int
wait_child(pid_t pid)
{
	int status;

	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	if (WIFEXITED(status))
		return (WEXITSTATUS(status));
	return (128 + WTERMSIG(status));
}

ATF_TC_WITHOUT_HEAD(security_helpers);
ATF_TC_BODY(security_helpers, tc)
{
	char lock[] = "meshd-security-lock.XXXXXX";
	char longpath[PATH_MAX + 16], sockpath[PATH_MAX];
	char lockfile[PATH_MAX];
	struct sockaddr_un sun;
	struct stat sb;
	int fd, livefd, seedfd, sockfd, p[2], sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_CHECK_EQ(1, meshd_peer_authorized(sp[0]));
	ATF_CHECK_EQ(1, meshd_uid_authorized(0, 1000));
	ATF_CHECK_EQ(1, meshd_uid_authorized(1000, 1000));
	ATF_CHECK_EQ(0, meshd_uid_authorized(1001, 1000));
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_CHECK_EQ(0, meshd_peer_authorized(p[0]));
	memset(longpath, 'x', sizeof(longpath));
	longpath[sizeof(longpath) - 1] = '\0';
	ATF_CHECK_EQ(-1, meshd_state_lock(longpath));
	ATF_CHECK_EQ(-1, meshd_state_lock("/nonexistent/meshd-state"));
	ATF_CHECK_EQ(-1, meshd_set_nonblock(-1));
	ATF_CHECK_EQ(0, meshd_unlink_stale_socket("meshd-no-such-socket"));
	snprintf(sockpath, sizeof(sockpath), "meshd-stale-%ld.sock",
	    (long)getpid());
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(sockfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
	ATF_REQUIRE_EQ(0, bind(sockfd, (struct sockaddr *)&sun, sizeof(sun)));
	ATF_CHECK_EQ(0, meshd_unlink_stale_socket(sockpath));
	ATF_CHECK_EQ(-1, access(sockpath, F_OK));
	ATF_REQUIRE_EQ(0, close(sockfd));
	snprintf(sockpath, sizeof(sockpath), "meshd-live-%ld.sock",
	    (long)getpid());
	livefd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(livefd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
	ATF_REQUIRE_EQ(0, bind(livefd, (struct sockaddr *)&sun, sizeof(sun)));
	ATF_REQUIRE_EQ(0, listen(livefd, 1));
	errno = 0;
	ATF_CHECK_EQ(-1, meshd_unlink_stale_socket(sockpath));
	ATF_CHECK_EQ(EADDRINUSE, errno);
	ATF_CHECK_EQ(0, access(sockpath, F_OK));
	ATF_REQUIRE_EQ(0, close(livefd));
	ATF_REQUIRE_EQ(0, unlink(sockpath));
	seedfd = mkstemp(lock);
	ATF_REQUIRE(seedfd >= 0);
	ATF_REQUIRE_EQ(0, close(seedfd));
	ATF_REQUIRE_EQ(0, unlink(lock));
	fd = meshd_state_lock(lock);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK(S_ISREG(sb.st_mode));
	ATF_CHECK_EQ(geteuid(), sb.st_uid);
	ATF_CHECK_EQ(0600, sb.st_mode & 0777);
	ATF_CHECK_EQ(0, close(fd));
	ATF_CHECK_EQ(0, close(sp[0]));
	ATF_CHECK_EQ(0, close(sp[1]));
	ATF_CHECK_EQ(0, close(p[0]));
	ATF_CHECK_EQ(0, close(p[1]));
	snprintf(lockfile, sizeof(lockfile), "%s.lock", lock);
	(void)unlink(lockfile);
}

ATF_TC_WITHOUT_HEAD(daemon_static_lifecycle_helpers);
ATF_TC_BODY(daemon_static_lifecycle_helpers, tc)
{
	struct meshd_config cfg;
	struct meshd_node *nd;
	struct meshd_app_client *cl;
	char missing[PATH_MAX], manager[PATH_MAX], reply[256];
	char *av[] = { __DECONST(char *, "create-network") };
	pid_t child;
	int kq, sp[2], status;

	ATF_CHECK(meshd_now() > 0);
	meshd_quit = 0;
	meshd_on_signal(SIGTERM);
	ATF_CHECK_EQ(1, meshd_quit);
	meshd_quit = 0;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		usage();
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(1, WEXITSTATUS(status));

	ATF_REQUIRE(snprintf(missing, sizeof(missing), "missing-manager-%ld",
	    (long)getpid()) < (int)sizeof(missing));
	ATF_REQUIRE(snprintf(manager, sizeof(manager), "manager-state-%ld",
	    (long)getpid()) < (int)sizeof(manager));
	memset(&cfg, 0, sizeof(cfg));
	meshd_config_defaults(&cfg);
	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(0, meshd_mgr_persist(nd, manager));
	meshd_mgr_restore(nd, missing);
	ATF_CHECK(nd->mgr == NULL);
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK(nd->mgr_active);
	ATF_CHECK_EQ(0, meshd_mgr_persist(nd, manager));
	/* Active managers refresh their mirror through the restore entrypoint. */
	meshd_mgr_restore(nd, manager);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	meshd_clients_queue_events(nd, kq); /* all client slots inactive */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	cl = meshd_client_alloc(nd, sp[0]);
	ATF_REQUIRE(cl != NULL);
	meshd_clients_queue_events(nd, kq); /* active, empty event queue */
	ATF_CHECK(cl->active);
	meshd_client_close(kq, cl);
	close(sp[1]);
	close(kq);
	meshd_node_fini(nd);
	free(nd);
	ATF_CHECK_EQ(0, unlink(manager));
}

ATF_TC_WITHOUT_HEAD(process_socket_lock_and_shutdown);
ATF_TC_BODY(process_socket_lock_and_shutdown, tc)
{
	char dir[] = "meshd-security.XXXXXX";
	char config[PATH_MAX], sock[PATH_MAX], state[PATH_MAX], manager[PATH_MAX];
	char state2[PATH_MAX], state_lock[PATH_MAX], state2_lock[PATH_MAX];
	char manager_lock[PATH_MAX];
	char reply[512];
	struct pollfd pfd;
	struct stat sb;
	pid_t first, second;
	ssize_t n;
	int fd;

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(config, sizeof(config), "%s/config", dir);
	snprintf(sock, sizeof(sock), "%s/control.sock", dir);
	snprintf(state, sizeof(state), "%s/node.state", dir);
	snprintf(manager, sizeof(manager), "%s/manager.state", dir);
	snprintf(state2, sizeof(state2), "%s/node2.state", dir);
	snprintf(state_lock, sizeof(state_lock), "%s.lock", state);
	snprintf(state2_lock, sizeof(state2_lock), "%s.lock", state2);
	snprintf(manager_lock, sizeof(manager_lock), "%s.lock", manager);
	write_config(config);
	first = spawn_meshd(config, sock, state, manager);
	ATF_REQUIRE_EQ(0, wait_for_socket(sock));
	ATF_REQUIRE_EQ(0, lstat(sock, &sb));
	ATF_CHECK_EQ(0600, sb.st_mode & 0777);

	fd = connect_control(sock);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(7, write(fd, "status\n", 7));
	pfd.fd = fd;
	pfd.events = POLLIN;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 3000));
	n = read(fd, reply, sizeof(reply) - 1);
	ATF_REQUIRE(n > 0);
	reply[n] = '\0';
	ATF_CHECK_MSG(strstr(reply, "OK addr=0x0001") != NULL, "%s", reply);
	ATF_CHECK_EQ(0, close(fd));

	/* A second process cannot become another writer for either state file. */
	second = spawn_meshd(config, sock, state, manager);
	ATF_CHECK(wait_child(second) != 0);
	second = spawn_meshd(config, sock, state2, manager);
	ATF_CHECK(wait_child(second) != 0);

	ATF_REQUIRE_EQ(0, kill(first, SIGTERM));
	ATF_CHECK_EQ(0, wait_child(first));
	ATF_CHECK_EQ(0, access(state, F_OK));
	ATF_CHECK_EQ(-1, access(sock, F_OK));

	(void)unlink(config);
	(void)unlink(state);
	(void)unlink(manager);
	(void)unlink(state_lock);
	(void)unlink(state2);
	(void)unlink(state2_lock);
	(void)unlink(manager_lock);
	(void)rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(shutdown_write_error_is_fatal);
ATF_TC_BODY(shutdown_write_error_is_fatal, tc)
{
	char dir[] = "meshd-shutdown-error.XXXXXX";
	char config[PATH_MAX], sock[PATH_MAX], state[PATH_MAX], manager[PATH_MAX];
	char state_lock[PATH_MAX], manager_lock[PATH_MAX];
	pid_t pid;

	if (geteuid() == 0)
		atf_tc_skip("root bypasses directory write permissions");
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(config, sizeof(config), "%s/config", dir);
	snprintf(sock, sizeof(sock), "%s/control.sock", dir);
	snprintf(state, sizeof(state), "%s/node.state", dir);
	snprintf(manager, sizeof(manager), "%s/manager.state", dir);
	snprintf(state_lock, sizeof(state_lock), "%s.lock", state);
	snprintf(manager_lock, sizeof(manager_lock), "%s.lock", manager);
	write_config(config);
	pid = spawn_meshd(config, sock, state, manager);
	ATF_REQUIRE_EQ(0, wait_for_socket(sock));
	ATF_REQUIRE_EQ(0, chmod(dir, 0500));
	ATF_REQUIRE_EQ(0, kill(pid, SIGTERM));
	ATF_CHECK_EQ(1, wait_child(pid));
	ATF_REQUIRE_EQ(0, chmod(dir, 0700));
	(void)unlink(config);
	(void)unlink(sock);
	(void)unlink(state);
	(void)unlink(manager);
	(void)unlink(state_lock);
	(void)unlink(manager_lock);
	(void)rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(embedded_manager_wins_over_corrupt_mirror);
ATF_TC_BODY(embedded_manager_wins_over_corrupt_mirror, tc)
{
	char dir[] = "meshd-manager-authority.XXXXXX";
	char config[PATH_MAX], sock[PATH_MAX], state[PATH_MAX], manager[PATH_MAX];
	char state_lock[PATH_MAX], manager_lock[PATH_MAX], reply[512];
	struct mesh_mgr loaded;
	pid_t pid;
	int fd;

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(config, sizeof(config), "%s/config", dir);
	snprintf(sock, sizeof(sock), "%s/control.sock", dir);
	snprintf(state, sizeof(state), "%s/node.state", dir);
	snprintf(manager, sizeof(manager), "%s/manager.state", dir);
	snprintf(state_lock, sizeof(state_lock), "%s.lock", state);
	snprintf(manager_lock, sizeof(manager_lock), "%s.lock", manager);
	write_config(config);
	pid = spawn_meshd(config, sock, state, manager);
	ATF_REQUIRE_EQ(0, wait_for_socket(sock));
	control_command(sock, "create-network\n", reply, sizeof(reply));
	ATF_CHECK_MSG(strstr(reply, "OK network created") != NULL, "%s", reply);
	ATF_REQUIRE_EQ(0, kill(pid, SIGTERM));
	ATF_REQUIRE_EQ(0, wait_child(pid));

	/* Damage only the compatibility mirror, leaving the atomic node commit. */
	fd = open(manager, O_WRONLY | O_TRUNC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(3, write(fd, "bad", 3));
	ATF_REQUIRE_EQ(0, close(fd));
	pid = spawn_meshd(config, sock, state, manager);
	ATF_REQUIRE_EQ(0, wait_for_socket(sock));
	control_command(sock, "list-nodes\n", reply, sizeof(reply));
	ATF_CHECK_MSG(strstr(reply, "OK nodes=") != NULL, "%s", reply);
	ATF_REQUIRE_EQ(0, mesh_mgr_load(&loaded, manager));
	ATF_REQUIRE_EQ(0, kill(pid, SIGTERM));
	ATF_CHECK_EQ(0, wait_child(pid));

	(void)unlink(config);
	(void)unlink(sock);
	(void)unlink(state);
	(void)unlink(manager);
	(void)unlink(state_lock);
	(void)unlink(manager_lock);
	(void)rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(refuse_non_socket_stale_path);
ATF_TC_BODY(refuse_non_socket_stale_path, tc)
{
	char path[] = "meshd-not-a-socket.XXXXXX";
	struct stat before, after;
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(4, write(fd, "keep", 4));
	ATF_REQUIRE_EQ(0, fstat(fd, &before));
	ATF_REQUIRE_EQ(0, close(fd));
	errno = 0;
	ATF_CHECK_EQ(-1, meshd_unlink_stale_socket(path));
	ATF_CHECK_EQ(EPERM, errno);
	ATF_REQUIRE_EQ(0, stat(path, &after));
	ATF_CHECK_EQ(before.st_ino, after.st_ino);
	ATF_CHECK_EQ(4, after.st_size);
	ATF_REQUIRE_EQ(0, unlink(path));
}

ATF_TC_WITHOUT_HEAD(app_client_io_and_event_helpers);
ATF_TC_BODY(app_client_io_and_event_helpers, tc)
{
	struct meshd_node *nd;
	struct meshd_app_client *cl;
	struct meshd_app_event *ev;
	char out[512], peerbuf[512];
	int sp[2], kq;
	ssize_t n;

	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[0]));
	cl = meshd_client_alloc(nd, sp[0]);
	ATF_REQUIRE(cl != NULL);

	ATF_CHECK_EQ(-1, meshd_client_queue_bytes(NULL, "x", 1));
	ATF_CHECK_EQ(-1, meshd_client_queue_bytes(cl, NULL, 1));
	ATF_CHECK_EQ(0, meshd_client_queue_bytes(cl, "abc", 3));
	ATF_CHECK_EQ(0, meshd_client_queue_line(cl, "line"));
	ATF_CHECK_EQ(-1, meshd_client_queue_bytes(cl, peerbuf,
	    sizeof(cl->txbuf)));
	cl->txlen = cl->txoff = 0;

	memset(&cl->apps, 0, sizeof(cl->apps));
	ev = &cl->apps.events[0];
	ev->elem_addr = 1;
	ev->id.model_id = 0x1000;
	ev->src = 2;
	ev->dst = 3;
	ev->opcode = 0x8204;
	ev->params[0] = 0xab;
	ev->params[1] = 0xcd;
	ev->params_len = 2;
	cl->apps.ev_count = 1;
	ATF_CHECK_EQ(0, meshd_format_event(ev, out, sizeof(out)));
	ATF_CHECK(strstr(out, "params=abcd") != NULL);
	ATF_CHECK_EQ(-1, meshd_format_event(ev, out, 8));
	ATF_CHECK_EQ(1, meshd_client_queue_events(cl));
	ATF_CHECK_EQ(0, meshd_client_queue_events(cl));
	ATF_REQUIRE_EQ(0, meshd_client_write(cl));
	n = read(sp[1], peerbuf, sizeof(peerbuf) - 1);
	ATF_REQUIRE(n > 0);
	peerbuf[n] = '\0';
	ATF_CHECK(strstr(peerbuf, "EVENT elem=0x0001") != NULL);

	ATF_REQUIRE_EQ(7, write(sp[1], "status\n", 7));
	ATF_CHECK_EQ(1, meshd_client_read(nd, cl));
	ATF_REQUIRE_EQ(0, meshd_client_write(cl));
	n = read(sp[1], peerbuf, sizeof(peerbuf) - 1);
	ATF_REQUIRE(n > 0);
	peerbuf[n] = '\0';
	ATF_CHECK(strstr(peerbuf, "OK addr=") != NULL);

	/* Partial input is retained until a newline completes the command. */
	ATF_REQUIRE_EQ(3, write(sp[1], "sta", 3));
	ATF_CHECK_EQ(0, meshd_client_read(nd, cl));
	ATF_CHECK_EQ(3, cl->rxlen);
	ATF_REQUIRE_EQ(4, write(sp[1], "tus\n", 4));
	ATF_CHECK_EQ(1, meshd_client_read(nd, cl));
	ATF_REQUIRE_EQ(0, meshd_client_write(cl));
	(void)read(sp[1], peerbuf, sizeof(peerbuf));

	/* Exhaust the fixed client table, then release the live client. */
	for (size_t i = 1; i < MESHD_MAX_APP_CLIENTS; i++)
		meshd_app_client_init(&nd->app_clients[i], -1);
	ATF_CHECK(meshd_client_alloc(nd, -1) == NULL);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	/* Input overflow and EOF are fatal to the individual client. */
	cl->rxlen = sizeof(cl->rxbuf) - 1;
	ATF_REQUIRE_EQ(2, write(sp[1], "xx", 2));
	ATF_CHECK_EQ(-1, meshd_client_read(nd, cl));
	cl->rxlen = 0;
	ATF_REQUIRE_EQ(0, close(sp[1]));
	ATF_CHECK_EQ(-1, meshd_client_read(nd, cl));

	/* A closed peer surfaces the write failure without terminating meshd. */
	(void)signal(SIGPIPE, SIG_IGN);
	cl->txoff = cl->txlen = 0;
	ATF_REQUIRE_EQ(0, meshd_client_queue_bytes(cl, "x", 1));
	ATF_CHECK_EQ(-1, meshd_client_write(cl));
	cl->txoff = cl->txlen = 0;

	/* Event queue overflow makes the outer client sweep release the client. */
	cl->txlen = sizeof(cl->txbuf);
	memset(&cl->apps.events[0], 0, sizeof(cl->apps.events[0]));
	cl->apps.events[0].opcode = 0x8204;
	cl->apps.ev_head = 0; cl->apps.ev_count = 1;
	meshd_clients_queue_events(nd, kq);
	ATF_CHECK(!cl->active);
	ATF_REQUIRE_EQ(0, close(kq));
	free(nd);
}

/*
 * A reconnect may receive the descriptor number that was just closed.  Its
 * generation, rather than the descriptor alone, must select bearer events.
 */
ATF_TC_WITHOUT_HEAD(blued_bearer_fd_reuse_generation);
ATF_TC_BODY(blued_bearer_fd_reuse_generation, tc)
{
	struct meshd_blued bc;
	struct kevent ev;
	int reused_fd = 17;

	meshd_blued_init(&bc, NULL);
	ATF_CHECK_EQ(0, meshd_blued_generation(&bc));

	bc.fd = reused_fd;
	bc.generation = 1;
	ATF_CHECK(!meshd_blued_registration_changed(&bc, reused_fd, 1));
	EV_SET(&ev, (uintptr_t)reused_fd, EVFILT_READ, 0, 0, 0,
	    meshd_blued_udata(bc.generation));
	ATF_CHECK(meshd_blued_event_current(&bc, &ev));

	/* The numeric fd is reused, but an event from generation 1 is stale. */
	bc.generation = 2;
	ATF_CHECK(meshd_blued_registration_changed(&bc, reused_fd, 1));
	ATF_CHECK(!meshd_blued_event_current(&bc, &ev));
	ev.udata = meshd_blued_udata(bc.generation);
	ATF_CHECK(meshd_blued_event_current(&bc, &ev));

	/* Closing also invalidates already-returned events before reconnect. */
	bc.fd = -1;
	ATF_CHECK(!meshd_blued_event_current(&bc, &ev));
	ATF_CHECK(!meshd_blued_event_current(NULL, &ev));
	ATF_CHECK(!meshd_blued_event_current(&bc, NULL));
}

ATF_TC_WITHOUT_HEAD(blued_bearer_async_handshake);
ATF_TC_BODY(blued_bearer_async_handshake, tc)
{
	struct meshd_blued bc;
	struct meshd_node *nd;
	struct sockaddr_un sun;
	char dir[] = "/tmp/meshd-async.XXXXXX", path[sizeof(sun.sun_path)];
	uint8_t hdr[IPC_HDR_SIZE], features[IPC_HELLO_FEATURES_SIZE];
	uint8_t payload[IPC_MAX_PAYLOAD], *body;
	uint32_t plen, request_id;
	uint16_t type, arg, status, flags;
	int lfd, pfd;

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	ATF_REQUIRE(snprintf(path, sizeof(path), "%s/broker.sock", dir) > 0);
	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(lfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	ATF_REQUIRE(strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) <
	    sizeof(sun.sun_path));
	ATF_REQUIRE_EQ(0, bind(lfd, (struct sockaddr *)&sun, sizeof(sun)));
	ATF_REQUIRE_EQ(0, listen(lfd, 1));

	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	meshd_blued_init(&bc, path);
	meshd_blued_bind_node(&bc, nd);
	ATF_REQUIRE_EQ(0, meshd_blued_connect(&bc));
	ATF_CHECK(meshd_blued_fd(&bc) >= 0);
	ATF_CHECK(meshd_blued_generation(&bc) != 0);
	ATF_CHECK(bc.state == MESHD_BLUED_CONNECTING ||
	    bc.state == MESHD_BLUED_HELLO);
	pfd = accept(lfd, NULL, NULL);
	ATF_REQUIRE(pfd >= 0);

	/* Writability advances EINPROGRESS and emits HELLO without blocking. */
	ATF_REQUIRE_EQ(0, meshd_blued_flush(&bc));
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), read(pfd, hdr, sizeof(hdr)));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_REQUIRE_EQ(IPC_T_HELLO, type);
	ATF_REQUIRE_EQ(IPC_PROTO_VERSION, arg);
	ATF_REQUIRE_EQ(IPC_HELLO_FEATURES_SIZE, plen);
	ATF_REQUIRE_EQ((ssize_t)plen, read(pfd, payload, plen));

	ipc_put_le32(features, IPC_FEATURE_MESH | IPC_FEATURE_EVENTS);
	bearer_write_frame(pfd, IPC_T_HELLO, IPC_PROTO_VERSION, features,
	    sizeof(features));
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, meshd_now()));
	ATF_REQUIRE_EQ(MESHD_BLUED_SUBSCRIBING, bc.state);
	ATF_REQUIRE_EQ(0, meshd_blued_flush(&bc));
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), read(pfd, hdr, sizeof(hdr)));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_REQUIRE_EQ(IPC_T_OP_REQ, type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_MESH, arg);
	ATF_REQUIRE(plen <= sizeof(payload));
	ATF_REQUIRE_EQ((ssize_t)plen, read(pfd, payload, plen));
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, status);
	ATF_REQUIRE_EQ(0, flags);

	/* Valid events interleaved before the correlated ACK are not lost. */
	for (unsigned i = 0; i < 2; i++) {
		memset(payload, 0, sizeof(payload));
		ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
		body = payload + IPC_OP_PREFIX_SIZE;
		ipc_put_le16(body, IPC_MESH_EV_ADV);
		body[2] = MESHD_PDU_PROV;
		body[3] = 1;
		body[IPC_MESH_ADV_EVENT_HDR_SIZE] = (uint8_t)(0xa0 + i);
		bearer_write_frame(pfd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_MESH,
		    payload, IPC_OP_PREFIX_SIZE + IPC_MESH_ADV_EVENT_HDR_SIZE + 1);
	}
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	bearer_write_frame(pfd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_MESH, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_CHECK_EQ(2, meshd_blued_pump_rx(&bc, nd, meshd_now()));
	ATF_CHECK_EQ(MESHD_BLUED_READY, bc.state);
	ATF_CHECK_EQ(0, bc.handshake_deadline);

	meshd_blued_close(&bc);
	ATF_REQUIRE_EQ(0, close(pfd));
	ATF_REQUIRE_EQ(0, close(lfd));
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_REQUIRE_EQ(0, rmdir(dir));
	free(nd);
}

ATF_TC_WITHOUT_HEAD(blued_bearer_guards_and_tx_matrix);
ATF_TC_BODY(blued_bearer_guards_and_tx_matrix, tc)
{
	struct meshd_blued bc;
	struct meshd_node *nd;
	uint8_t pdu[32], hdr[IPC_HDR_SIZE], fill[4096];
	uint64_t retry_first, retry_floor;
	const char *addr = "00:11:22:33:44:55";
	int sp[2];

	(void)signal(SIGPIPE, SIG_IGN);
	memset(pdu, 0x5a, sizeof(pdu));
	meshd_blued_init(NULL, NULL);
	meshd_blued_init(&bc, "/definitely/missing/blued.sock");
	ATF_CHECK_EQ(-1, meshd_blued_fd(NULL));
	ATF_CHECK_EQ(-1, meshd_blued_fd(&bc));
	ATF_CHECK_EQ(-1, meshd_blued_attach(NULL, -1));
	ATF_CHECK_EQ(-1, meshd_blued_connect(NULL));
	ATF_CHECK_EQ(-1, meshd_blued_connect(&bc));
	ATF_CHECK_EQ(0, meshd_blued_maintain(NULL, 0));
	bc.retry_at = 10;
	ATF_CHECK_EQ(0, meshd_blued_maintain(&bc, 9));
	bc.retry_at = 0;
	ATF_CHECK_EQ(0, meshd_blued_maintain(&bc, 10));
	ATF_CHECK_EQ(1, bc.backoff);
	retry_first = bc.retry_at;
	ATF_CHECK(retry_first > meshd_now());
	ATF_CHECK_EQ(0, meshd_blued_maintain(&bc, retry_first - 1));
	ATF_CHECK_EQ(1, bc.backoff);
	bc.retry_at = 0;
	ATF_CHECK_EQ(0, meshd_blued_maintain(&bc, retry_first));
	ATF_CHECK_EQ(2, bc.backoff);
	bc.backoff = 16;
	bc.retry_at = 0;
	retry_floor = meshd_now() + 30000;
	ATF_CHECK_EQ(0, meshd_blued_maintain(&bc, 5000));
	ATF_CHECK_EQ(30, bc.backoff);
	ATF_CHECK(bc.retry_at >= retry_floor);

	ATF_CHECK_EQ(-1, meshd_blued_tx(NULL, MESHD_PDU_NET, pdu, 1));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, MESHD_PDU_NET, NULL, 1));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu, 0));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu, 1));
	ATF_CHECK_EQ(-1, meshd_blued_proxy_tx(NULL, addr,
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, 1));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_bind(NULL, addr, 0, 1, 2));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_discover(NULL, addr, 0));
	ATF_CHECK_EQ(-1, meshd_blued_proxy_open(NULL, addr, 0,
	    MESHD_ADAPTER_DEFAULT));

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	bc.fd = sp[0];
	ATF_CHECK_EQ(1, meshd_blued_maintain(&bc, 100));
	ATF_CHECK_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu, 3));
	ATF_CHECK_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_BEACON, pdu, 3));
	ATF_CHECK_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_PROV, pdu, 3));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, (enum meshd_pdu_class)99, pdu,
	    3));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu,
	    sizeof(pdu)));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_bind(&bc, "bad", 0, 1, 2));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_bind(&bc, addr, 0, 0, 2));
	ATF_CHECK_EQ(0, meshd_blued_pbgatt_bind(&bc, addr, 0, 1, 2));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_discover(&bc, "bad", 0));
	ATF_CHECK_EQ(0, meshd_blued_pbgatt_discover(&bc, addr, 0));
	ATF_CHECK(bc.discover_request_id != 0);
	ATF_CHECK_EQ(0, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	ATF_CHECK_EQ(-1, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	bc.proxy[0].data_in = 3;
	bc.proxy[0].mtu = 23;
	bc.proxy[0].subscribed = 1;
	ATF_CHECK_EQ(0, meshd_blued_proxy_tx(&bc, addr,
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, 3));
	/* Large negotiated MTUs are capped at the Mesh Proxy PDU maximum. */
	bc.proxy[0].mtu = MESHD_GATT_MAX_MTU;
	ATF_CHECK_EQ(0, meshd_blued_proxy_tx(&bc, addr,
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, MESH_PROXY_MAX_NETWORK_PDU));
	ATF_CHECK_EQ(-1, meshd_blued_proxy_tx(&bc, "bad",
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, 3));
	/* Capacity is reserved for the whole Proxy message before any segment. */
	bc.txoff = 0;
	bc.txlen = sizeof(bc.tx) - 1;
	ATF_CHECK_EQ(-1, meshd_blued_proxy_tx(&bc, addr,
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, 3));
	ATF_CHECK_EQ(sizeof(bc.tx) - 1, bc.txlen);
	bc.txoff = bc.txlen = 0;
	memset(bc.writes, 0x01, sizeof(bc.writes));
	ATF_CHECK_EQ(-1, meshd_blued_proxy_tx(&bc, addr,
	    MESHD_ADDR_PUBLIC, MESHD_ADAPTER_DEFAULT, MESH_PROXY_TYPE_NETWORK,
	    pdu, 3));
	ATF_CHECK_EQ(0, bc.txlen);
	memset(bc.writes, 0, sizeof(bc.writes));
	ATF_CHECK_EQ(-1, meshd_blued_pbgatt_drain(NULL, NULL));

	meshd_blued_close(&bc);
	ATF_CHECK_EQ(-1, bc.fd);
	ATF_CHECK_EQ(0, close(sp[1]));
	meshd_blued_close(NULL);

	/* EAGAIN queues a whole frame; writability later drains it intact. */
	meshd_blued_init(&bc, NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[0]));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[1]));
	bc.fd = sp[0];
	memset(fill, 0xa5, sizeof(fill));
	for (;;) {
		ssize_t n = write(sp[0], fill, sizeof(fill));

		if (n > 0)
			continue;
		ATF_REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
		break;
	}
	ATF_REQUIRE_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu, 3));
	ATF_CHECK_EQ(sp[0], bc.fd);
	ATF_CHECK(meshd_blued_wants_write(&bc));
	while (read(sp[1], fill, sizeof(fill)) > 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
	ATF_REQUIRE_EQ(0, meshd_blued_flush(&bc));
	ATF_CHECK(!meshd_blued_wants_write(&bc));
	while (read(sp[1], fill, sizeof(fill)) > 0)
		;

	/* A random peer's type is retained and encoded at GATT request offset 4. */
	ATF_REQUIRE(fcntl(sp[1], F_SETFL,
	    fcntl(sp[1], F_GETFL, 0) & ~O_NONBLOCK) >= 0);
	ATF_REQUIRE_EQ(0, meshd_blued_pbgatt_discover(&bc, addr, 1));
	ATF_REQUIRE_EQ((ssize_t)(IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE +
	    IPC_GATT_REQ_SIZE), recv(sp[1], fill, IPC_HDR_SIZE +
	    IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE, MSG_WAITALL));
	ATF_CHECK_EQ(1, fill[IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE + 4]);
	ATF_CHECK_EQ(1, bc.gatt_addr_type);
	meshd_blued_close(&bc);
	ATF_REQUIRE_EQ(0, close(sp[1]));

	/* Handshake EOF and oversized receive frames fail closed. */
	meshd_blued_init(&bc, NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, close(sp[1]));
	ATF_CHECK_EQ(-1, meshd_blued_attach(&bc, sp[0]));
	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	ATF_CHECK_EQ(-1, meshd_blued_pump_rx(NULL, nd, 0));
	ATF_CHECK_EQ(-1, meshd_blued_pump_rx(&bc, NULL, 0));
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 0));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[0]));
	bc.fd = sp[0];
	ipc_hdr_encode(hdr, IPC_MAX_PAYLOAD + 1, IPC_T_OP_EVENT,
	    IPC_OP_DOMAIN_MESH);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(sp[1], hdr, sizeof(hdr)));
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 0));
	ATF_CHECK_EQ(-1, bc.fd);
	ATF_REQUIRE_EQ(0, close(sp[1]));
	free(nd);
}

ATF_TC_WITHOUT_HEAD(blued_bearer_gatt_event_matrix);
ATF_TC_BODY(blued_bearer_gatt_event_matrix, tc)
{
	struct meshd_blued bc;
	struct meshd_node *nd;
	bdaddr_t ba;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 2];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	uint32_t request_id;
	size_t i;
	const char *addr = "00:11:22:33:44:55";
	int sp[2];

	ATF_REQUIRE(bt_aton(addr, &ba));
	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[0]));
	meshd_blued_init(&bc, NULL);
	bc.fd = sp[0];

	/* PB-GATT service and both characteristics, followed by completion. */
	ATF_REQUIRE_EQ(0, meshd_blued_pbgatt_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	request_id = bc.discover_request_id;
	bearer_write_discovery_event(sp[1], request_id, IPC_GATT_EV_SERVICE,
	    0x1827, 0);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, 0x2adb, 0x0021);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, 0x2adc, 0x0022);
	bearer_write_reply(sp[1], request_id, IPC_ERR_NONE, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 1));
	ATF_CHECK_EQ(0x0021, bc.gatt_data_in);
	ATF_CHECK_EQ(0x0022, bc.gatt_data_out);
	ATF_CHECK_EQ(0, bc.gatt_discovering);

	/* A PB notification with no active provisioning session is ignored. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	memcpy(body + 3, &ba, sizeof(ba));
	ipc_put_le16(body + 9, bc.gatt_data_out);
	ipc_put_le16(body + 11, 2);
	ipc_put_le16(body + 14, 23);
	body[IPC_GATT_NOTIFY_EVENT_SIZE] = 0x00;
	body[IPC_GATT_NOTIFY_EVENT_SIZE + 1] = 0x01;
	bearer_write_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    sizeof(payload));
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 2));

	/* Proxy discovery uses an independent request and subscribes on success. */
	nd->provisioned = 1;
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT, 23));
	ATF_REQUIRE_EQ(0, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	request_id = bc.proxy[0].discover_request_id;
	bearer_write_discovery_event(sp[1], request_id, IPC_GATT_EV_SERVICE,
	    MESH_PROXY_SERVICE_UUID, 0);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, MESH_PROXY_DATA_IN_UUID, 0x0031);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, MESH_PROXY_DATA_OUT_UUID, 0x0032);
	bearer_write_reply(sp[1], request_id, IPC_ERR_NONE, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 3));
	ATF_CHECK_EQ(0, bc.proxy[0].discovering);
	ATF_CHECK_EQ(0x0031, bc.proxy[0].data_in);
	ATF_CHECK_EQ(0x0032, bc.proxy[0].data_out);
	ATF_CHECK(bc.proxy[0].subscribing);
	ATF_CHECK(!bc.proxy[0].subscribed);
	request_id = bc.proxy[0].subscribe_request_id;
	/* A notification may race ahead of the CCCD Write Response. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	memcpy(body + 3, &ba, sizeof(ba));
	ipc_put_le16(body + 9, bc.proxy[0].data_out);
	ipc_put_le16(body + 11, 2);
	ipc_put_le16(body + 14, 23);
	body[IPC_GATT_NOTIFY_EVENT_SIZE] = 0x3f; /* well-formed RFU: ignore */
	body[IPC_GATT_NOTIFY_EVENT_SIZE + 1] = 0x00;
	bearer_write_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    sizeof(payload));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, 3));
	bearer_write_ack(sp[1], request_id, IPC_ERR_NONE);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 3));
	ATF_CHECK(!bc.proxy[0].subscribing);
	ATF_CHECK(bc.proxy[0].subscribed);

	/* Route a matching proxy notification after the subscription ACK too. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	memcpy(body + 3, &ba, sizeof(ba));
	ipc_put_le16(body + 9, bc.proxy[0].data_out);
	ipc_put_le16(body + 11, 2);
	ipc_put_le16(body + 14, 23);
	body[IPC_GATT_NOTIFY_EVENT_SIZE] = 0xff; /* malformed SAR/type */
	body[IPC_GATT_NOTIFY_EVENT_SIZE + 1] = 0x00;
	bearer_write_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    sizeof(payload));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, 4));

	/* A failed Write Command reply tears down exactly its Proxy bearer. */
	ATF_REQUIRE_EQ(0, meshd_blued_proxy_tx(&bc, addr, 0,
	    0, MESH_PROXY_TYPE_NETWORK,
	    body + IPC_GATT_NOTIFY_EVENT_SIZE + 1, 1));
	request_id = 0;
	for (i = 0; i < MESHD_BLUED_MAX_WRITES; i++)
		if (bc.writes[i].kind == MESHD_BLUED_WRITE_PROXY) {
			request_id = bc.writes[i].request_id;
			break;
		}
	ATF_REQUIRE(request_id != 0);
	bearer_write_ack(sp[1], request_id, IPC_ERR_IO);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 4));
	ATF_CHECK_EQ(0, bc.proxy[0].active);

	/* A later GAP disconnect for the closed link remains harmless. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GAP_EV_DISCONNECTED);
	memcpy(body + 3, &ba, sizeof(ba));
	bearer_write_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 5));
	ATF_CHECK_EQ(0, bc.proxy[0].active);

	/* A failed correlated subscription ACK closes the pending Proxy link. */
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT, 23));
	ATF_REQUIRE_EQ(0, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	request_id = bc.proxy[0].discover_request_id;
	bearer_write_discovery_event(sp[1], request_id, IPC_GATT_EV_SERVICE,
	    MESH_PROXY_SERVICE_UUID, 0);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, MESH_PROXY_DATA_IN_UUID, 0x0031);
	bearer_write_discovery_event(sp[1], request_id,
	    IPC_GATT_EV_CHARACTERISTIC, MESH_PROXY_DATA_OUT_UUID, 0x0032);
	bearer_write_reply(sp[1], request_id, IPC_ERR_NONE, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 5));
	request_id = bc.proxy[0].subscribe_request_id;
	bearer_write_ack(sp[1], request_id, IPC_ERR_IO);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 5));
	ATF_CHECK_EQ(0, bc.proxy[0].active);

	/* Failed discovery replies and stream errors release pending state. */
	ATF_REQUIRE_EQ(0, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	request_id = bc.proxy[0].discover_request_id;
	bearer_write_reply(sp[1], request_id, IPC_ERR_IO, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 6));
	ATF_CHECK_EQ(0, bc.proxy[0].active);
	ATF_REQUIRE_EQ(0, meshd_blued_proxy_open(&bc, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	bearer_write_frame(sp[1], IPC_T_ERROR, IPC_ERR_PROTO, NULL, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 7));
	ATF_CHECK_EQ(0, bc.proxy[0].active);

	ATF_REQUIRE_EQ(0, meshd_blued_pbgatt_discover(&bc, addr, 0));
	request_id = bc.discover_request_id;
	bearer_write_reply(sp[1], request_id, IPC_ERR_NOT_FOUND, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 8));
	ATF_CHECK_EQ(0, bc.gatt_discovering);
	ATF_REQUIRE_EQ(0, meshd_blued_pbgatt_discover(&bc, addr, 0));
	bearer_write_frame(sp[1], IPC_T_ERROR, IPC_ERR_PROTO, NULL, 0);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 9));
	ATF_CHECK_EQ(0, bc.gatt_discovering);

	/* The same disconnect event clears the non-proxy PB-GATT binding. */
	strlcpy(bc.gatt_addr, addr, sizeof(bc.gatt_addr));
	bc.gatt_adapter_index = 0;
	bc.gatt_data_in = 0x41;
	bc.gatt_data_out = 0x42;
	bc.gatt_subscribed = 1;
	bc.writes[0].kind = MESHD_BLUED_WRITE_PBGATT;
	bc.writes[0].request_id = 0xdead;
	bc.writes[0].generation = bc.pbgatt_generation;
	bearer_write_ack(sp[1], 0xdead, IPC_ERR_IO);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 10));
	ATF_CHECK_EQ(0, bc.gatt_addr[0]);

	strlcpy(bc.gatt_addr, addr, sizeof(bc.gatt_addr));
	bc.gatt_adapter_index = 0;
	bc.gatt_data_in = 0x41;
	bc.gatt_data_out = 0x42;
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GAP_EV_DISCONNECTED);
	memcpy(body + 3, &ba, sizeof(ba));
	bearer_write_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 10));
	ATF_CHECK_EQ(0, bc.gatt_addr[0]);
	ATF_CHECK_EQ(0, bc.gatt_data_in);
	ATF_CHECK_EQ(0, bc.gatt_data_out);

	meshd_blued_close(&bc);
	ATF_REQUIRE_EQ(0, close(sp[1]));
	free(nd);
}

/*
 * Complete the synchronous HELLO path against a peer, then make the peer
 * disappear before a transmit.  The public attach API owns the descriptor on
 * both success and failure, so this also verifies that a write error returns
 * the bearer to its reconnectable state rather than leaving a stale fd.
 */
ATF_TC_WITHOUT_HEAD(blued_bearer_attach_and_link_loss);
ATF_TC_BODY(blued_bearer_attach_and_link_loss, tc)
{
	struct meshd_blued bc;
	struct meshd_node *nd;
	uint8_t hdr[IPC_HDR_SIZE], features[IPC_HELLO_FEATURES_SIZE];
	uint8_t payload[IPC_MAX_PAYLOAD];
	uint32_t plen;
	uint16_t type, arg;
	pid_t pid;
	int sp[2], status;
	uint8_t pdu = 0x5a;

	(void)signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), read(sp[1], hdr, sizeof(hdr)));
		ipc_hdr_decode(hdr, &plen, &type, &arg);
		ATF_REQUIRE_EQ(IPC_T_HELLO, type);
		ATF_REQUIRE_EQ(IPC_PROTO_VERSION, arg);
		ATF_REQUIRE_EQ(IPC_HELLO_FEATURES_SIZE, plen);
		ATF_REQUIRE_EQ((ssize_t)sizeof(features), read(sp[1], features,
		    sizeof(features)));
		ipc_put_le32(features, IPC_FEATURE_MESH | IPC_FEATURE_EVENTS);
		ipc_hdr_encode(hdr, sizeof(features), IPC_T_HELLO, IPC_PROTO_VERSION);
		ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(sp[1], hdr, sizeof(hdr)));
		ATF_REQUIRE_EQ((ssize_t)sizeof(features), write(sp[1], features,
		    sizeof(features)));
		/* Consume the subscribe request, then force the parent's next write. */
		ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), read(sp[1], hdr, sizeof(hdr)));
		ipc_hdr_decode(hdr, &plen, &type, &arg);
		ATF_REQUIRE_EQ(IPC_T_OP_REQ, type);
		ATF_REQUIRE_EQ(IPC_OP_DOMAIN_MESH, arg);
		ATF_REQUIRE_EQ((ssize_t)plen, read(sp[1], payload, plen));
		{
			uint32_t subscribe_id;
			uint16_t subscribe_status, subscribe_flags;
			uint8_t *body;

			ipc_op_prefix_decode(payload, &subscribe_id,
			    &subscribe_status, &subscribe_flags);
			ATF_REQUIRE_EQ(IPC_ERR_NONE, subscribe_status);
			ATF_REQUIRE_EQ(0, subscribe_flags);
			/* A valid event may arrive before the correlated subscribe ACK. */
			memset(payload, 0, sizeof(payload));
			ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
			body = payload + IPC_OP_PREFIX_SIZE;
			ipc_put_le16(body, IPC_MESH_EV_ADV);
			body[2] = MESHD_PDU_PROV;
			body[3] = 1;
			body[IPC_MESH_ADV_EVENT_HDR_SIZE] = 0xff;
			bearer_write_frame(sp[1], IPC_T_OP_EVENT,
			    IPC_OP_DOMAIN_MESH, payload, IPC_OP_PREFIX_SIZE +
			    IPC_MESH_ADV_EVENT_HDR_SIZE + 1);
			ipc_op_prefix_encode(payload, subscribe_id, IPC_ERR_NONE, 0);
			bearer_write_frame(sp[1], IPC_T_OP_REPLY,
			    IPC_OP_DOMAIN_MESH, payload, IPC_OP_PREFIX_SIZE);
		}
		(void)close(sp[1]);
		meshd_child_exit(0);
	}
	(void)close(sp[1]);
	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	meshd_blued_init(&bc, NULL);
	meshd_blued_bind_node(&bc, nd);
	ATF_REQUIRE_EQ(0, meshd_blued_attach(&bc, sp[0]));
	ATF_CHECK(bc.fd >= 0);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
	/* The event buffered before ACK is dispatched even though EOF follows it. */
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, 1));
	ATF_CHECK_EQ(-1, bc.fd);
	/* A synchronous hard send failure tears down every node-side GATT link. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	bc.fd = sp[0];
	nd->proxy_gatt[0].active = 1;
	nd->pbgatt.active = 1;
	ATF_REQUIRE_EQ(0, close(sp[1]));
	ATF_CHECK_EQ(-1, meshd_blued_tx(&bc, MESHD_PDU_NET, &pdu, 1));
	ATF_CHECK(!nd->proxy_gatt[0].active);
	ATF_CHECK(!nd->pbgatt.active);
	free(nd);

	/* A syntactically complete but incompatible HELLO reply is rejected. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	meshd_blued_init(&bc, NULL);
	ipc_hdr_encode(hdr, 0, IPC_T_HELLO, IPC_PROTO_VERSION);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(sp[1], hdr, sizeof(hdr)));
	ATF_CHECK_EQ(-1, meshd_blued_attach(&bc, sp[0]));
	ATF_REQUIRE_EQ(0, close(sp[1]));

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	meshd_blued_init(&bc, NULL);
	ipc_put_le32(features, IPC_FEATURE_EVENTS);
	ipc_hdr_encode(hdr, sizeof(features), IPC_T_HELLO, IPC_PROTO_VERSION);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(sp[1], hdr, sizeof(hdr)));
	ATF_REQUIRE_EQ((ssize_t)sizeof(features), write(sp[1], features,
	    sizeof(features)));
	ATF_CHECK_EQ(-1, meshd_blued_attach(&bc, sp[0]));
	ATF_REQUIRE_EQ(0, close(sp[1]));
}

ATF_TC_WITHOUT_HEAD(pbgatt_timeout_failed_wire_order);
ATF_TC_BODY(pbgatt_timeout_failed_wire_order, tc)
{
	struct meshd_blued bc;
	struct meshd_node *nd;
	struct meshd_bearer bearer = {
		.pbgatt_close = meshd_blued_pbgatt_close,
		.pbgatt_timeout = meshd_blued_pbgatt_timeout,
	};
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_REQ_SIZE + 3];
	uint8_t *request;
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	const char *addr = "00:11:22:33:44:55";
	int sp[2];

	nd = calloc(1, sizeof(*nd));
	ATF_REQUIRE(nd != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, meshd_set_nonblock(sp[0]));
	meshd_blued_init(&bc, NULL);
	bc.fd = sp[0];
	bc.pbgatt_generation = 9;
	meshd_blued_bind_node(&bc, nd);
	bearer.arg = &bc;
	meshd_set_bearer(nd, &bearer);
	strlcpy(bc.gatt_addr, addr, sizeof(bc.gatt_addr));
	bc.gatt_adapter_index = 0;
	bc.gatt_data_in = 0x0041;
	bc.gatt_data_out = 0x0042;
	bc.gatt_subscribed = 1;
	nd->pbgatt.active = 1;
	nd->pbgatt.mtu = MESHD_PBGATT_MIN_MTU;

	/* Failed is the sole pre-disconnect operation and remains correlated. */
	ATF_REQUIRE_EQ(0, meshd_pbgatt_timeout(nd, 1234));
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), recv(sp[1], hdr, sizeof(hdr),
	    MSG_WAITALL));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(IPC_T_OP_REQ, type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_GATT, domain);
	ATF_REQUIRE_EQ(sizeof(payload), plen);
	ATF_REQUIRE_EQ((ssize_t)plen, recv(sp[1], payload, plen, MSG_WAITALL));
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_REQUIRE(request_id != 0);
	ATF_CHECK_EQ(IPC_ERR_NONE, status);
	ATF_CHECK_EQ(0, flags);
	request = payload + IPC_OP_PREFIX_SIZE;
	ATF_CHECK_EQ(IPC_GATT_WRITE_CMD, ipc_get_le16(request));
	ATF_CHECK_EQ(0x0041, ipc_get_le16(request + 12));
	ATF_REQUIRE_EQ(3, ipc_get_le16(request + 14));
	ATF_CHECK_EQ(MESH_PROXY_TYPE_PROVISIONING,
	    request[IPC_GATT_VALUE_REQ_SIZE]);
	ATF_CHECK_EQ(MESH_PROV_FAILED,
	    request[IPC_GATT_VALUE_REQ_SIZE + 1]);
	ATF_CHECK_EQ(MESHD_PROV_ERR_UNEXPECTED_ERROR,
	    request[IPC_GATT_VALUE_REQ_SIZE + 2]);
	ATF_CHECK(nd->pbgatt.active);
	ATF_CHECK_STREQ(addr, bc.gatt_addr);

	/* Only the correlated successful write completion permits disconnection. */
	bearer_write_ack(sp[1], request_id, IPC_ERR_NONE);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 1235));
	ATF_CHECK(!nd->pbgatt.active);
	ATF_CHECK_EQ('\0', bc.gatt_addr[0]);

	/* A late result from generation 9 cannot tear down generation 10. */
	strlcpy(bc.gatt_addr, addr, sizeof(bc.gatt_addr));
	bc.gatt_adapter_index = 0;
	bc.gatt_data_in = 0x0041;
	bc.gatt_data_out = 0x0042;
	bc.gatt_subscribed = 1;
	bc.pbgatt_generation = 10;
	nd->pbgatt.active = 1;
	bc.writes[0].kind = MESHD_BLUED_WRITE_PBGATT;
	bc.writes[0].request_id = 0xfeed;
	bc.writes[0].generation = 9;
	bc.writes[0].terminal = 1;
	bearer_write_ack(sp[1], 0xfeed, IPC_ERR_IO);
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, 1236));
	ATF_CHECK(nd->pbgatt.active);
	ATF_CHECK_STREQ(addr, bc.gatt_addr);
	meshd_pbgatt_cancel(nd);

	meshd_blued_close(&bc);
	ATF_REQUIRE_EQ(0, close(sp[1]));
	free(nd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, security_helpers);
	ATF_TP_ADD_TC(tp, startup_failure_matrix);
	ATF_TP_ADD_TC(tp, daemon_static_lifecycle_helpers);
	ATF_TP_ADD_TC(tp, process_socket_lock_and_shutdown);
	ATF_TP_ADD_TC(tp, refuse_non_socket_stale_path);
	ATF_TP_ADD_TC(tp, shutdown_write_error_is_fatal);
	ATF_TP_ADD_TC(tp, embedded_manager_wins_over_corrupt_mirror);
	ATF_TP_ADD_TC(tp, app_client_io_and_event_helpers);
	ATF_TP_ADD_TC(tp, blued_bearer_fd_reuse_generation);
	ATF_TP_ADD_TC(tp, blued_bearer_async_handshake);
	ATF_TP_ADD_TC(tp, blued_bearer_guards_and_tx_matrix);
	ATF_TP_ADD_TC(tp, blued_bearer_gatt_event_matrix);
	ATF_TP_ADD_TC(tp, blued_bearer_attach_and_link_loss);
	ATF_TP_ADD_TC(tp, pbgatt_timeout_failed_wire_order);
	return (atf_no_error());
}
