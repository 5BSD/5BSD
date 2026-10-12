/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <sys/wait.h>
#define service_open_isolated mock_open
#include "../resolver.c"
#undef service_open_isolated
static int available, opens, source;
int mock_open(struct service_context *ctx, const char *path, uint32_t flags,
	      int mode, int *fdp)
{
	(void)ctx;
	(void)path;
	(void)flags;
	(void)mode;
	opens++;
	if (!available) {
		errno = ENOENT;
		return -1;
	}
	*fdp = dup(source);
	if (*fdp >= 0)
		ATF_REQUIRE(cap_clofork_limit(*fdp, CAP_CLOFORK_ONCE) == 0);
	return *fdp < 0 ? -1 : 0;
}
static int fdcount(void)
{
	int n = 0;
	for (int i = 0; i < 4096; i++)
		if (fcntl(i, F_GETFD) != -1)
			n++;
	return n;
}
ATF_TC_WITHOUT_HEAD(startup_recovery);
ATF_TC_BODY(startup_recovery, tc)
{
	char buf[64], token;
	int syncfd[2], status, stable, count, before, saved, broken[2];
	pid_t child;
	source = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(source >= 0);
	ATF_REQUIRE(ftruncate(source, 20) == 0);

	ATF_REQUIRE(write(source, "127.0.0.1 localhost\n", 20) == 20);
	ATF_REQUIRE(nameservers_share_init() == 0);
	ATF_REQUIRE(resolver_file_init(NULL, "/etc/hosts", &g_hostsfd, 1) == 0);
	stable = g_hostsfd;
	ATF_REQUIRE(!resolver_file_ready(1));
	for (int i = 0; i < 100; i++)
		resolver_file_retry(NULL, "/etc/hosts", g_hostsfd, 1, 64);
	ATF_REQUIRE(!resolver_file_ready(1));
	ATF_REQUIRE(g_hostsfd == stable);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, syncfd) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(syncfd[0]);
		ATF_REQUIRE(netresolve_worker_enter() == 0);
		ATF_REQUIRE(cap_enter() == 0);
		ATF_REQUIRE(write(syncfd[1], "r", 1) == 1);
		ATF_REQUIRE(read(syncfd[1], &token, 1) == 1);
		ATF_REQUIRE(resolver_file_ready(1));
		ATF_REQUIRE(read_snapshot(g_hostsfd, buf, sizeof(buf)) == 20);
		ATF_REQUIRE(memcmp(buf, "127.0.0.1 localhost\n", 20) == 0);
		errno = 0;
		ATF_REQUIRE(pwrite(g_hostsfd, "x", 1, 0) == -1 &&
			    errno == ENOTCAPABLE);
		_exit(0);
	}
	close(syncfd[1]);
	ATF_REQUIRE(read(syncfd[0], &token, 1) == 1);
	available = 1;
	before = fdcount();
	saved = source;
	ATF_REQUIRE(pipe(broken) == 0);
	source = broken[0];
	for (int i = 0; i < 100; i++)
		resolver_file_retry(NULL, "/etc/hosts", g_hostsfd, 1, 64);
	ATF_REQUIRE(!resolver_file_ready(1));
	ATF_REQUIRE(fdcount() == before + 2);
	close(broken[0]);
	close(broken[1]);
	source = saved;
	resolver_file_retry(NULL, "/etc/hosts", g_hostsfd, 1, 64);
	ATF_REQUIRE(resolver_file_ready(1));
	ATF_REQUIRE(g_hostsfd == stable);
	count = opens;
	for (int i = 0; i < 100; i++)
		resolver_file_retry(NULL, "/etc/hosts", g_hostsfd, 1, 64);
	ATF_REQUIRE(opens == count);
	ATF_REQUIRE(lseek(source, 0, SEEK_CUR) == 20);
	ATF_REQUIRE(write(syncfd[0], "g", 1) == 1);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(syncfd[0]);
	close(g_hostsfd);
	available = 0;
	ATF_REQUIRE(resolver_file_init(NULL, "/etc/services", &g_servfd, 2) ==
		    0);
	ATF_REQUIRE(!resolver_file_ready(2));
	available = 1;
	ATF_REQUIRE(pwrite(source, "testsvc 1234/tcp\n", 17, 0) == 17);
	resolver_file_retry(NULL, "/etc/services", g_servfd, 2,
			    RSLV_SERV_BUFSZ);
	ATF_REQUIRE(serv_lookup_file("testsvc", "tcp") == 1234);
	close(g_servfd);
	g_servfd = -1;
	g_recovery_files = 0;
	atomic_store(&g_nameservers->files_ready, 0);
	ATF_REQUIRE(resolver_file_init(NULL, "/etc/services", &g_servfd, 2) ==
		    0);
	ATF_REQUIRE(g_recovery_files == 2);
	ATF_REQUIRE(serv_lookup_file("testsvc", "tcp") == 1234);
	close(g_servfd);
	close(source);
	puts("PASS persistent failure, recovery, inherited worker, read-only "
	     "rights, stable descriptor, no repeated opens, source offset");
	(void)tc;
}


ATF_TC_WITHOUT_HEAD(repeated_workers);
ATF_TC_BODY(repeated_workers, tc)
{
	int status, initial_count;
	pid_t child;

	(void)tc;
	source = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(source >= 0);
	ATF_REQUIRE(ftruncate(source, 16) == 0);
	ATF_REQUIRE(write(source, "testsvc 1234/tcp\n", 16) == 16);
	ATF_REQUIRE(nameservers_share_init() == 0);
	available = 1;
	initial_count = fdcount();
	ATF_REQUIRE(resolver_file_init(NULL, "/etc/services", &g_servfd, 2) == 0);
	ATF_REQUIRE(fdcount() == initial_count + 1);
	for (int i = 0; i < 8; i++) {
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			ATF_REQUIRE(netresolve_worker_enter() == 0);
			ATF_REQUIRE(cap_enter() == 0);
			ATF_REQUIRE(serv_lookup_file("testsvc", "tcp") == 1234);
			_exit(0);
		}
		ATF_REQUIRE(waitpid(child, &status, 0) == child);
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		ATF_REQUIRE(fdcount() == initial_count + 1);
	}
	ATF_REQUIRE(opens == 1);
	close(g_servfd);
	close(source);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, startup_recovery);
	ATF_TP_ADD_TC(tp, repeated_workers);
	return (atf_no_error());
}
