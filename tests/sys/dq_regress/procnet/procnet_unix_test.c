/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * unix(4) names, connections and descriptor passing of unattached
 * processes, as before stage 1c.
 *
 * Stage 1c consults an ATTACHED caller's AF_UNIX name in kern_bindat(),
 * kern_connectat() and kern_sendit() (content slots, abstract names with
 * DQ_RF_ABSTRACT) and checks uipc_bindat()'s lookup against it.  For other
 * processes binding, connecting and sending by name must resolve, fail
 * and order errors exactly as before, also for a dirfd, a leading NUL and
 * a name racing with unlink(2).
 *
 * The unix(4) sendfile(2) cases cover commit 02ae46680f4 ("deliver
 * sendfile data that is not yet ready before EOF"), which is ALSO an
 * intended change for every process: data sent with sendfile(2) is read
 * before EOF even when the sender closes at once, and a receive buffer
 * shut with SHUT_RD refuses sendfile(2) with EPIPE.  Those two cases skip
 * with -v pre1c=yes; on the pre-1c kernel the first is a race (early EOF)
 * and the second may append or block.
 *
 * Expectations from 3f330ee172d: uipc_syscalls.c getsockaddr(),
 * kern_bindat(), kern_accept4(), sys_accept4(); uipc_usrreq.c
 * unp_sun_path(), uipc_bindat(), unp_connectat(), unp_connectat_peer()
 * (5BSD: an empty name with a socket dirfd names that socket),
 * unp_vnode_peer(), unp_connect_peer(), uipc_sosend_dgram().
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <pthread.h>
#include <stddef.h>

#include "procnet_common.h"

#define	SUN_PATH_LEN	sizeof(((struct sockaddr_un *)0)->sun_path)

/* A sockaddr_un for name; returns the length to pass. */
static socklen_t
sun_make(struct sockaddr_un *sun, const char *name)
{

	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	ATF_REQUIRE(strlen(name) < SUN_PATH_LEN);
	strlcpy(sun->sun_path, name, sizeof(sun->sun_path));
	sun->sun_len = (uint8_t)SUN_LEN(sun);
	return (sun->sun_len);
}

static int
bind_name(int s, const char *name)
{
	struct sockaddr_un sun;
	socklen_t len;

	len = sun_make(&sun, name);
	return (PN_ERR(bind(s, (struct sockaddr *)&sun, len)));
}

static int
connect_name(int s, const char *name)
{
	struct sockaddr_un sun;
	socklen_t len;

	len = sun_make(&sun, name);
	return (PN_ERR(connect(s, (struct sockaddr *)&sun, len)));
}

static int
listener(const char *name)
{
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	ATF_REQUIRE_MSG(bind_name(s, name) == 0, "bind %s: %s", name,
	    strerror(errno));
	ATF_REQUIRE(listen(s, 8) == 0);
	return (s);
}

static int
fresh(int type)
{
	int s;

	s = socket(AF_UNIX, type, 0);
	ATF_REQUIRE(s >= 0);
	return (s);
}

/* --- bind(2) --------------------------------------------------------- */

ATF_TC(bind_errors);
ATF_TC_HEAD(bind_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "bind(2): EADDRINUSE over a socket, a "
	    "file and a dangling symlink (not followed); ENOENT in a missing "
	    "directory; ENOTDIR through a file; EINVAL rebinding");
}
ATF_TC_BODY(bind_errors, tc)
{
	struct stat st;
	int s, l;

	l = listener("sock");
	pn_writefile("file", "x", 1, 0644);
	ATF_REQUIRE(symlink("target", "dangling") == 0);

	s = fresh(SOCK_STREAM);
	PN_CHECK_ERRNO(EADDRINUSE, bind_name(s, "sock"), "over a socket");
	PN_CHECK_ERRNO(EADDRINUSE, bind_name(s, "file"), "over a file");
	PN_CHECK_ERRNO(EADDRINUSE, bind_name(s, "dangling"),
	    "over a dangling symlink");
	ATF_CHECK_MSG(lstat("target", &st) != 0, "the symlink was followed");
	PN_CHECK_ERRNO(ENOENT, bind_name(s, "missing/sock"),
	    "in a missing directory");
	PN_CHECK_ERRNO(ENOTDIR, bind_name(s, "file/sock"), "through a file");
	PN_CHECK_ERRNO(0, bind_name(s, "sock2"), "fresh name");
	PN_CHECK_ERRNO(EINVAL, bind_name(s, "sock3"), "rebinding");
	ATF_CHECK(lstat("sock3", &st) != 0);
	ATF_REQUIRE(lstat("sock2", &st) == 0);
	ATF_CHECK(S_ISSOCK(st.st_mode));
	close(s);
	close(l);
}

ATF_TC(bind_unpriv);
ATF_TC_HEAD(bind_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "bind(2) where the caller may not "
	    "create is EACCES; the socket file's mode follows the umask");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
bind_unpriv_child(void *arg)
{
	const char *dir = arg;
	char name[PATH_MAX];
	struct stat st;
	int s;

	if (chdir(dir) != 0)
		return (PN_X_SETUP);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return (PN_X_SETUP);
	if (bind_name(s, "ro/sock") != EACCES)
		return (PN_X_WRONG);
	umask(027);
	snprintf(name, sizeof(name), "rw/sock");
	if (bind_name(s, name) != 0)
		return (errno);
	if (stat(name, &st) != 0 || (st.st_mode & 0777) != 0750 ||
	    st.st_uid != PN_UID)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(bind_unpriv, tc)
{
	char dir[PATH_MAX], sub[PATH_MAX];

	pn_pubdir("bind_unpriv", dir, sizeof(dir));
	snprintf(sub, sizeof(sub), "%s/ro", dir);
	ATF_REQUIRE(mkdir(sub, 0755) == 0);
	snprintf(sub, sizeof(sub), "%s/rw", dir);
	ATF_REQUIRE(mkdir(sub, 0755) == 0);
	ATF_REQUIRE(chown(sub, PN_UID, PN_GID) == 0);
	PN_CHECK_ERRNO(0, pn_child(bind_unpriv_child, dir, PN_UID, PN_GID),
	    "unprivileged bind");
	pn_pubdir_remove("bind_unpriv");
}

ATF_TC(sun_lengths);
ATF_TC_HEAD(sun_lengths, tc)
{
	atf_tc_set_md_var(tc, "descr", "address lengths: a full 104-byte "
	    "sun_path without NUL is a 104-byte name; over sizeof(struct "
	    "sockaddr_un) EINVAL; over SOCK_MAXADDRLEN ENAMETOOLONG (before "
	    "the descriptor is looked at); under 2 EINVAL; no path EINVAL "
	    "for bind and ENOENT for connect; wrong family EAFNOSUPPORT");
}
ATF_TC_BODY(sun_lengths, tc)
{
	struct sockaddr_un sun;
	char big[SOCK_MAXADDRLEN + 8];
	char name[SUN_PATH_LEN + 1];
	struct stat st;
	int s, c, fd;

	s = fresh(SOCK_STREAM);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memset(sun.sun_path, 'n', SUN_PATH_LEN);
	PN_EXPECT(0, bind(s, (struct sockaddr *)&sun, sizeof(sun)));
	memset(name, 'n', SUN_PATH_LEN);
	name[SUN_PATH_LEN] = '\0';
	ATF_REQUIRE_MSG(lstat(name, &st) == 0, "the 104-byte name: %s",
	    strerror(errno));
	ATF_CHECK(S_ISSOCK(st.st_mode));
	ATF_REQUIRE(listen(s, 1) == 0);
	c = fresh(SOCK_STREAM);
	PN_EXPECT(0, connect(c, (struct sockaddr *)&sun, sizeof(sun)));
	close(c);

	c = fresh(SOCK_STREAM);
	memset(big, 0, sizeof(big));
	((struct sockaddr *)big)->sa_family = AF_UNIX;
	PN_EXPECT(EINVAL, bind(c, (struct sockaddr *)big, sizeof(sun) + 1));
	PN_EXPECT(EINVAL, connect(c, (struct sockaddr *)big, sizeof(sun) +
	    1));
	PN_EXPECT(ENAMETOOLONG, bind(c, (struct sockaddr *)big,
	    SOCK_MAXADDRLEN + 1));
	PN_EXPECT(EINVAL, bind(c, (struct sockaddr *)big, 1));
	PN_EXPECT(EINVAL, bind(c, (struct sockaddr *)big, 0));
	/* getsockaddr() before getsock(): the length error wins. */
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	PN_EXPECT(ENAMETOOLONG, bind(fd, (struct sockaddr *)big,
	    SOCK_MAXADDRLEN + 1));
	PN_EXPECT(ENOTSOCK, bind(fd, (struct sockaddr *)&sun, sizeof(sun)));
	PN_EXPECT(EBADF, bind(1000, (struct sockaddr *)&sun, sizeof(sun)));
	close(fd);
	/* No path at all. */
	PN_EXPECT(EINVAL, bind(c, (struct sockaddr *)big, 2));
	/* uipc_connect() refuses an empty sun_path (historical behaviour). */
	PN_EXPECT(EINVAL, connect(c, (struct sockaddr *)big, 2));
	/* Wrong family. */
	((struct sockaddr *)big)->sa_family = AF_INET;
	strlcpy(((struct sockaddr_un *)big)->sun_path, "x", 2);
	PN_EXPECT(EAFNOSUPPORT, bind(c, (struct sockaddr *)big, 4));
	close(c);
	close(s);
}

ATF_TC(leading_nul);
ATF_TC_HEAD(leading_nul, tc)
{
	atf_tc_set_md_var(tc, "descr", "a native socket has no abstract "
	    "namespace: a name with a leading NUL is the empty path, ENOENT "
	    "for bind, connect and sendto, and creates nothing");
}
ATF_TC_BODY(leading_nul, tc)
{
	struct sockaddr_un sun;
	socklen_t len;
	int s, d;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, "\0procnet_abstract", 17);
	len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 17);
	s = fresh(SOCK_STREAM);
	PN_EXPECT(ENOENT, bind(s, (struct sockaddr *)&sun, len));
	PN_EXPECT(ENOENT, connect(s, (struct sockaddr *)&sun, len));
	d = fresh(SOCK_DGRAM);
	PN_EXPECT(ENOENT, sendto(d, "x", 1, 0, (struct sockaddr *)&sun,
	    len));
	close(d);
	close(s);
}

/* --- connect(2) and sendto(2) ---------------------------------------- */

ATF_TC(connect_errors);
ATF_TC_HEAD(connect_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "connect(2): ENOENT, ENOTSOCK for a "
	    "file or directory, ECONNREFUSED for a stale name or a bound "
	    "socket that does not listen, EPROTOTYPE across types, EISCONN "
	    "twice, EOPNOTSUPP from a listener, ELOOP for a symlink loop");
}
ATF_TC_BODY(connect_errors, tc)
{
	int l, s, b, d;

	l = listener("live");
	s = fresh(SOCK_STREAM);
	ATF_REQUIRE(bind_name(s, "stale") == 0);
	close(s);
	b = fresh(SOCK_STREAM);
	ATF_REQUIRE(bind_name(b, "bound") == 0);
	d = fresh(SOCK_DGRAM);
	ATF_REQUIRE(bind_name(d, "dgram") == 0);
	pn_writefile("file", "x", 1, 0644);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	ATF_REQUIRE(symlink("loop", "loop") == 0);
	ATF_REQUIRE(symlink("live", "tolive") == 0);

	s = fresh(SOCK_STREAM);
	PN_CHECK_ERRNO(ENOENT, connect_name(s, "missing"), "missing");
	PN_CHECK_ERRNO(ENOTSOCK, connect_name(s, "file"), "file");
	PN_CHECK_ERRNO(ENOTSOCK, connect_name(s, "dir"), "directory");
	PN_CHECK_ERRNO(ECONNREFUSED, connect_name(s, "stale"), "stale");
	PN_CHECK_ERRNO(ECONNREFUSED, connect_name(s, "bound"),
	    "not listening");
	PN_CHECK_ERRNO(EPROTOTYPE, connect_name(s, "dgram"),
	    "stream to dgram");
	PN_CHECK_ERRNO(ELOOP, connect_name(s, "loop"), "symlink loop");
	PN_CHECK_ERRNO(ENOTDIR, connect_name(s, "file/x"), "through a file");
	/* A symlink to the socket is followed. */
	PN_CHECK_ERRNO(0, connect_name(s, "tolive"), "through a symlink");
	PN_CHECK_ERRNO(EISCONN, connect_name(s, "live"), "twice");
	close(s);

	PN_CHECK_ERRNO(EOPNOTSUPP, connect_name(l, "live"), "from a listener");

	s = fresh(SOCK_DGRAM);
	PN_CHECK_ERRNO(EPROTOTYPE, connect_name(s, "live"), "dgram to stream");
	PN_CHECK_ERRNO(0, connect_name(s, "dgram"), "dgram to dgram");
	close(s);

	s = fresh(SOCK_SEQPACKET);
	PN_CHECK_ERRNO(EPROTOTYPE, connect_name(s, "live"),
	    "seqpacket to stream");
	close(s);
	close(b);
	close(d);
	close(l);
}

ATF_TC(connect_unpriv);
ATF_TC_HEAD(connect_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "connect(2) to a socket file the "
	    "caller may not write is EACCES; with write permission it works");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
connect_unpriv_child(void *arg)
{
	const char *dir = arg;
	int s;

	if (chdir(dir) != 0)
		return (PN_X_SETUP);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return (PN_X_SETUP);
	if (connect_name(s, "closed") != EACCES)
		return (PN_X_WRONG);
	if (connect_name(s, "open") != 0)
		return (errno == 0 ? PN_X_WRONG : errno);
	return (0);
}

ATF_TC_BODY(connect_unpriv, tc)
{
	char dir[PATH_MAX], p[PATH_MAX];
	int l1, l2;

	pn_pubdir("connect_unpriv", dir, sizeof(dir));
	snprintf(p, sizeof(p), "%s/closed", dir);
	l1 = listener(p);
	ATF_REQUIRE(chmod(p, 0755) == 0);
	snprintf(p, sizeof(p), "%s/open", dir);
	l2 = listener(p);
	ATF_REQUIRE(chmod(p, 0777) == 0);
	PN_CHECK_ERRNO(0, pn_child(connect_unpriv_child, dir, PN_UID,
	    PN_GID), "unprivileged connect");
	close(l1);
	close(l2);
	pn_pubdir_remove("connect_unpriv");
}

ATF_TC(listen_queue_full);
ATF_TC_HEAD(listen_queue_full, tc)
{
	atf_tc_set_md_var(tc, "descr", "connect(2) to a listener whose "
	    "queue is over its limit is ECONNREFUSED, after some successes");
}
ATF_TC_BODY(listen_queue_full, tc)
{
	int l, s[16], i, ok, refused, e;

	l = fresh(SOCK_STREAM);
	ATF_REQUIRE(bind_name(l, "q") == 0);
	ATF_REQUIRE(listen(l, 1) == 0);
	ok = refused = 0;
	for (i = 0; i < 16; i++) {
		s[i] = fresh(SOCK_STREAM);
		e = connect_name(s[i], "q");
		if (e == 0)
			ok++;
		else {
			PN_CHECK_ERRNO(ECONNREFUSED, e, "connect to a full "
			    "queue");
			refused++;
		}
	}
	ATF_CHECK(ok >= 1);
	ATF_CHECK(refused >= 1);
	for (i = 0; i < 16; i++)
		close(s[i]);
	close(l);
}

ATF_TC(sendto_errors);
ATF_TC_HEAD(sendto_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "dgram sendto(2): ENOENT, EPROTOTYPE "
	    "to a stream name, ECONNREFUSED to a stale name, EDESTADDRREQ "
	    "without an address, EISCONN with one when connected; a datagram "
	    "by name arrives");
}
ATF_TC_BODY(sendto_errors, tc)
{
	struct sockaddr_un sun;
	socklen_t len;
	char buf[8];
	int l, r, s, st;

	l = listener("stream");
	r = fresh(SOCK_DGRAM);
	ATF_REQUIRE(bind_name(r, "recv") == 0);
	st = fresh(SOCK_DGRAM);
	ATF_REQUIRE(bind_name(st, "stale") == 0);
	close(st);

	s = fresh(SOCK_DGRAM);
	len = sun_make(&sun, "missing");
	PN_EXPECT(ENOENT, sendto(s, "x", 1, 0, (struct sockaddr *)&sun, len));
	len = sun_make(&sun, "stream");
	PN_EXPECT(EPROTOTYPE, sendto(s, "x", 1, 0, (struct sockaddr *)&sun,
	    len));
	len = sun_make(&sun, "stale");
	PN_EXPECT(ECONNREFUSED, sendto(s, "x", 1, 0, (struct sockaddr *)&sun,
	    len));
	PN_EXPECT(EDESTADDRREQ, send(s, "x", 1, 0));
	len = sun_make(&sun, "recv");
	ATF_REQUIRE(sendto(s, "hello", 5, 0, (struct sockaddr *)&sun, len) ==
	    5);
	ATF_REQUIRE(recv(r, buf, sizeof(buf), 0) == 5);
	ATF_CHECK(memcmp(buf, "hello", 5) == 0);
	/* An unconnected sender stays unconnected. */
	PN_EXPECT(EDESTADDRREQ, send(s, "x", 1, 0));
	ATF_REQUIRE(connect_name(s, "recv") == 0);
	PN_EXPECT(EISCONN, sendto(s, "x", 1, 0, (struct sockaddr *)&sun,
	    len));
	ATF_REQUIRE(send(s, "y", 1, 0) == 1);
	ATF_REQUIRE(recv(r, buf, sizeof(buf), 0) == 1);
	ATF_CHECK_EQ('y', buf[0]);
	close(s);
	close(r);
	close(l);
}

/* --- bindat(2) and connectat(2) -------------------------------------- */

ATF_TC(dirfd_variants);
ATF_TC_HEAD(dirfd_variants, tc)
{
	atf_tc_set_md_var(tc, "descr", "bindat(2)/connectat(2) resolve "
	    "relative names from the dirfd and absolute ones from the root; "
	    "a file dirfd is ENOTDIR, a bad one EBADF; an empty name with a "
	    "socket dirfd connects to that socket (5BSD, as built)");
}
ATF_TC_BODY(dirfd_variants, tc)
{
	struct sockaddr_un sun;
	char abs[PATH_MAX];
	socklen_t len;
	struct stat st;
	int dfd, ffd, l, s, a;

	ATF_REQUIRE(mkdir("d", 0755) == 0);
	dfd = open("d", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	pn_writefile("file", "x", 1, 0644);
	ffd = open("file", O_RDONLY);
	ATF_REQUIRE(ffd >= 0);

	l = fresh(SOCK_STREAM);
	len = sun_make(&sun, "sock");
	PN_EXPECT(0, bindat(dfd, l, (struct sockaddr *)&sun, len));
	ATF_REQUIRE(lstat("d/sock", &st) == 0);
	ATF_CHECK(lstat("sock", &st) != 0);
	ATF_REQUIRE(listen(l, 8) == 0);

	s = fresh(SOCK_STREAM);
	PN_EXPECT(ENOENT, connect(s, (struct sockaddr *)&sun, len));
	PN_EXPECT(0, connectat(dfd, s, (struct sockaddr *)&sun, len));
	close(s);
	a = accept(l, NULL, NULL);
	ATF_REQUIRE(a >= 0);
	close(a);

	/* An absolute name ignores the dirfd, even a file one. */
	pn_cwdpath("d/sock", abs, sizeof(abs));
	if (strlen(abs) < SUN_PATH_LEN) {
		s = fresh(SOCK_STREAM);
		len = sun_make(&sun, abs);
		PN_EXPECT(0, connectat(ffd, s, (struct sockaddr *)&sun, len));
		close(s);
		a = accept(l, NULL, NULL);
		ATF_REQUIRE(a >= 0);
		close(a);
	}

	s = fresh(SOCK_STREAM);
	len = sun_make(&sun, "sock");
	PN_EXPECT(ENOTDIR, connectat(ffd, s, (struct sockaddr *)&sun, len));
	PN_EXPECT(EBADF, connectat(1000, s, (struct sockaddr *)&sun, len));
	PN_EXPECT(ENOTDIR, bindat(ffd, s, (struct sockaddr *)&sun, len));
	PN_EXPECT(EBADF, bindat(1000, s, (struct sockaddr *)&sun, len));
	/* Not a socket as s: ENOTSOCK. */
	PN_EXPECT(ENOTSOCK, connectat(dfd, ffd, (struct sockaddr *)&sun,
	    len));

	/* 5BSD: an empty name with a socket as dirfd names that socket. */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = (uint8_t)offsetof(struct sockaddr_un, sun_path);
	PN_EXPECT(0, connectat(l, s, (struct sockaddr *)&sun, sun.sun_len));
	close(s);
	a = accept(l, NULL, NULL);
	ATF_REQUIRE(a >= 0);
	close(a);
	/* A directory as dirfd with an empty name: the directory, ENOTSOCK. */
	s = fresh(SOCK_STREAM);
	PN_EXPECT(ENOTSOCK, connectat(dfd, s, (struct sockaddr *)&sun,
	    sun.sun_len));
	close(s);

	close(l);
	close(ffd);
	close(dfd);
}

/* --- connecting while the name is unlinked and rebound --------------- */

static volatile bool race_stop;

static void *
race_rebind(void *arg __unused)
{
	struct sockaddr_un sun;
	socklen_t len;
	int l;

	len = sun_make(&sun, "racesock");
	while (!race_stop) {
		l = socket(AF_UNIX, SOCK_STREAM, 0);
		if (l < 0)
			continue;
		if (bind(l, (struct sockaddr *)&sun, len) == 0) {
			(void)listen(l, 64);
			usleep(50);
			(void)unlink("racesock");
		}
		close(l);
	}
	return (NULL);
}

ATF_TC(connect_unlink_race);
ATF_TC_HEAD(connect_unlink_race, tc)
{
	atf_tc_set_md_var(tc, "descr", "connect(2)/sendto(2) while another "
	    "thread binds, unlinks and closes the name: only success, "
	    "ENOENT or ECONNREFUSED");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(connect_unlink_race, tc)
{
	pthread_t thr;
	int i, e, s, ok, other;

	race_stop = false;
	ATF_REQUIRE(pthread_create(&thr, NULL, race_rebind, NULL) == 0);
	ok = other = 0;
	for (i = 0; i < 20000; i++) {
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		ATF_REQUIRE(s >= 0);
		e = connect_name(s, "racesock");
		close(s);
		if (e == 0)
			ok++;
		else if (e != ENOENT && e != ECONNREFUSED) {
			other++;
			fprintf(stderr, "connect: %s\n", strerror(e));
		}
	}
	race_stop = true;
	ATF_REQUIRE(pthread_join(thr, NULL) == 0);
	ATF_CHECK_EQ_MSG(0, other, "%d unexpected errors", other);
	fprintf(stderr, "%d connections succeeded\n", ok);
}

/* --- accept(2), accept4(2) ------------------------------------------- */

ATF_TC(accept_variants);
ATF_TC_HEAD(accept_variants, tc)
{
	atf_tc_set_md_var(tc, "descr", "accept(2) inherits O_NONBLOCK, "
	    "accept4(2) does not unless asked; bad flags EINVAL; not a "
	    "listener EINVAL; not a socket ENOTSOCK; nothing pending on a "
	    "non-blocking listener EAGAIN; an unnamed peer's address is "
	    "AF_UNIX with no path");
}
ATF_TC_BODY(accept_variants, tc)
{
	struct sockaddr_un sun;
	socklen_t len;
	int l, c, a, fd;

	l = listener("acc");
	ATF_REQUIRE(fcntl(l, F_SETFL, O_NONBLOCK) == 0);
	PN_EXPECT(EAGAIN, accept(l, NULL, NULL));
	PN_EXPECT(EAGAIN, accept4(l, NULL, NULL, SOCK_CLOEXEC));
	PN_EXPECT(EINVAL, accept4(l, NULL, NULL, 0x1));
	PN_EXPECT(EINVAL, accept4(l, NULL, NULL, ~0));

	c = fresh(SOCK_STREAM);
	ATF_REQUIRE(connect_name(c, "acc") == 0);
	memset(&sun, 0xa5, sizeof(sun));
	len = sizeof(sun);
	a = accept(l, (struct sockaddr *)&sun, &len);
	ATF_REQUIRE(a >= 0);
	ATF_CHECK((fcntl(a, F_GETFL) & O_NONBLOCK) != 0);
	ATF_CHECK((fcntl(a, F_GETFD) & FD_CLOEXEC) == 0);
	ATF_CHECK_EQ(AF_UNIX, sun.sun_family);
	/* sun_noname: a bare struct sockaddr (16 bytes), no path. */
	ATF_CHECK_EQ_MSG((socklen_t)sizeof(struct sockaddr), len,
	    "address length %u", (unsigned)len);
	close(a);
	close(c);

	c = fresh(SOCK_STREAM);
	ATF_REQUIRE(connect_name(c, "acc") == 0);
	a = accept4(l, NULL, NULL, 0);
	ATF_REQUIRE(a >= 0);
	ATF_CHECK((fcntl(a, F_GETFL) & O_NONBLOCK) == 0);
	close(a);
	close(c);

	c = fresh(SOCK_STREAM);
	ATF_REQUIRE(connect_name(c, "acc") == 0);
	a = accept4(l, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	ATF_REQUIRE(a >= 0);
	ATF_CHECK((fcntl(a, F_GETFL) & O_NONBLOCK) != 0);
	ATF_CHECK((fcntl(a, F_GETFD) & FD_CLOEXEC) != 0);
	close(a);
	close(c);

	c = fresh(SOCK_STREAM);
	PN_EXPECT(EINVAL, accept(c, NULL, NULL));
	close(c);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	PN_EXPECT(ENOTSOCK, accept(fd, NULL, NULL));
	close(fd);
	PN_EXPECT(EBADF, accept(1000, NULL, NULL));
	close(l);
}

static int
accept_full_child(void *arg __unused)
{
	int l, c, a, lim;

	l = socket(AF_UNIX, SOCK_STREAM, 0);
	c = socket(AF_UNIX, SOCK_STREAM, 0);
	if (l < 0 || c < 0 || bind_name(l, "accfull") != 0 ||
	    listen(l, 4) != 0 || connect_name(c, "accfull") != 0)
		return (PN_X_SETUP);
	if ((lim = pn_fill_fdtable()) < 0)
		return (PN_X_SETUP);
	/* falloc() before the dequeue: EMFILE, the connection stays. */
	if (accept(l, NULL, NULL) != -1 || errno != EMFILE)
		return (PN_X_WRONG);
	/* Free one slot (the last /dev/null), not the client. */
	if (close(lim - 1) != 0)
		return (PN_X_SETUP);
	/* A slot is free again: the pending connection is accepted. */
	a = accept(l, NULL, NULL);
	if (a < 0)
		return (errno);
	return (0);
}

ATF_TC(accept_fdfull);
ATF_TC_HEAD(accept_fdfull, tc)
{
	atf_tc_set_md_var(tc, "descr", "accept(2) with a full table is "
	    "EMFILE and leaves the connection queued");
}
ATF_TC_BODY(accept_fdfull, tc)
{

	PN_CHECK_ERRNO(0, pn_child(accept_full_child, NULL, 0, 0),
	    "accept with a full table");
}

/* --- SCM_RIGHTS of sockets ------------------------------------------- */

static int
send_fd(int chan, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char buf[CMSG_SPACE(sizeof(int))];
	char c = 'F';

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));
	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	return (PN_ERR(sendmsg(chan, &msg, 0)));
}

static int
recv_fd(int chan, int flags)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char buf[CMSG_SPACE(sizeof(int))];
	char c;
	int fd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	ATF_REQUIRE(recvmsg(chan, &msg, flags) == 1);
	cm = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cm != NULL && cm->cmsg_type == SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return (fd);
}

ATF_TC(scm_rights_sockets);
ATF_TC_HEAD(scm_rights_sockets, tc)
{
	atf_tc_set_md_var(tc, "descr", "SCM_RIGHTS passes a connected socket "
	    "and a listening socket, both usable after receipt; "
	    "MSG_CMSG_CLOEXEC marks the received one; a receiver without "
	    "SO_PASSRIGHTS refuses with EPERM");
}
ATF_TC_BODY(scm_rights_sockets, tc)
{
	char c;
	int chan[2], pair[2], l, got, cl, a, off;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, chan) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);

	/* A connected socket. */
	PN_CHECK_ERRNO(0, send_fd(chan[0], pair[0]), "send connected");
	close(pair[0]);
	got = recv_fd(chan[1], 0);
	ATF_CHECK((fcntl(got, F_GETFD) & FD_CLOEXEC) == 0);
	ATF_REQUIRE(write(got, "z", 1) == 1);
	ATF_REQUIRE(read(pair[1], &c, 1) == 1);
	ATF_CHECK_EQ('z', c);
	close(got);
	/* The last reference went: the peer sees EOF. */
	ATF_CHECK_EQ(0, read(pair[1], &c, 1));
	close(pair[1]);

	/* A listener, received with MSG_CMSG_CLOEXEC. */
	l = listener("passed");
	PN_CHECK_ERRNO(0, send_fd(chan[0], l), "send listener");
	close(l);
	got = recv_fd(chan[1], MSG_CMSG_CLOEXEC);
	ATF_CHECK((fcntl(got, F_GETFD) & FD_CLOEXEC) != 0);
	cl = fresh(SOCK_STREAM);
	PN_CHECK_ERRNO(0, connect_name(cl, "passed"), "connect to passed");
	a = accept(got, NULL, NULL);
	ATF_CHECK(a >= 0);
	close(a);
	close(cl);
	close(got);

	/* A socket passed over itself, then closed: no leak, no hang. */
	PN_CHECK_ERRNO(0, send_fd(chan[0], chan[1]), "send over itself");

	/* SO_PASSRIGHTS off at the receiver: EPERM. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
	off = 0;
	ATF_REQUIRE(setsockopt(pair[1], SOL_SOCKET, SO_PASSRIGHTS, &off,
	    sizeof(off)) == 0);
	PN_CHECK_ERRNO(EPERM, send_fd(pair[0], chan[0]), "no SO_PASSRIGHTS");
	close(pair[0]);
	close(pair[1]);
	close(chan[0]);
	close(chan[1]);
}

/* --- sendfile(2) into unix(4) ---------------------------------------- */

#define	SF_SIZE		(1024 * 1024 + 4321)

struct sf_reader {
	int		fd;
	volatile size_t	got;
	bool		match;
	volatile int	error;
};

static unsigned char
sf_byte(size_t i)
{

	return ((unsigned char)((i * 2654435761u) >> 13));
}

static int
sf_file(void)
{
	unsigned char *buf;
	size_t i;
	int fd;

	buf = malloc(SF_SIZE);
	ATF_REQUIRE(buf != NULL);
	for (i = 0; i < SF_SIZE; i++)
		buf[i] = sf_byte(i);
	pn_writefile("sf_data", buf, SF_SIZE, 0644);
	free(buf);
	fd = open("sf_data", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fsync(fd) == 0);
	/* Drop the cached pages so sendfile(2) does real (async) I/O. */
	(void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	return (fd);
}

static void *
sf_read(void *arg)
{
	struct sf_reader *r = arg;
	unsigned char buf[8192];
	ssize_t n, k;

	r->got = 0;
	r->match = true;
	r->error = 0;
	for (;;) {
		n = read(r->fd, buf, sizeof(buf));
		if (n < 0) {
			r->error = errno;
			break;
		}
		if (n == 0)
			break;
		for (k = 0; k < n; k++)
			if (buf[k] != sf_byte(r->got + (size_t)k))
				r->match = false;
		r->got += (size_t)n;
	}
	return (NULL);
}

static void
sf_transfer(bool close_at_once)
{
	struct sf_reader r;
	pthread_t thr;
	off_t sbytes;
	int fd, sv[2];

	fd = sf_file();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	r.fd = sv[1];
	ATF_REQUIRE(pthread_create(&thr, NULL, sf_read, &r) == 0);
	sbytes = 0;
	PN_EXPECT(0, sendfile(fd, sv[0], 0, 0, NULL, &sbytes, 0));
	ATF_CHECK_EQ((off_t)SF_SIZE, sbytes);
	if (!close_at_once) {
		/* Wait until the reader has everything before closing. */
		while (r.got < SF_SIZE && r.error == 0)
			usleep(1000);
	}
	close(sv[0]);
	ATF_REQUIRE(pthread_join(thr, NULL) == 0);
	PN_CHECK_ERRNO(0, r.error, "reader");
	ATF_CHECK_EQ_MSG((size_t)SF_SIZE, r.got, "read %zu of %d before EOF",
	    r.got, SF_SIZE);
	ATF_CHECK_MSG(r.match, "the data differs");
	close(sv[1]);
	close(fd);
}

ATF_TC(sendfile_unix_complete);
ATF_TC_HEAD(sendfile_unix_complete, tc)
{
	atf_tc_set_md_var(tc, "descr", "sendfile(2) of an uncached file into "
	    "a stream pair delivers every byte in order; the sender closes "
	    "only after the reader has it all (valid on both kernels)");
}
ATF_TC_BODY(sendfile_unix_complete, tc)
{

	sf_transfer(false);
}

ATF_TC(sendfile_unix_close_at_once);
ATF_TC_HEAD(sendfile_unix_close_at_once, tc)
{
	atf_tc_set_md_var(tc, "descr", "INTENDED FIX 02ae46680f4: the sender "
	    "closes right after sendfile(2); the reader still gets every "
	    "byte before EOF (skipped with -v pre1c=yes: an early-EOF race "
	    "there)");
}
ATF_TC_BODY(sendfile_unix_close_at_once, tc)
{
	int i;

	if (pn_pre1c(tc))
		atf_tc_skip("pre-1c kernel: early EOF race, fixed by "
		    "02ae46680f4");
	for (i = 0; i < 8; i++)
		sf_transfer(true);
}

ATF_TC(sendfile_unix_peer_closed);
ATF_TC_HEAD(sendfile_unix_peer_closed, tc)
{
	atf_tc_set_md_var(tc, "descr", "sendfile(2) to a stream whose peer "
	    "has closed is ENOTCONN with nothing sent; write(2) is EPIPE");
}
ATF_TC_BODY(sendfile_unix_peer_closed, tc)
{
	off_t sbytes;
	int fd, sv[2];

	ATF_REQUIRE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	fd = sf_file();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	close(sv[1]);
	sbytes = -1;
	/*
	 * The peer's close disconnected the pair: uipc_sendfile_wait()
	 * tests SS_ISCONNECTED first; sosend() (write(2)) tests
	 * SBS_CANTSENDMORE first.
	 */
	PN_EXPECT(ENOTCONN, sendfile(fd, sv[0], 0, 0, NULL, &sbytes, 0));
	ATF_CHECK_EQ(0, sbytes);
	PN_EXPECT(EPIPE, write(sv[0], "x", 1));
	close(sv[0]);
	close(fd);
}

ATF_TC(sendfile_unix_peer_shut_rd);
ATF_TC_HEAD(sendfile_unix_peer_shut_rd, tc)
{
	atf_tc_set_md_var(tc, "descr", "INTENDED FIX 02ae46680f4: sendfile(2) "
	    "into a peer that did shutdown(SHUT_RD) is EPIPE at once, as "
	    "write(2) (skipped with -v pre1c=yes: appended or blocked "
	    "there)");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(sendfile_unix_peer_shut_rd, tc)
{
	off_t sbytes;
	int fd, sv[2];

	ATF_REQUIRE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	fd = sf_file();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(shutdown(sv[1], SHUT_RD) == 0);
	/* write(2) into a shut receive buffer: EPIPE on both kernels. */
	PN_EXPECT(EPIPE, write(sv[0], "x", 1));
	if (pn_pre1c(tc))
		atf_tc_skip("pre-1c kernel: sendfile(2) into SHUT_RD, "
		    "changed by 02ae46680f4");
	sbytes = -1;
	PN_EXPECT(EPIPE, sendfile(fd, sv[0], 0, 0, NULL, &sbytes, 0));
	ATF_CHECK_EQ(0, sbytes);
	close(sv[0]);
	close(sv[1]);
	close(fd);
}

ATF_TC(sendfile_unix_full);
ATF_TC_HEAD(sendfile_unix_full, tc)
{
	atf_tc_set_md_var(tc, "descr", "non-blocking sendfile(2) into a full "
	    "peer is EAGAIN with nothing sent; once drained it proceeds");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(sendfile_unix_full, tc)
{
	char buf[65536];
	off_t sbytes;
	ssize_t n;
	int fd, sv[2];

	fd = sf_file();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	memset(buf, 'f', sizeof(buf));
	while ((n = write(sv[0], buf, sizeof(buf))) > 0)
		;
	ATF_REQUIRE_EQ(EAGAIN, errno);
	sbytes = -1;
	PN_EXPECT(EAGAIN, sendfile(fd, sv[0], 0, 0, NULL, &sbytes, 0));
	/* To be confirmed: no space at all, so nothing was queued. */
	ATF_CHECK_EQ(0, sbytes);
	/* Drain, then a page goes. */
	ATF_REQUIRE(fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
	while (read(sv[1], buf, sizeof(buf)) > 0)
		;
	sbytes = 0;
	(void)sendfile(fd, sv[0], 0, 4096, NULL, &sbytes, 0);
	ATF_CHECK_EQ(4096, sbytes);
	close(sv[0]);
	close(sv[1]);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bind_errors);
	ATF_TP_ADD_TC(tp, bind_unpriv);
	ATF_TP_ADD_TC(tp, sun_lengths);
	ATF_TP_ADD_TC(tp, leading_nul);
	ATF_TP_ADD_TC(tp, connect_errors);
	ATF_TP_ADD_TC(tp, connect_unpriv);
	ATF_TP_ADD_TC(tp, listen_queue_full);
	ATF_TP_ADD_TC(tp, sendto_errors);
	ATF_TP_ADD_TC(tp, dirfd_variants);
	ATF_TP_ADD_TC(tp, connect_unlink_race);
	ATF_TP_ADD_TC(tp, accept_variants);
	ATF_TP_ADD_TC(tp, accept_fdfull);
	ATF_TP_ADD_TC(tp, scm_rights_sockets);
	ATF_TP_ADD_TC(tp, sendfile_unix_complete);
	ATF_TP_ADD_TC(tp, sendfile_unix_close_at_once);
	ATF_TP_ADD_TC(tp, sendfile_unix_peer_closed);
	ATF_TP_ADD_TC(tp, sendfile_unix_peer_shut_rd);
	ATF_TP_ADD_TC(tp, sendfile_unix_full);
	return (atf_no_error());
}
