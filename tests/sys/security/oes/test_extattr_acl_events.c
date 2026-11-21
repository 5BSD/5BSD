/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES extended attribute and ACL event tests.
 *
 * Tests extattr get/set/delete/list and ACL operations.
 */
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sys/mdioctl.h>
#include <sys/stat.h>

#include "test_common.h"

/* An actor's exit status when the filesystem has no extended attributes. */
#define	EXTATTR_NOTSUP	77

static int
extattr_set_get(void *arg)
{
	const char *path = arg, *val = "test_value";
	char buf[64];

	if (extattr_set_file(path, EXTATTR_NAMESPACE_USER, "test_attr", val,
	    strlen(val)) < 0)
		return (errno == EOPNOTSUPP || errno == ENOTSUP ?
		    EXTATTR_NOTSUP : 1);
	if (extattr_get_file(path, EXTATTR_NAMESPACE_USER, "test_attr", buf,
	    sizeof(buf)) < 0)
		return (2);
	return (0);
}

static int
extattr_list_delete(void *arg)
{
	const char *path = arg;
	char buf[256];

	if (extattr_list_file(path, EXTATTR_NAMESPACE_USER, buf,
	    sizeof(buf)) < 0)
		return (1);
	if (extattr_delete_file(path, EXTATTR_NAMESPACE_USER,
	    "test_attr2") < 0)
		return (2);
	return (0);
}

static int
test_extattr_set_get(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_SETEXTATTR,
		OES_EVENT_NOTIFY_GETEXTATTR,
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	pid_t actor;
	int got_set = 0, got_get = 0, status;

	TEST_BEGIN("extattr set/get events");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 2, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Create temp file */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	close(testfd);

	/*
	 * Set and get the attribute in an actor child: the test opened the
	 * client, so its own events never reach it (oes(4)).
	 */
	actor = test_in_child(extattr_set_get, temppath, &status);
	if (actor < 0 || !WIFEXITED(status) ||
	    (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != EXTATTR_NOTSUP)) {
		TEST_FAIL("extattr set/get in the actor failed (status %#x)",
		    status);
		unlink(temppath);
		close(fd);
		return (1);
	}
	if (WEXITSTATUS(status) == EXTATTR_NOTSUP) {
		printf("    INFO: extattr not supported on this filesystem\n");
		unlink(temppath);
		close(fd);
		TEST_SKIP("extattr not supported");
		return (0);
	}

	/* Check for events */
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_process.ep_pid != actor)
				continue;
			if (msg->em_event == OES_EVENT_NOTIFY_SETEXTATTR)
				got_set = 1;
			else if (msg->em_event == OES_EVENT_NOTIFY_GETEXTATTR)
				got_get = 1;
		}
	}

	printf("    INFO: set event: %s, get event: %s\n",
	    got_set ? "yes" : "no", got_get ? "yes" : "no");

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_extattr_delete_list(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_DELETEEXTATTR,
		OES_EVENT_NOTIFY_LISTEXTATTR,
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	const char *attrname = "test_attr2";
	const char *attrval = "test_value2";
	ssize_t ret;
	pid_t actor;
	int got_delete = 0, got_list = 0, status;

	TEST_BEGIN("extattr delete/list events");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 2, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Create temp file and set attr (the test's own events are not seen) */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	close(testfd);

	ret = extattr_set_file(temppath, EXTATTR_NAMESPACE_USER, attrname,
	    attrval, strlen(attrval));
	if (ret < 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			unlink(temppath);
			close(fd);
			TEST_SKIP("extattr not supported");
			return (0);
		}
		TEST_FAIL("extattr_set_file: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* List, then delete, in an actor child. */
	actor = test_in_child(extattr_list_delete, temppath, &status);
	if (actor < 0 || !test_child_ok(status)) {
		TEST_FAIL("extattr list/delete in the actor failed (status %#x)",
		    status);
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for events */
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_process.ep_pid != actor)
				continue;
			if (msg->em_event == OES_EVENT_NOTIFY_DELETEEXTATTR)
				got_delete = 1;
			else if (msg->em_event == OES_EVENT_NOTIFY_LISTEXTATTR)
				got_list = 1;
		}
	}

	printf("    INFO: delete event: %s, list event: %s\n",
	    got_delete ? "yes" : "no", got_list ? "yes" : "no");

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * The ACL events need a filesystem with ACLs.  The test directory's (tmpfs
 * in the guest tier) has none, and neither has UFS in this kernel, which is
 * built without UFS_ACL.  ZFS has NFSv4 ACLs, so the test brings its own
 * pool: one memory disk, mounted on a temporary directory and destroyed at
 * the end.
 */
static int acl_md_ctl = -1;
static unsigned acl_md_unit;
static char acl_md_dev[32];
static char acl_pool[32];
static char acl_mnt[] = "/tmp/oes-acl.XXXXXX";
static bool acl_mnt_made, acl_pool_made;

/* Run a program to completion, its standard output discarded. */
static int
acl_run(char *const argv[])
{
	pid_t pid;
	int devnull, status;

	fflush(NULL);
	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0)
			(void)dup2(devnull, STDOUT_FILENO);
		execv(argv[0], argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static void
acl_fixture_down(void)
{
	char *destroy[] = { __DECONST(char *, "/sbin/zpool"),
	    __DECONST(char *, "destroy"), __DECONST(char *, "-f"), acl_pool,
	    NULL };
	struct md_ioctl mdio;

	if (acl_pool_made)
		(void)acl_run(destroy);
	acl_pool_made = false;
	if (acl_md_ctl >= 0) {
		memset(&mdio, 0, sizeof(mdio));
		mdio.md_version = MDIOVERSION;
		mdio.md_unit = acl_md_unit;
		(void)ioctl(acl_md_ctl, MDIOCDETACH, &mdio);
		close(acl_md_ctl);
		acl_md_ctl = -1;
	}
	if (acl_mnt_made)
		(void)rmdir(acl_mnt);
	acl_mnt_made = false;
}

/* 0, or -1 with the step that failed in *why and errno set. */
static int
acl_fixture_up(const char **why)
{
	char *create[] = { __DECONST(char *, "/sbin/zpool"),
	    __DECONST(char *, "create"), __DECONST(char *, "-f"),
	    __DECONST(char *, "-O"), __DECONST(char *, "acltype=nfsv4"),
	    __DECONST(char *, "-m"), acl_mnt, acl_pool, acl_md_dev, NULL };
	struct md_ioctl mdio;
	int error;

	*why = "open /dev/" MDCTL_NAME;
	acl_md_ctl = open("/dev/" MDCTL_NAME, O_RDWR | O_CLOEXEC);
	if (acl_md_ctl < 0)
		return (-1);
	*why = "MDIOCATTACH";
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_SWAP;
	mdio.md_mediasize = 128 * 1024 * 1024;
	mdio.md_sectorsize = 512;
	mdio.md_options = MD_AUTOUNIT;
	if (ioctl(acl_md_ctl, MDIOCATTACH, &mdio) != 0) {
		error = errno;
		close(acl_md_ctl);
		acl_md_ctl = -1;
		errno = error;
		return (-1);
	}
	acl_md_unit = mdio.md_unit;
	snprintf(acl_md_dev, sizeof(acl_md_dev), "/dev/%s%u", MD_NAME,
	    acl_md_unit);

	*why = "mkdtemp";
	if (mkdtemp(acl_mnt) == NULL)
		return (-1);
	acl_mnt_made = true;

	*why = "zpool create (its message is on standard error)";
	snprintf(acl_pool, sizeof(acl_pool), "oesacl%d", (int)getpid());
	error = acl_run(create);
	if (error != 0) {
		errno = error == -1 ? errno : ENOEXEC;
		return (-1);
	}
	acl_pool_made = true;
	return (0);
}

/*
 * Wait for one ACL event of the actor on the given file and check the ACL
 * type it names.
 */
static void
expect_acl_event(int fd, pid_t actor, oes_event_type_t event,
    const char *what, const struct stat *sb, int acl_type)
{
	test_msg_buf buf;
	const oes_event_acl_t *ea;
	struct timespec start, now;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 5) {
			TEST_FAIL("%s: event not received", what);
			return;
		}
		if (test_wait_event(fd, &buf.msg, 100) != 0 ||
		    buf.msg.em_event != event ||
		    buf.msg.em_process.ep_pid != actor)
			continue;
		/* The three ACL events share one layout. */
		ea = &buf.msg.em_event_data.getacl;
		if (ea->file.ef_ino != (uint64_t)sb->st_ino ||
		    ea->file.ef_dev != (uint64_t)sb->st_dev)
			continue;
		ASSERT_MSG(ea->type == acl_type, "%s: ACL type %d, want %d",
		    what, ea->type, acl_type);
		ASSERT_MSG(strcmp(ea->file.ef_fstype, "zfs") == 0,
		    "%s: filesystem type '%s'", what, ea->file.ef_fstype);
		return;
	}
}

/* The ACL actor's exit status: one bit per step that failed. */
#define	ACL_R_GET	0x01
#define	ACL_R_SET	0x02
#define	ACL_R_GETDIR	0x04
#define	ACL_R_DELOK	0x08	/* the delete succeeded: it must not */

static char acl_file[96], acl_dir[96];

static int
acl_actor(void *arg __unused)
{
	acl_t acl;
	int rc = 0;

	acl = acl_get_file(acl_file, ACL_TYPE_NFS4);
	if (acl == NULL)
		rc |= ACL_R_GET | ACL_R_SET;
	else {
		if (acl_set_file(acl_file, ACL_TYPE_NFS4, acl) != 0)
			rc |= ACL_R_SET;
		acl_free(acl);
	}
	acl = acl_get_file(acl_dir, ACL_TYPE_NFS4);
	if (acl == NULL)
		rc |= ACL_R_GETDIR;
	else
		acl_free(acl);
	if (acl_delete_file_np(acl_dir, ACL_TYPE_NFS4) == 0)
		rc |= ACL_R_DELOK;
	return (rc);
}

static int
test_acl_events(void)
{
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_GETACL,
		OES_EVENT_NOTIFY_SETACL,
		OES_EVENT_NOTIFY_DELETEACL,
	};
	char *file = acl_file, *dir = acl_dir;
	struct stat fsb, dsb;
	const char *why;
	pid_t actor;
	int fd, testfd, status, rc;

	TEST_BEGIN("ACL get, set and delete events");

	if (geteuid() != 0) {
		TEST_SKIP("the ACL fixture needs root");
		return (0);
	}
	if (acl_fixture_up(&why) != 0) {
		TEST_FAIL("ACL fixture: %s: %s", why, strerror(errno));
		acl_fixture_down();
		return (1);
	}
	snprintf(acl_file, sizeof(acl_file), "%s/file", acl_mnt);
	snprintf(acl_dir, sizeof(acl_dir), "%s/dir", acl_mnt);
	testfd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (testfd < 0 || fstat(testfd, &fsb) != 0 || mkdir(dir, 0755) != 0 ||
	    stat(dir, &dsb) != 0) {
		TEST_FAIL("ACL fixture files: %s", strerror(errno));
		if (testfd >= 0)
			close(testfd);
		acl_fixture_down();
		return (1);
	}
	close(testfd);

	fd = test_open_oes();
	if (fd < 0 || test_set_mode(fd, OES_MODE_NOTIFY) < 0 ||
	    test_subscribe(fd, events, 3, OES_SUB_REPLACE) < 0) {
		TEST_FAIL("client setup: %s", strerror(errno));
		if (fd >= 0)
			close(fd);
		acl_fixture_down();
		return (1);
	}

	/*
	 * The actor child reads the file's ACL and writes it back, reads the
	 * directory's, then asks to delete it; the events arrive in that
	 * order.  The test opened the client, so its own are never seen.
	 */
	actor = test_in_child(acl_actor, NULL, &status);
	ASSERT_MSG(actor > 0 && WIFEXITED(status), "ACL actor did not run");
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : 0xff;
	ASSERT_MSG((rc & ACL_R_GET) == 0, "acl_get_file failed");
	ASSERT_MSG((rc & ACL_R_SET) == 0, "acl_set_file failed");
	ASSERT_MSG((rc & ACL_R_GETDIR) == 0, "acl_get_file, directory, failed");
	ASSERT_MSG((rc & ACL_R_DELOK) == 0, "deleting an NFSv4 ACL succeeded");
	if ((rc & ACL_R_GET) == 0) {
		expect_acl_event(fd, actor, OES_EVENT_NOTIFY_GETACL, "get",
		    &fsb, ACL_TYPE_NFS4);
		if ((rc & ACL_R_SET) == 0)
			expect_acl_event(fd, actor, OES_EVENT_NOTIFY_SETACL,
			    "set", &fsb, ACL_TYPE_NFS4);
	}
	if ((rc & ACL_R_GETDIR) == 0)
		expect_acl_event(fd, actor, OES_EVENT_NOTIFY_GETACL,
		    "get directory", &dsb, ACL_TYPE_NFS4);
	/*
	 * An NFSv4 ACL cannot be removed, only replaced, and no filesystem
	 * in this kernel has a POSIX.1e default ACL to delete.  The request
	 * still passes the MAC check, where the event is generated, before
	 * ZFS refuses it; the event reports the request.
	 */
	expect_acl_event(fd, actor, OES_EVENT_NOTIFY_DELETEACL, "delete", &dsb,
	    ACL_TYPE_NFS4);

	close(fd);
	acl_fixture_down();
	TEST_PASS();
	return (0);
}

int
main(void)
{
	TEST_SUITE_BEGIN("extattr/acl events");

	(void)atexit(acl_fixture_down);
	test_extattr_set_get();
	test_extattr_delete_list();
	test_acl_events();

	if (oes_test_failures == 0)
		TEST_SUITE_END("extattr/acl events");
	return (oes_test_failures != 0);
}
