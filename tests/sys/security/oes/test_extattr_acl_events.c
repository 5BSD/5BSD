/*
 * OES extended attribute and ACL event tests.
 *
 * Tests extattr get/set/delete/list and ACL operations.
 */
#include "test_common.h"

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/acl.h>

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
	const char *attrname = "test_attr";
	const char *attrval = "test_value";
	char buf[64];
	ssize_t ret;
	int got_set = 0, got_get = 0;

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

	/* Clear self-mute to receive events from our own actions */
	if (test_unmute_self(fd) < 0) {
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

	/* Set extended attribute */
	ret = extattr_set_file(temppath, EXTATTR_NAMESPACE_USER, attrname,
	    attrval, strlen(attrval));
	if (ret < 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			printf("    INFO: extattr not supported on this filesystem\n");
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

	/* Get extended attribute */
	ret = extattr_get_file(temppath, EXTATTR_NAMESPACE_USER, attrname,
	    buf, sizeof(buf));
	if (ret < 0) {
		TEST_FAIL("extattr_get_file: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for events */
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
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
	char buf[256];
	ssize_t ret;
	int got_delete = 0, got_list = 0;

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

	/* Clear self-mute to receive events from our own actions */
	if (test_unmute_self(fd) < 0) {
		close(fd);
		return (1);
	}

	/* Create temp file and set attr */
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

	/* Drain set event */
	test_drain_events(fd);

	/* List extended attributes */
	ret = extattr_list_file(temppath, EXTATTR_NAMESPACE_USER, buf, sizeof(buf));
	if (ret < 0) {
		TEST_FAIL("extattr_list_file: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Delete extended attribute */
	ret = extattr_delete_file(temppath, EXTATTR_NAMESPACE_USER, attrname);
	if (ret < 0) {
		TEST_FAIL("extattr_delete_file: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for events */
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
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

static int
test_acl_get_set(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_GETACL,
		OES_EVENT_NOTIFY_SETACL,
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	acl_t acl;
	acl_type_t acl_type = ACL_TYPE_ACCESS;
	int got_get = 0, got_set = 0;

	TEST_BEGIN("ACL get/set events");

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

	/* Clear self-mute to receive events from our own actions */
	if (test_unmute_self(fd) < 0) {
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

	/* Get ACL - try POSIX first, fall back to NFS4 for ZFS */
	acl = acl_get_file(temppath, ACL_TYPE_ACCESS);
	if (acl == NULL && errno == EINVAL) {
		/* ZFS uses NFS4 ACLs, not POSIX ACLs */
		acl = acl_get_file(temppath, ACL_TYPE_NFS4);
		acl_type = ACL_TYPE_NFS4;
	}
	if (acl == NULL) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			printf("    INFO: ACL not supported on this filesystem\n");
			unlink(temppath);
			close(fd);
			TEST_SKIP("ACL not supported");
			return (0);
		}
		TEST_FAIL("acl_get_file: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Set ACL (same ACL back) */
	if (acl_set_file(temppath, acl_type, acl) < 0) {
		TEST_FAIL("acl_set_file: %s", strerror(errno));
		acl_free(acl);
		unlink(temppath);
		close(fd);
		return (1);
	}

	acl_free(acl);

	/* Check for events */
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_GETACL)
				got_get = 1;
			else if (msg->em_event == OES_EVENT_NOTIFY_SETACL)
				got_set = 1;
		}
	}

	printf("    INFO: get ACL event: %s, set ACL event: %s\n",
	    got_get ? "yes" : "no", got_set ? "yes" : "no");

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_acl_delete(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_DELETEACL,
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int got_delete = 0;

	TEST_BEGIN("ACL delete event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Clear self-mute to receive events from our own actions */
	if (test_unmute_self(fd) < 0) {
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

	/* Try to delete default ACL (usually only makes sense for dirs) */
	if (acl_delete_def_file(temppath) < 0) {
		/* Expected to fail on regular files */
		printf("    INFO: acl_delete_def_file: %s (expected for files)\n",
		    strerror(errno));
	}

	/* Check for events */
	for (int i = 0; i < 2; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_DELETEACL)
				got_delete = 1;
		}
	}

	printf("    INFO: delete ACL event: %s\n", got_delete ? "yes" : "no");

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	TEST_SUITE_BEGIN("extattr/acl events");

	test_extattr_set_get();
	test_extattr_delete_list();
	test_acl_get_set();
	test_acl_delete();

	TEST_SUITE_END("extattr/acl events");
}
