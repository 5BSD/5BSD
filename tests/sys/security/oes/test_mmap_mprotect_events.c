/*
 * OES mmap/mprotect event tests.
 *
 * Tests memory mapping operations and protection changes.
 */
#include "test_common.h"

#include <sys/mman.h>
#include <sys/stat.h>

static int
test_mmap_file(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_MMAP };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	void *addr;
	char data[] = "test data for mmap";
	int got_mmap = 0;

	TEST_BEGIN("mmap file event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Create temp file with data */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	(void)write(testfd, data, sizeof(data));

	/* mmap the file */
	addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, testfd, 0);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(testfd);
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for mmap event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP &&
			    msg->em_process.ep_pid == getpid()) {
				got_mmap = 1;
				printf("    INFO: mmap event: prot=0x%x flags=0x%x\n",
				    msg->em_event_data.mmap.prot,
				    msg->em_event_data.mmap.flags);
			}
		}
	}

	if (!got_mmap)
		TEST_FAIL("no file mmap event received");

	munmap(addr, 4096);
	close(testfd);
	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_mmap_anon(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_MMAP };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	void *addr;
	int got_mmap = 0;

	TEST_BEGIN("anonymous mmap has no vnode event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* mmap anonymous memory */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap anon: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* The vnode hook must not invent a file event for an anonymous mapping. */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP &&
			    msg->em_process.ep_pid == getpid())
				got_mmap = 1;
		}
	}

	if (got_mmap)
		TEST_FAIL("unexpected anonymous file mmap event");

	munmap(addr, 4096);
	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * oes_event_mprotect_t documents the backing file as optional, so an
 * anonymous mapping must still report the mprotect -- with an empty file --
 * rather than being dropped for want of a vnode.
 */
static int
test_mprotect_anon(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_MPROTECT };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	void *addr;
	int got_mprotect = 0, got_file = 0;

	TEST_BEGIN("anonymous mprotect event has no file");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return (1);
	}

	if (mprotect(addr, 4096, PROT_READ) < 0) {
		TEST_FAIL("mprotect: %s", strerror(errno));
		munmap(addr, 4096);
		close(fd);
		return (1);
	}

	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MPROTECT &&
			    msg->em_process.ep_pid == getpid() &&
			    msg->em_event_data.mprotect.prot == PROT_READ) {
				got_mprotect = 1;
				if (msg->em_event_data.mprotect.file.ef_ino != 0 ||
				    msg->em_event_data.mprotect.file.ef_fstype[0] != '\0')
					got_file = 1;
			}
		}
	}

	if (!got_mprotect)
		TEST_FAIL("no anonymous mprotect event received");
	if (got_file)
		TEST_FAIL("anonymous mprotect event reported a backing file");

	munmap(addr, 4096);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_mprotect(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_MPROTECT };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	void *addr;
	int got_mprotect = 0;

	TEST_BEGIN("mprotect event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* mprotect's OES hook observes vnode-backed mappings. */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	if (ftruncate(testfd, 4096) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(testfd);
		unlink(temppath);
		close(fd);
		return (1);
	}
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	    MAP_SHARED, testfd, 0);
	close(testfd);
	unlink(temppath);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Change protection */
	if (mprotect(addr, 4096, PROT_READ) < 0) {
		TEST_FAIL("mprotect: %s", strerror(errno));
		munmap(addr, 4096);
		close(fd);
		return (1);
	}

	/* Check for mprotect event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MPROTECT &&
			    msg->em_process.ep_pid == getpid() &&
			    msg->em_event_data.mprotect.prot == PROT_READ) {
				got_mprotect = 1;
				printf("    INFO: mprotect event: new_prot=0x%x\n",
				    msg->em_event_data.mprotect.prot);
			}
		}
	}

	if (!got_mprotect)
		TEST_FAIL("no file mprotect event received");

	munmap(addr, 4096);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_mmap_exec(void)
{
	int fd, testfd;
	char temppath[64];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_MMAP };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	void *addr;
	int got_mmap = 0;

	TEST_BEGIN("mmap with PROT_EXEC");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Create temp file */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	/* Write some bytes */
	char buf[4096];
	memset(buf, 0x90, sizeof(buf));  /* NOP sled */
	if (write(testfd, buf, sizeof(buf)) != sizeof(buf) ||
	    fchmod(testfd, 0700) < 0) {
		TEST_FAIL("prepare executable mapping: %s", strerror(errno));
		close(testfd);
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* mmap with PROT_EXEC */
	addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, testfd, 0);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap exec: %s", strerror(errno));
		close(testfd);
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for mmap event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP &&
			    msg->em_process.ep_pid == getpid() &&
			    (msg->em_event_data.mmap.prot & PROT_EXEC) != 0) {
				got_mmap = 1;
				if (msg->em_event_data.mmap.prot & PROT_EXEC)
					printf("    INFO: EXEC mmap detected\n");
			}
		}
	}

	if (!got_mmap)
		TEST_FAIL("no executable mmap event received");

	munmap(addr, 4096);
	close(testfd);
	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_auth_mapping(int deny, int protect)
{
	int fd, testfd;
	char temppath[64];
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_invert_args invert;
	oes_event_type_t events[] = {
		protect ? OES_EVENT_AUTH_MPROTECT : OES_EVENT_AUTH_MMAP
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	pid_t child;
	int pipefd[2];
	char buf;
	void *addr;
	int status;

	TEST_BEGIN(protect ? (deny ? "AUTH mprotect (deny)" :
	    "AUTH mprotect (allow)") : (deny ? "AUTH mmap (deny)" :
	    "AUTH mmap (allow)"));

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = 5000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		TEST_FAIL("set mode: %s", strerror(errno));
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		TEST_FAIL("subscribe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Invert muting so only selected processes are monitored */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = OES_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	if (ioctl(fd, OES_IOC_SET_MUTE_INVERT, &invert) < 0) {
		TEST_FAIL("invert process selection: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Create temp file */
	testfd = test_create_temp_file(temppath, sizeof(temppath));
	if (testfd < 0) {
		close(fd);
		return (1);
	}
	char data[4096];
	memset(data, 'A', sizeof(data));
	(void)write(testfd, data, sizeof(data));
	close(testfd);

	if (pipe(pipefd) < 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		unlink(temppath);
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		unlink(temppath);
		close(fd);
		return (1);
	}

	if (child == 0) {
		close(pipefd[1]);
		close(fd);

		/* Wait for parent */
		if (read(pipefd[0], &buf, 1) != 1)
			_exit(1);
		close(pipefd[0]);

		/* Try to mmap the file */
		int f = open(temppath, protect ? O_RDWR : O_RDONLY);
		if (f < 0)
			_exit(2);
		addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0);
		int map_errno = errno;
		close(f);
		if (protect) {
			if (addr == MAP_FAILED)
				_exit(5);
			int result = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
			int protect_errno = errno;
			munmap(addr, 4096);
			_exit(deny ? !(result == -1 && protect_errno == EACCES) :
			    result != 0);
		}
		if (deny)
			_exit(addr == MAP_FAILED && map_errno == EACCES ? 0 : 4);
		if (addr == MAP_FAILED)
			_exit(3);
		munmap(addr, 4096);
		_exit(0);
	}

	close(pipefd[0]);

	/* Mute child so it's monitored (inverted mode) */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = child;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0)
		TEST_FAIL("select child: %s", strerror(errno));

	/* Signal child to proceed */
	(void)write(pipefd[1], "G", 1);
	close(pipefd[1]);

	/* The operation must actually reach the subscribed authorization hook. */
	if (test_wait_event_type(fd, msg, events[0], 3000) == 0 &&
	    msg->em_process.ep_pid == child) {
		printf("    INFO: got mapping AUTH event, responding\n");
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = deny ? OES_AUTH_DENY : OES_AUTH_ALLOW;
		if (write(fd, &resp, sizeof(resp)) != sizeof(resp))
			TEST_FAIL("write AUTH response: %s", strerror(errno));
	} else {
		TEST_FAIL("no matching mapping AUTH event received");
	}

	if (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		TEST_FAIL("child did not observe requested mapping authorization");

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	int failed = 0;

	TEST_SUITE_BEGIN("mmap/mprotect events");

	failed += test_mmap_file();
	failed += test_mmap_anon();
	failed += test_mprotect();
	failed += test_mprotect_anon();
	failed += test_mmap_exec();
	failed += test_auth_mapping(0, 0);
	failed += test_auth_mapping(1, 0);
	failed += test_auth_mapping(0, 1);
	failed += test_auth_mapping(1, 1);

	TEST_SUITE_END("mmap/mprotect events");
	return (failed != 0);
}
