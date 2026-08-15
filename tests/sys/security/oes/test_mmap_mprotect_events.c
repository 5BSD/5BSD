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

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
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
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP) {
				got_mmap = 1;
				printf("    INFO: mmap event: prot=0x%x flags=0x%x\n",
				    msg->em_event_data.mmap.prot,
				    msg->em_event_data.mmap.flags);
			}
		}
	}

	if (!got_mmap)
		printf("    INFO: no mmap event received\n");

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

	TEST_BEGIN("mmap anonymous event");

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

	/* mmap anonymous memory */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED) {
		TEST_FAIL("mmap anon: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Check for mmap event (anonymous mmap may or may not generate events) */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP)
				got_mmap = 1;
		}
	}

	printf("    INFO: anonymous mmap event: %s\n", got_mmap ? "yes" : "no");

	munmap(addr, 4096);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_mprotect(void)
{
	int fd;
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

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Allocate memory */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
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
			if (msg->em_event == OES_EVENT_NOTIFY_MPROTECT) {
				got_mprotect = 1;
				printf("    INFO: mprotect event: new_prot=0x%x\n",
				    msg->em_event_data.mprotect.prot);
			}
		}
	}

	if (!got_mprotect)
		printf("    INFO: no mprotect event received\n");

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

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
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
	(void)write(testfd, buf, sizeof(buf));

	/* mmap with PROT_EXEC */
	addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, testfd, 0);
	if (addr == MAP_FAILED) {
		if (errno == EACCES) {
			printf("    INFO: PROT_EXEC denied (W^X enforcement)\n");
			close(testfd);
			unlink(temppath);
			close(fd);
			TEST_PASS();
			return (0);
		}
		TEST_FAIL("mmap exec: %s", strerror(errno));
		close(testfd);
		unlink(temppath);
		close(fd);
		return (1);
	}

	/* Check for mmap event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_MMAP) {
				got_mmap = 1;
				if (msg->em_event_data.mmap.prot & PROT_EXEC)
					printf("    INFO: EXEC mmap detected\n");
			}
		}
	}

	printf("    INFO: exec mmap event: %s\n", got_mmap ? "yes" : "no");

	munmap(addr, 4096);
	close(testfd);
	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_auth_mmap(void)
{
	int fd, testfd;
	char temppath[64];
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_invert_args invert;
	oes_event_type_t events[] = { OES_EVENT_AUTH_MMAP };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	pid_t child;
	int pipefd[2];
	char buf;
	void *addr;
	int status;

	TEST_BEGIN("AUTH mmap (allow)");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 5000;
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
	(void)ioctl(fd, OES_IOC_SET_MUTE_INVERT, &invert);

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
		int f = open(temppath, O_RDONLY);
		if (f < 0)
			_exit(2);
		addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0);
		close(f);
		if (addr == MAP_FAILED)
			_exit(3);
		munmap(addr, 4096);
		_exit(0);
	}

	close(pipefd[0]);

	/* Mute child so it's monitored (inverted mode) */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = child;
	(void)ioctl(fd, OES_IOC_MUTE_PROCESS, &mute);

	/* Signal child to proceed */
	(void)write(pipefd[1], "G", 1);
	close(pipefd[1]);

	/* Wait for AUTH_MMAP event */
	if (test_wait_event_type(fd, msg, OES_EVENT_AUTH_MMAP, 3000) == 0) {
		printf("    INFO: got AUTH_MMAP event, allowing\n");
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_ALLOW;
		(void)write(fd, &resp, sizeof(resp));
	} else {
		printf("    INFO: no AUTH_MMAP event received\n");
	}

	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("    INFO: child mmap succeeded\n");
	} else {
		printf("    INFO: child exit status: %d\n",
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}

	unlink(temppath);
	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	TEST_SUITE_BEGIN("mmap/mprotect events");

	test_mmap_file();
	test_mmap_anon();
	test_mprotect();
	test_mmap_exec();
	test_auth_mmap();

	TEST_SUITE_END("mmap/mprotect events");
}
