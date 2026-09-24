/* SPDX-License-Identifier: BSD-2-Clause */
/* Native POSIX AIO regression for the shared Linux-ABI adapter changes. */
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int
wait_done(struct aiocb *cb, ssize_t wanted)
{
	const struct aiocb *list[1] = { cb };
	struct timespec timeout = { .tv_sec = 10 };
	int error;

	for (;;) {
		error = aio_error(cb);
		if (error != EINPROGRESS)
			break;
		if (aio_suspend(list, 1, &timeout) != 0 && errno != EINTR)
			return (1);
	}
	return (error != 0 || aio_return(cb) != wanted);
}

int
main(void)
{
	const char path[] = "native-aio-test-file";
	char input[] = "abcde", output[6] = { 0 };
	struct aiocb cb;
	int fd;

	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd < 0)
		return (1);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_offset = 0;
	cb.aio_buf = input;
	cb.aio_nbytes = 5;
	if (aio_write(&cb) != 0 || wait_done(&cb, 5) != 0)
		return (2);
	if (pread(fd, output, 5, 0) != 5 || memcmp(output, input, 5) != 0)
		return (3);
	memset(output, 0, sizeof(output));
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_offset = 0;
	cb.aio_buf = output;
	cb.aio_nbytes = 5;
	if (aio_read(&cb) != 0 || wait_done(&cb, 5) != 0 ||
	    memcmp(output, input, 5) != 0)
		return (4);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	if (aio_fsync(O_SYNC, &cb) != 0 || wait_done(&cb, 0) != 0)
		return (5);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = -1;
	cb.aio_buf = input;
	cb.aio_nbytes = 1;
	if (aio_write(&cb) != -1 || errno != EBADF)
		return (6);
	if (close(fd) != 0 || unlink(path) != 0)
		return (7);
	return (0);
}
