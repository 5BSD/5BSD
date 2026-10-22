/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live test for a dttransport descriptor transferred after its opener exits.
 * Run as root in a guest with dttransport.ko loaded and no daemon holding it.
 */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <dev/dttransport/dttransport.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
send_fd(int sock, int fd)
{
	union {
		struct cmsghdr align;
		char control[CMSG_SPACE(sizeof(int))];
	} ancillary;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char byte;

	memset(&ancillary, 0, sizeof(ancillary));
	memset(&msg, 0, sizeof(msg));
	byte = 'F';
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ancillary.control;
	msg.msg_controllen = sizeof(ancillary.control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	return (sendmsg(sock, &msg, 0) == sizeof(byte) ? 0 : -1);
}

static int
receive_fd(int sock)
{
	union {
		struct cmsghdr align;
		char control[CMSG_SPACE(sizeof(int))];
	} ancillary;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char byte;
	int fd;

	memset(&ancillary, 0, sizeof(ancillary));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ancillary.control;
	msg.msg_controllen = sizeof(ancillary.control);
	if (recvmsg(sock, &msg, 0) != sizeof(byte) || byte != 'F' ||
	    (msg.msg_flags & MSG_CTRUNC) != 0)
		return (-1);
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
		return (-1);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return (fd);
}

int
main(void)
{
	struct dtt_vm_identity identity;
	char entry[DTT_ENTRYLEN];
	int pair[2], fd, status;
	pid_t opener;
	ssize_t read_result, write_result;
	int read_error, write_error, ioctl_error, commit_error, commit_result;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
		perror("socketpair");
		return (1);
	}
	opener = fork();
	if (opener < 0) {
		perror("fork");
		return (1);
	}
	if (opener == 0) {
		close(pair[0]);
		fd = open("/dev/dttransport", O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			perror("opener open");
			_exit(1);
		}
		status = send_fd(pair[1], fd);
		close(fd);
		close(pair[1]);
		_exit(status == 0 ? 0 : 1);
	}
	close(pair[1]);
	fd = receive_fd(pair[0]);
	close(pair[0]);
	if (waitpid(opener, &status, 0) != opener || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0 || fd < 0) {
		fprintf(stderr, "descriptor transfer failed\n");
		return (1);
	}

	memset(entry, 0, sizeof(entry));
	memset(&identity, 0, sizeof(identity));
	errno = 0;
	read_result = read(fd, entry, sizeof(entry));
	read_error = errno;
	errno = 0;
	write_result = write(fd, entry, sizeof(entry));
	write_error = errno;
	errno = 0;
	status = ioctl(fd, DTT_GET_VM_IDENTITY, &identity);
	ioctl_error = errno;
	errno = 0;
	commit_result = ioctl(fd, DTT_COMMIT_VM_REKEY, &identity);
	commit_error = errno;
	if (read_result != -1 || read_error != EBUSY ||
	    write_result != -1 || write_error != EBUSY ||
	    status != -1 || ioctl_error != EBUSY ||
	    commit_result != -1 || commit_error != EBUSY) {
		fprintf(stderr, "transferred fd: read=%zd/%d write=%zd/%d "
		    "identity=%d/%d commit=%d/%d (expected EBUSY)\n",
		    read_result, read_error, write_result, write_error, status,
		    ioctl_error, commit_result, commit_error);
		close(fd);
		return (1);
	}
	close(fd);
	fd = open("/dev/dttransport", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("reopen after transferred fd close");
		return (1);
	}
	close(fd);
	puts("HYPERTRACE_DTT_TRANSFER_PASS");
	return (0);
}
