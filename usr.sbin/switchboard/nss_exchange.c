/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "nss_child.h"
#include "nss_exchange.h"

static int
remaining_ms(const struct timespec *deadline)
{
	struct timespec now;
	int64_t ns;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) return (-1);
	ns = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000000000 +
	    deadline->tv_nsec - now.tv_nsec;
	if (ns <= 0) return (0);
	return ((int)((ns + 999999) / 1000000));
}

static int
above_stdio(int *fd)
{
	int replacement;
	if (*fd >= 3) return (0);
	replacement = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
	if (replacement == -1) return (-1);
	close(*fd);
	*fd = replacement;
	return (0);
}

int
sb_nss_exchange(const char *helper, int diagnostic,
    const struct sb_nss_request *request, uid_t owner, int timeout_ms,
    struct sb_nss_reply *out)
{
	struct timespec deadline;
	struct pollfd pollfds[2];
	struct sb_nss_reply reply;
	unsigned char extra;
	int input[2] = {-1, -1}, output[2] = {-1, -1}, diag = -1, pd = -1;
	int error = 0, status = 0, timeout, result;
	ssize_t n;
	size_t used = 0;
	bool eof = false, exited = false;

	if (out == NULL) return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out));
	if (helper == NULL || helper[0] != '/' || timeout_ms <= 0 ||
	    diagnostic < 0) return (errno = EINVAL, -1);
	if (sb_nss_request_valid(request) == -1) return (-1);
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) return (-1);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++; deadline.tv_nsec -= 1000000000L;
	}
	diag = fcntl(diagnostic, F_DUPFD_CLOEXEC, 3);
	if (diag == -1 || pipe2(input, O_CLOEXEC) == -1 ||
	    pipe2(output, O_CLOEXEC) == -1) goto failed;
	for (int i = 0; i < 2; i++)
		if (above_stdio(&input[i]) == -1 || above_stdio(&output[i]) == -1)
			goto failed;
	if (fcntl(output[0], F_SETFL, O_NONBLOCK) == -1) goto failed;
	/* An empty private pipe with a reader held here cannot block or SIGPIPE.
	 * Queue before fork so the parent never writes to an untrusted child. */
	_Static_assert(sizeof(*request) <= PIPE_BUF, "NSS request must be atomic");
	do { n = write(input[1], request, sizeof(*request)); }
	while (n == -1 && errno == EINTR);
	if (n != sizeof(*request)) { if (n >= 0) errno = EIO; goto failed; }
	close(input[1]); input[1] = -1;
	/* Setup can consume the budget too. Never start a child after expiry. */
	timeout = remaining_ms(&deadline);
	if (timeout == -1) goto failed;
	if (timeout == 0) { errno = ETIMEDOUT; goto failed; }
	/* Protect the interval before the child has discarded inherited power. */
	result = pdfork(&pd, PD_CLOEXEC | PD_NOWAITPID | PD_PROTECTED);
	if (result == -1) goto failed;
	if (result == 0) sb_nss_child_exec(helper, input[0], output[1], diag);
	close(input[0]); input[0] = -1;
	close(output[1]); output[1] = -1;
	close(diag); diag = -1;
	while (!eof || !exited) {
		timeout = remaining_ms(&deadline);
		if (timeout == -1) goto failed;
		if (timeout == 0) { errno = ETIMEDOUT; goto failed; }
		pollfds[0] = (struct pollfd){ .fd = eof ? -1 : output[0], .events = POLLIN };
		pollfds[1] = (struct pollfd){ .fd = exited ? -1 : pd, .events = 0 };
		result = poll(pollfds, 2, timeout);
		if (result == -1 && errno == EINTR) continue;
		if (result == -1) goto failed;
		if (result == 0) continue;
		if ((pollfds[0].revents | pollfds[1].revents) & (POLLERR | POLLNVAL)) {
			errno = EIO; goto failed;
		}
		if (pollfds[0].revents & (POLLIN | POLLHUP)) {
			n = read(output[0], used < sizeof(reply) ? (char *)&reply + used :
			    (void *)&extra, used < sizeof(reply) ? sizeof(reply) - used : 1);
			if (n == -1 && errno != EINTR && errno != EAGAIN) goto failed;
			if (n == 0) eof = true;
			if (n > 0) {
				if (used == sizeof(reply)) { errno = EPROTO; goto failed; }
				used += n;
			}
		}
		if (pollfds[1].revents & POLLHUP) {
			result = pdwait(pd, &status, WEXITED | WNOHANG, NULL, NULL);
			if (result == -1 && errno == EINTR) continue;
			if (result == -1) goto failed;
			exited = true;
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
				errno = EIO; goto failed;
			}
		}
	}
	if (sb_nss_reply_valid(request, &reply, used, owner) == -1) goto failed;
	*out = reply;
	goto done;
failed:
	error = errno;
	if (pd != -1 && !exited) {
		/* No unbounded wait after timeout, including uninterruptible I/O.
		 * Last close of the non-daemon procdesc also kills and arranges reaping. */
		(void)pdkill(pd, SIGKILL);
	}
done:
	if (pd != -1) close(pd);
	if (diag != -1) close(diag);
	for (int i = 0; i < 2; i++) {
		if (input[i] != -1) close(input[i]);
		if (output[i] != -1) close(output[i]);
	}
	if (error != 0) { errno = error; return (-1); }
	return (0);
}
