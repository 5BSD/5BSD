/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include "nss_protocol.h"

/* One request per process. The launcher must strip authority before exec;
 * this executable does not provide its own privileged launch boundary. */
int
main(int argc, char **argv __unused)
{
	struct sb_nss_request request;
	struct sb_nss_reply reply;
	unsigned char extra;
	char *p;
	size_t remaining;
	ssize_t n;

	if (argc != 1) return (1);
	p = (char *)&request;
	for (remaining = sizeof(request); remaining != 0; remaining -= n, p += n) {
		n = read(STDIN_FILENO, p, remaining);
		if (n == -1 && errno == EINTR) { n = 0; continue; }
		if (n <= 0) return (1);
	}
	do { n = read(STDIN_FILENO, &extra, 1); } while (n == -1 && errno == EINTR);
	if (n != 0) return (1);
	sb_nss_lookup(&request, &reply);
	p = (char *)&reply;
	for (remaining = sizeof(reply); remaining != 0; remaining -= n, p += n) {
		n = write(STDOUT_FILENO, p, remaining);
		if (n == -1 && errno == EINTR) { n = 0; continue; }
		if (n <= 0) return (1);
	}
	return (0);
}
