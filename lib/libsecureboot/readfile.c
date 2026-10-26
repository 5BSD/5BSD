/*-
 * Copyright (c) 2017-2018, Juniper Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
#include <libsecureboot.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

unsigned char *
read_fd(int fd, size_t len)
{
	size_t offset, count;
	ssize_t n;
	unsigned char *buf;

	if (len == SIZE_MAX)
		return (NULL);
	buf = malloc(len + 1);
	if (buf == NULL)
		return (NULL);
	for (offset = 0; offset < len; offset += (size_t)n) {
		count = len - offset;
		if (count > SSIZE_MAX)
			count = SSIZE_MAX;
		do {
			n = read(fd, buf + offset, count);
		} while (n < 0 && errno == EINTR);
		if (n <= 0) {
			free(buf);
			return (NULL);
		}
	}
	buf[len] = '\0';
	return (buf);
}

unsigned char *
read_file(const char *path, size_t *len)
{
	struct stat st;
	unsigned char *ucp;
	int fd, flags = O_RDONLY;

	if (len != NULL)
		*len = 0;
#ifndef _STANDALONE
	/* Do not block opening a FIFO before checking its type. */
	flags |= O_NONBLOCK;
#endif
	if ((fd = open(path, flags)) < 0)
		return (NULL);
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size < 0 || (uintmax_t)st.st_size >= SIZE_MAX) {
		close(fd);
		return (NULL);
	}
	ucp = read_fd(fd, (size_t)st.st_size);
	close(fd);
	if (ucp != NULL && len != NULL)
		*len = (size_t)st.st_size;
	return (ucp);
}
