/* SPDX-License-Identifier: BSD-2-Clause */
/* Ordinary ELF signature verification on the exact descriptor being loaded. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include "security/mac_veriexec/mac_veriexec.h"
#include "rtld.h"
#include "sys/capimage_elf.h"
#include "rtld_libc.h"

static int
rtld_capimage_read(void *context, uint64_t offset, void *data, size_t size)
{
	int fd = *(int *)context;
	unsigned char *cursor = data;

	while (size != 0) {
		ssize_t n = pread(fd, cursor, size, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		cursor += n;
		offset += n;
		size -= n;
	}
	return (0);
}

/* A caller-supplied descriptor does not pass through O_VERIFY. Recognize
 * either locator, rejecting a damaged one rather than treating it as unsigned. */
int
rtld_verify_object_signature(const char *path, int fd, const struct stat *st,
    bool required)
{
	struct capimage_elf_info image;
	int probe = capimage_elf_probe(rtld_capimage_read, &fd, st->st_size, &image);

	if (probe < 0 || (required && probe == 0)) {
		_rtld_error("Invalid library signature container: %s",
		    path != NULL ? path : "<descriptor>");
		return (-1);
	}
	if (probe == 0)
		return (0);
	if (syscall(SYS_mac_syscall, MAC_VERIEXEC_NAME,
	    MAC_VERIEXEC_CHECK_CAPIMAGE_FD_SYSCALL, (void *)(intptr_t)fd) < 0) {
		_rtld_error("Library signature verification failed: %s",
		    path != NULL ? path : "<descriptor>");
		return (-1);
	}
	return (0);
}
