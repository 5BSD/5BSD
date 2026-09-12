/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <kory@5bsd.org>
 */

#ifndef _LINUX_SIGNALFD_H_
#define	_LINUX_SIGNALFD_H_

#define	LINUX_SFD_CLOEXEC	LINUX_O_CLOEXEC
#define	LINUX_SFD_NONBLOCK	LINUX_O_NONBLOCK

/* struct signalfd_siginfo: 128 bytes, padded to allow future growth. */
struct l_signalfd_siginfo {
	uint32_t	ssi_signo;
	int32_t		ssi_errno;
	int32_t		ssi_code;
	uint32_t	ssi_pid;
	uint32_t	ssi_uid;
	int32_t		ssi_fd;
	uint32_t	ssi_tid;
	uint32_t	ssi_band;
	uint32_t	ssi_overrun;
	uint32_t	ssi_trapno;
	int32_t		ssi_status;
	int32_t		ssi_int;
	uint64_t	ssi_ptr;
	uint64_t	ssi_utime;
	uint64_t	ssi_stime;
	uint64_t	ssi_addr;
	uint16_t	ssi_addr_lsb;
	uint16_t	__pad2;
	int32_t		ssi_syscall;
	uint64_t	ssi_call_addr;
	uint32_t	ssi_arch;
	uint8_t		__pad[28];
};
_Static_assert(sizeof(struct l_signalfd_siginfo) == 128,
    "struct signalfd_siginfo must be 128 bytes");

#endif /* _LINUX_SIGNALFD_H_ */
