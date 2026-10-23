/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD pflogd(8) (contrib/openbsd-pf/sbin/pflogd) on 5BSD: force-included
 * before every source file.  The vendor sources carry the remaining
 * differences as edits marked "5BSD"; see contrib/openbsd-pf/README.5BSD.
 */
#ifndef _PFLOGD_5BSD_H_
#define	_PFLOGD_5BSD_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdint.h>

#define	__dead			__dead2

/*
 * pledge(2)/unveil(2) do not exist on 5BSD; daemons are confined by the
 * capability plane.  pflogd still chroots and drops to _pflogd.
 */
#define	pledge(promises, execpromises)	0
#define	unveil(path, permissions)	0

/* OpenBSD libc getexecpath(3). */
int	getexecpath(char *, size_t);

/*
 * OpenBSD libutil pidfile(3): write /var/run/<basename>.pid (basename
 * defaults to the program name) and remove it when this process exits.
 * pflogd -p, kept from the FreeBSD pflogd for rc.d/pflog and newsyslog.
 */
int	pidfile(const char *);

/*
 * The savefile record header.  OpenBSD's struct pcap_pkthdr has 32-bit
 * time fields and is written to the file as is; 5BSD's carries a struct
 * timeval, so pflogd converts each header to this on-disk layout.
 *
 * The capture length is also clamped to the snaplen in use: OpenBSD lets
 * the root process reprogram a BIOCLOCKed bpf(4) descriptor when an
 * existing log file has a different snaplen, 5BSD's bpf(4) does not, so
 * the kernel may keep capturing at the snaplen pflogd started with.
 */
struct pcap_sf_pkthdr {
	struct {
		uint32_t	tv_sec;
		uint32_t	tv_usec;
	}		ts;
	uint32_t	caplen;
	uint32_t	len;
};

#define	PCAP_SF_PKTHDR(ph, snap) {					\
	.ts = { .tv_sec = (uint32_t)(ph)->ts.tv_sec,			\
	    .tv_usec = (uint32_t)(ph)->ts.tv_usec },			\
	.caplen = (ph)->caplen > (uint32_t)(snap) ?			\
	    (uint32_t)(snap) : (ph)->caplen,				\
	.len = (ph)->len }

#endif /* _PFLOGD_5BSD_H_ */
