/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * 5BSD glue for OpenBSD pflogd(8): the OpenBSD library functions it uses
 * that 5BSD lacks, and opening pflog(4) through the public libpcap API.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <net/bpf.h>

#include <errno.h>
#include <paths.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pflogd.h"

pcap_t	*pflog_read_live(const char *, int, int, int, char *);

int
getexecpath(char *buf, size_t len)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };

	if (sysctl(mib, 4, buf, &len, NULL, 0) == -1)
		return (-1);
	return (0);
}

/*
 * OpenBSD opens bpf(4) itself and fills in libpcap's private pcap_t;
 * 5BSD's libpcap only supports that through pcap_activate(3).
 */
pcap_t *
pflog_read_live(const char *source, int slen, int promisc, int to_ms,
    char *ebuf)
{
	pcap_t	*p;

	if (source == NULL || slen <= 0)
		return (NULL);

	p = pcap_create(source, ebuf);
	if (p == NULL)
		return (NULL);
	if (pcap_set_snaplen(p, slen) != 0 ||
	    pcap_set_promisc(p, promisc) != 0 ||
	    pcap_set_timeout(p, to_ms) != 0 ||
	    pcap_activate(p) < 0 ||
	    pcap_set_datalink(p, DLT_PFLOG) != 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(p));
		pcap_close(p);
		return (NULL);
	}
	return (p);
}

static char	*pidfile_path;
static pid_t	 pidfile_pid;

static void
pidfile_cleanup(void)
{
	if (pidfile_path != NULL && pidfile_pid == getpid())
		(void)unlink(pidfile_path);
}

int
pidfile(const char *basename)
{
	FILE	*f;
	int	 serrno;

	if (basename == NULL)
		basename = getprogname();

	free(pidfile_path);
	pidfile_path = NULL;
	/* _PATH_VARRUN includes the trailing '/' */
	if (asprintf(&pidfile_path, "%s%s.pid", _PATH_VARRUN, basename) == -1) {
		pidfile_path = NULL;
		return (-1);
	}

	if ((f = fopen(pidfile_path, "w")) == NULL)
		goto fail;
	if (fprintf(f, "%ld\n", (long)getpid()) <= 0) {
		serrno = errno;
		(void)fclose(f);
		errno = serrno;
		goto unlink;
	}
	if (fclose(f) != 0)
		goto unlink;

	if (pidfile_pid == 0 && atexit(pidfile_cleanup) != 0)
		goto unlink;
	pidfile_pid = getpid();
	return (0);

unlink:
	serrno = errno;
	(void)unlink(pidfile_path);
	errno = serrno;
fail:
	serrno = errno;
	free(pidfile_path);
	pidfile_path = NULL;
	errno = serrno;
	return (-1);
}
