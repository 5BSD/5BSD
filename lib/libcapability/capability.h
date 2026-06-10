/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapability — helpers for writing .cap bundle service daemons.
 */

#ifndef _CAPABILITY_H_
#define	_CAPABILITY_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>

#define	CAP_LABEL_MAX	64

typedef int (*cap_client_handler)(int, const char *, void *);

struct cap_daemon_config {
	const char		*service_name;
	cap_client_handler	 handler;
	void			*handler_arg;
	unsigned		 client_timeout;
};

int	 cap_daemon_run(const struct cap_daemon_config *cfg);
ssize_t	 cap_daemon_recv(int fd, void *buf, size_t bufsz, unsigned timeout);
int	 cap_daemon_send(int fd, const void *buf, size_t len);
bool	 cap_daemon_label_allowed(const char *path, const char *label);

#endif /* !_CAPABILITY_H_ */
