/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapability — helpers for writing .cap bundle service daemons.
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include "capability.h"


static volatile sig_atomic_t quit;
static volatile sig_atomic_t reap_requested;
static int service_fd = -1;

static void
handle_term(int sig __unused)
{

	quit = 1;
	if (service_fd >= 0)
		close(service_fd);
}

static void
handle_chld(int sig __unused)
{

	reap_requested = 1;
}

static void
reap_children(void)
{
	int status;

	reap_requested = 0;
	while (waitpid(-1, &status, WNOHANG) > 0)
		;
}

static int
install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handle_term;
	if (sigaction(SIGTERM, &sa, NULL) == -1 ||
	    sigaction(SIGINT, &sa, NULL) == -1)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handle_chld;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		return (-1);

	return (0);
}

static void
serve_child(const struct cap_daemon_config *cfg, int client_fd,
    const char *label)
{
	int pair_fd, error;

	pair_fd = service_pair_fd();
	if (pair_fd >= 0)
		close(pair_fd);

	if (cfg->client_timeout != 0)
		alarm(cfg->client_timeout);

	error = cfg->handler(client_fd, label, cfg->handler_arg);
	close(client_fd);
	_exit(error == 0 ? 0 : 1);
}

int
cap_daemon_run(const struct cap_daemon_config *cfg)
{
	char label[CAP_LABEL_MAX];
	int client_fd;
	pid_t pid;

	if (cfg == NULL || cfg->service_name == NULL || cfg->handler == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (service_init() == -1)
		return (-1);
	if (service_protect(CP_SF_PTRACE | CP_SF_VISIBLE | CP_SF_WAIT |
	    CP_SF_SCHED | CP_SF_CORE | CP_SF_KTRACE) == -1) {
		if (errno != ENOTSUP)
			syslog(LOG_WARNING, "service protect: %m");
	} else {
		syslog(LOG_INFO, "service protect active");
	}
	if (service_register(cfg->service_name) == -1)
		return (-1);
	if (service_ready() == -1)
		return (-1);
	service_fd = service_pair_fd();
	if (install_signals() == -1)
		return (-1);

	while (!quit) {
		if (reap_requested)
			reap_children();

		client_fd = service_accept(label, sizeof(label));
		if (client_fd == -1) {
			if (!quit)
				syslog(LOG_WARNING, "service accept: %m");
			continue;
		}

		pid = fork();
		if (pid == -1) {
			syslog(LOG_WARNING, "fork client %s: %m", label);
			close(client_fd);
			continue;
		}
		if (pid == 0)
			serve_child(cfg, client_fd, label);
		close(client_fd);
		if (cfg->client_timeout != 0)
			syslog(LOG_INFO,
			    "client connected: %s pid %jd timeout %us",
			    label, (intmax_t)pid, cfg->client_timeout);
		else
			syslog(LOG_INFO,
			    "client connected: %s pid %jd no timeout",
			    label, (intmax_t)pid);
	}

	reap_children();
	return (0);
}

ssize_t
cap_daemon_recv(int fd, void *buf, size_t bufsz, unsigned timeout)
{
	ssize_t n;

	if (timeout != 0)
		alarm(timeout);
	n = service_recv(fd, buf, bufsz, NULL);
	if (timeout != 0)
		alarm(0);	/* cancel pending alarm */
	return (n);
}

int
cap_daemon_send(int fd, const void *buf, size_t len)
{

	if (service_send(fd, buf, len) == -1) {
		syslog(LOG_WARNING, "service send: %m");
		return (-1);
	}
	return (0);
}

static char *
trim(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;
	if (*s == '\0')
		return (s);
	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';
	return (s);
}

bool
cap_daemon_label_allowed(const char *path, const char *label)
{
	char line[256], *p;
	FILE *fp;
	bool allowed;

	if (path == NULL || label == NULL || label[0] == '\0')
		return (false);

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (errno != ENOENT)
			syslog(LOG_WARNING, "%s: %m", path);
		return (false);
	}

	allowed = false;
	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strchr(line, '#');
		if (p != NULL)
			*p = '\0';
		p = trim(line);
		if (*p == '\0')
			continue;
		if (strcmp(p, "*") == 0 || strcmp(p, label) == 0) {
			allowed = true;
			break;
		}
	}
	fclose(fp);
	return (allowed);
}
