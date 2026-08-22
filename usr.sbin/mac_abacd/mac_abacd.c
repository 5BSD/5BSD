/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abacd - ABAC Policy Daemon
 *
 * Loads security policy from configuration files.
 * Uses mac_syscall() to communicate with the kernel module.
 * Supports UCL, JSON, and simple line-based policy formats.
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "mac_abacd.h"

/* Global state */
static struct mac_abacd_config config;
static volatile sig_atomic_t reload_pending = 0;
static volatile sig_atomic_t shutdown_pending = 0;
static volatile sig_atomic_t status_pending = 0;
static struct pidfh *pfh = NULL;

/* Forward declarations */
static void usage(void);
static void signal_handler(int sig);
static int setup_signals(void);
static int load_policy(const char *path);
static void main_loop(void);
static void cleanup(void);
static void daemonize(void);

/*
 * Wrapper for mac_syscall with error checking
 */
static int
abac_syscall(int cmd, void *arg)
{
	int error;

	error = mac_syscall(ABAC_POLICY_NAME, cmd, arg);
	if (error < 0 && errno == ENOSYS) {
		mac_abacd_log(LOG_ERR, "ABAC module not loaded");
		return (-1);
	}
	return (error);
}

/*
 * Logging wrapper - logs to syslog when daemonized, stderr otherwise
 */
void
mac_abacd_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (config.daemonize) {
		vsyslog(priority, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: mac_abacd [-dfv] [-c config] [-p pidfile]\n"
	    "       mac_abacd -t [-v] [-c config]\n"
	    "\n"
	    "Options:\n"
	    "  -c config   Policy configuration file (default: %s)\n"
	    "  -d          Debug mode (don't daemonize, verbose logging)\n"
	    "  -f          Run in foreground (don't daemonize)\n"
	    "  -p pidfile  PID file path (default: %s)\n"
	    "  -t          Test configuration and exit\n"
	    "  -v          Verbose output\n"
	    "\n"
	    "Signals:\n"
	    "  SIGHUP      Reload policy configuration\n"
	    "  SIGUSR1     Log current status and statistics\n"
	    "\n"
	    "Configuration directives:\n"
	    "  mode = \"enforcing\";      # disabled, permissive, or enforcing\n"
	    "  default_policy = \"deny\"; # allow or deny (when no rule matches)\n"
	    "  rules = [ ... ];         # rule definitions\n",
	    MAC_ABACD_DEFAULT_CONFIG,
	    MAC_ABACD_DEFAULT_PIDFILE);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		reload_pending = 1;
		break;
	case SIGINT:
	case SIGTERM:
		shutdown_pending = 1;
		break;
	case SIGUSR1:
		status_pending = 1;
		break;
	}
}

static int
setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		mac_abacd_log(LOG_ERR, "sigaction(SIGHUP): %s", strerror(errno));
		return (-1);
	}
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		mac_abacd_log(LOG_ERR, "sigaction(SIGINT): %s", strerror(errno));
		return (-1);
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		mac_abacd_log(LOG_ERR, "sigaction(SIGTERM): %s", strerror(errno));
		return (-1);
	}

	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		mac_abacd_log(LOG_ERR, "sigaction(SIGUSR1): %s", strerror(errno));
		return (-1);
	}

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		mac_abacd_log(LOG_ERR, "sigaction(SIGPIPE): %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Set enforcement mode
 */
static int
mac_abacd_set_mode(int mode)
{
	/* In test mode, just validate */
	if (config.test_mode) {
		if (config.verbose)
			mac_abacd_log(LOG_DEBUG, "would set mode to %d", mode);
		return (0);
	}

	if (abac_syscall(ABAC_SYS_SETMODE, &mode) < 0) {
		mac_abacd_log(LOG_ERR, "SETMODE: %s", strerror(errno));
		return (-1);
	}

	if (config.verbose)
		mac_abacd_log(LOG_DEBUG, "set mode to %d", mode);

	return (0);
}

/*
 * Set default policy (allow=0, deny=1)
 */
static int
mac_abacd_set_default_policy(int policy)
{
	/* In test mode, just validate */
	if (config.test_mode) {
		if (config.verbose)
			mac_abacd_log(LOG_DEBUG, "would set default_policy to %d", policy);
		return (0);
	}

	if (abac_syscall(ABAC_SYS_SETDEFPOL, &policy) < 0) {
		mac_abacd_log(LOG_ERR, "SETDEFPOL: %s", strerror(errno));
		return (-1);
	}

	if (config.verbose)
		mac_abacd_log(LOG_DEBUG, "set default_policy to %d", policy);

	return (0);
}

/*
 * Log current status and statistics
 */
static void
log_status(void)
{
	struct abac_stats stats;
	struct abac_rule_list_arg list_arg;
	int mode, defpol;
	const char *modestr, *defpolstr;

	/* Get mode */
	if (abac_syscall(ABAC_SYS_GETMODE, &mode) < 0) {
		mac_abacd_log(LOG_WARNING, "status: failed to get mode");
		return;
	}

	switch (mode) {
	case ABAC_MODE_DISABLED:
		modestr = "disabled";
		break;
	case ABAC_MODE_PERMISSIVE:
		modestr = "permissive";
		break;
	case ABAC_MODE_ENFORCING:
		modestr = "enforcing";
		break;
	default:
		modestr = "unknown";
		break;
	}

	/* Get default policy */
	if (abac_syscall(ABAC_SYS_GETDEFPOL, &defpol) < 0) {
		mac_abacd_log(LOG_WARNING, "status: failed to get default policy");
		return;
	}
	defpolstr = (defpol == 0) ? "allow" : "deny";

	/* Get stats */
	if (abac_syscall(ABAC_SYS_GETSTATS, &stats) < 0) {
		mac_abacd_log(LOG_WARNING, "status: failed to get stats");
		return;
	}

	/* Get rule count */
	memset(&list_arg, 0, sizeof(list_arg));
	if (abac_syscall(ABAC_SYS_RULE_LIST, &list_arg) < 0) {
		mac_abacd_log(LOG_WARNING, "status: failed to get rule count");
		return;
	}

	mac_abacd_log(LOG_INFO, "status: mode=%s default=%s rules=%u",
	    modestr, defpolstr, list_arg.vrl_total);
	mac_abacd_log(LOG_INFO, "stats: checks=%ju allowed=%ju denied=%ju",
	    (uintmax_t)stats.vs_checks,
	    (uintmax_t)stats.vs_allowed,
	    (uintmax_t)stats.vs_denied);
}

struct policy_buffer {
	char		*data;
	size_t		 used;
	size_t		 capacity;
	uint32_t	 count;
};

/* Append one validated parser rule in the kernel's packed load format. */
static int
pack_rule(struct abac_rule_io *rule_io, void *cookie)
{
	struct policy_buffer *policy;
	struct abac_rule_arg arg;
	char *newdata, *data;
	size_t subject_len, object_len, total_len;
	size_t capacity;

	policy = cookie;

	/* Calculate lengths (include null terminators) */
	subject_len = strlen(rule_io->vr_subject.vp_pattern) + 1;
	object_len = strlen(rule_io->vr_object.vp_pattern) + 1;
	total_len = sizeof(struct abac_rule_arg) + subject_len + object_len;

	if (total_len > ABAC_MAX_RULE_LOAD_SIZE - policy->used ||
	    policy->count == UINT32_MAX) {
		errno = E2BIG;
		return (-1);
	}
	if (policy->used + total_len > policy->capacity) {
		capacity = policy->capacity == 0 ? 8192 : policy->capacity;
		while (capacity < policy->used + total_len) {
			if (capacity > ABAC_MAX_RULE_LOAD_SIZE / 2) {
				capacity = ABAC_MAX_RULE_LOAD_SIZE;
				break;
			}
			capacity *= 2;
		}
		newdata = realloc(policy->data, capacity);
		if (newdata == NULL)
			return (-1);
		policy->data = newdata;
		policy->capacity = capacity;
	}

	memset(&arg, 0, sizeof(arg));

	arg.vr_action = rule_io->vr_action;
	arg.vr_set = rule_io->vr_set;
	arg.vr_operations = rule_io->vr_operations;
	arg.vr_subject_flags = rule_io->vr_subject.vp_flags;
	arg.vr_object_flags = rule_io->vr_object.vp_flags;
	/* Subject context constraints */
	arg.vr_subj_context.vc_flags = rule_io->vr_subj_context.vc_flags;
	arg.vr_subj_context.vc_cap_sandboxed =
	    rule_io->vr_subj_context.vc_cap_sandboxed;
	arg.vr_subj_context.vc_has_tty =
	    rule_io->vr_subj_context.vc_has_tty;
	arg.vr_subj_context.vc_jail_check =
	    rule_io->vr_subj_context.vc_jail_check;
	arg.vr_subj_context.vc_uid = rule_io->vr_subj_context.vc_uid;
	arg.vr_subj_context.vc_gid = rule_io->vr_subj_context.vc_gid;
	/* Object context constraints */
	arg.vr_obj_context.vc_flags = rule_io->vr_obj_context.vc_flags;
	arg.vr_obj_context.vc_cap_sandboxed =
	    rule_io->vr_obj_context.vc_cap_sandboxed;
	arg.vr_obj_context.vc_has_tty = rule_io->vr_obj_context.vc_has_tty;
	arg.vr_obj_context.vc_jail_check =
	    rule_io->vr_obj_context.vc_jail_check;
	arg.vr_obj_context.vc_uid = rule_io->vr_obj_context.vc_uid;
	arg.vr_obj_context.vc_gid = rule_io->vr_obj_context.vc_gid;
	arg.vr_subject_len = subject_len;
	arg.vr_object_len = object_len;

	/* Copy strings after the header */
	memcpy(policy->data + policy->used, &arg, sizeof(arg));
	data = policy->data + policy->used + sizeof(arg);
	memcpy(data, rule_io->vr_subject.vp_pattern, subject_len);
	data += subject_len;
	memcpy(data, rule_io->vr_object.vp_pattern, object_len);

	policy->used += total_len;
	policy->count++;
	return (0);
}

/*
 * Load policy from a configuration file
 */
static int
load_policy(const char *path)
{
	struct mac_abac_policy_settings settings;
	struct abac_rule_load_arg load;
	struct policy_buffer policy;
	int error = -1;

	mac_abacd_log(LOG_INFO, "loading policy from %s", path);
	memset(&policy, 0, sizeof(policy));

	if (mac_abacd_compile_ucl(path, config.verbose, pack_rule, &policy,
	    &settings) != 0) {
		mac_abacd_log(LOG_ERR, "failed to parse policy: %s", path);
		goto out;
	}

	if (config.test_mode) {
		mac_abacd_log(LOG_INFO, "validated %u rules", policy.count);
		error = 0;
		goto out;
	}

	memset(&load, 0, sizeof(load));
	load.vrl_count = policy.count;
	load.vrl_buflen = policy.used;
	load.vrl_buf = policy.data;
	if (abac_syscall(ABAC_SYS_RULE_LOAD, &load) < 0) {
		mac_abacd_log(LOG_ERR, "RULE_LOAD: %s", strerror(errno));
		goto out;
	}
	if (settings.has_default_policy &&
	    mac_abacd_set_default_policy(settings.default_policy) != 0)
		goto out;
	/* Apply mode last so a newly enforcing policy is complete first. */
	if (settings.has_mode && mac_abacd_set_mode(settings.mode) != 0)
		goto out;

	mac_abacd_log(LOG_INFO, "policy loaded successfully (%u rules)",
	    policy.count);
	error = 0;
out:
	free(policy.data);
	return (error);
}

static void
main_loop(void)
{
	mac_abacd_log(LOG_INFO, "daemon started");

	/* Log initial status after startup */
	log_status();

	while (!shutdown_pending) {
		/* Check for pending reload */
		if (reload_pending) {
			reload_pending = 0;
			mac_abacd_log(LOG_INFO, "reloading policy");
			load_policy(config.config_file);
			log_status();
		}

		/* Check for pending status request (SIGUSR1) */
		if (status_pending) {
			status_pending = 0;
			log_status();
		}

		/* Sleep - audit events are handled by FreeBSD's audit subsystem */
		sleep(1);
	}

	mac_abacd_log(LOG_INFO, "shutting down");
}

static void
cleanup(void)
{
	if (pfh != NULL) {
		pidfile_remove(pfh);
		pfh = NULL;
	}
}

static void
daemonize(void)
{
	pid_t otherpid;

	/* Check/create pidfile */
	pfh = pidfile_open(config.pidfile, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			errx(1, "daemon already running, pid: %jd",
			    (intmax_t)otherpid);
		}
		err(1, "pidfile_open");
	}

	/* Daemonize */
	if (daemon(0, 0) < 0) {
		pidfile_remove(pfh);
		err(1, "daemon");
	}

	/* Write PID */
	pidfile_write(pfh);

	/* Open syslog */
	openlog("mac_abacd", LOG_PID | LOG_NDELAY, LOG_SECURITY);
}

int
main(int argc, char *argv[])
{
	int ch;

	/* Initialize config with defaults */
	memset(&config, 0, sizeof(config));
	config.config_file = MAC_ABACD_DEFAULT_CONFIG;
	config.pidfile = MAC_ABACD_DEFAULT_PIDFILE;
	config.daemonize = true;
	config.verbose = false;
	config.test_mode = false;

	while ((ch = getopt(argc, argv, "c:dfp:tv")) != -1) {
		switch (ch) {
		case 'c':
			config.config_file = optarg;
			break;
		case 'd':
			config.daemonize = false;
			config.verbose = true;
			break;
		case 'f':
			config.daemonize = false;
			break;
		case 'p':
			config.pidfile = optarg;
			break;
		case 't':
			config.test_mode = true;
			config.daemonize = false;
			break;
		case 'v':
			config.verbose = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	/* Validation is deliberately available to unprivileged policy authors. */
	if (!config.test_mode && geteuid() != 0)
		errx(1, "must be run as root");

	/* Setup signal handlers */
	if (setup_signals() < 0)
		exit(1);

	/* Verify module is loaded (not needed for test mode) */
	if (!config.test_mode) {
		int mode;
		if (abac_syscall(ABAC_SYS_GETMODE, &mode) < 0) {
			errx(1, "cannot communicate with ABAC module");
		}
	}

	/* Load policy */
	if (load_policy(config.config_file) < 0) {
		cleanup();
		exit(1);
	}

	/* Test mode - just validate and exit */
	if (config.test_mode) {
		printf("configuration OK\n");
		exit(0);
	}

	/* Daemonize if requested */
	if (config.daemonize)
		daemonize();

	/* Main event loop */
	main_loop();

	/* Cleanup */
	cleanup();

	return (0);
}
