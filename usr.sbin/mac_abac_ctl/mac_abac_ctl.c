/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abac_ctl - ABAC Control Utility
 *
 * Command-line tool for managing the ABAC MAC policy module.
 * Uses mac_syscall() to communicate with the kernel module.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/mac.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <security/mac_abac/mac_abac.h>
#include "mac_abac_ctl.h"

/*
 * Wrapper for mac_syscall with error checking
 */
int
abac_syscall(int cmd, void *arg)
{
	int error;

	error = mac_syscall(ABAC_POLICY_NAME, cmd, arg);
	if (error < 0 && errno == ENOSYS)
		errx(EX_UNAVAILABLE, "ABAC module not loaded");
	return (error);
}

/*
 * Get the extattr name from kernel sysctl.
 * Returns static buffer with name, or default "mac_abac" on error.
 */
const char *
get_extattr_name(void)
{
	static char extattr_name[64];
	static int initialized = 0;
	size_t len;

	if (initialized)
		return (extattr_name);

	len = sizeof(extattr_name);
	if (sysctlbyname("security.mac.mac_abac.extattr_name",
	    extattr_name, &len, NULL, 0) < 0) {
		/* Fall back to default if sysctl fails (module not loaded) */
		strlcpy(extattr_name, "mac_abac", sizeof(extattr_name));
	}

	initialized = 1;
	return (extattr_name);
}

/*
 * Convert a user-provided label from comma format to newline format.
 * Input:  "key1=val1,key2=val2"
 * Output: "key1=val1\nkey2=val2\n"
 * Returns newly allocated string (caller must free), or NULL on error.
 */
char *
convert_label_format(const char *input)
{
	size_t len, outlen;
	char *output, *outp;
	const char *p, *end, *comma, *eq;
	const char *keys[ABAC_MAX_PAIRS];
	size_t key_lengths[ABAC_MAX_PAIRS];
	size_t keylen, valuelen, npairs, i;

	if (input == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	len = strlen(input);
	if (len == 0 || len + 2 > ABAC_MAX_LABEL_LEN ||
	    memchr(input, '\n', len) != NULL || memchr(input, '\r', len) != NULL) {
		errno = EINVAL;
		return (NULL);
	}

	/* Validate the complete label before allocating or rewriting it. */
	p = input;
	end = input + len;
	npairs = 0;
	while (p < end) {
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;
		if (comma == p || npairs >= ABAC_MAX_PAIRS) {
			errno = EINVAL;
			return (NULL);
		}
		eq = memchr(p, '=', comma - p);
		if (eq == NULL) {
			errno = EINVAL;
			return (NULL);
		}
		keylen = (size_t)(eq - p);
		valuelen = (size_t)(comma - eq - 1);
		if (keylen == 0 || keylen >= ABAC_MAX_KEY_LEN ||
		    valuelen >= ABAC_MAX_VALUE_LEN) {
			errno = EINVAL;
			return (NULL);
		}
		for (i = 0; i < npairs; i++) {
			if (key_lengths[i] == keylen &&
			    memcmp(keys[i], p, keylen) == 0) {
				errno = EEXIST;
				return (NULL);
			}
		}
		keys[npairs] = p;
		key_lengths[npairs++] = keylen;
		if (comma == end)
			break;
		p = comma + 1;
		if (p == end) {
			errno = EINVAL;
			return (NULL);
		}
	}

	/* Output size: same length, commas become newlines, plus trailing \n + \0 */
	outlen = len + 2;
	output = malloc(outlen);
	if (output == NULL) {
		warn("malloc");
		return (NULL);
	}

	p = input;
	end = input + len;
	outp = output;

	while (p < end) {
		/* Find next comma or end */
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;

		memcpy(outp, p, comma - p);
		outp += comma - p;
		*outp++ = '\n';

		if (comma == end)
			break;
		p = comma + 1;
	}

	*outp = '\0';
	return (output);
}

/*
 * Helper to format an operation bitmask as a string
 */
const char *
ops_to_string(uint32_t ops, char *buf, size_t buflen)
{
	size_t len;

	if (ops == ABAC_OP_ALL)
		return "all";

	buf[0] = '\0';

#define APPEND_OPERATION(name, value) do { \
	if ((ops & (value)) != 0) \
		(void)strlcat(buf, #name ",", buflen); \
} while (0);
	ABAC_OPERATION_LIST(APPEND_OPERATION)
#undef APPEND_OPERATION

	/* Remove trailing comma */
	len = strlen(buf);
	if (len > 0 && buf[len - 1] == ',')
		buf[len - 1] = '\0';

	return buf[0] ? buf : "none";
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: mac_abac_ctl <command> [arguments]\n"
	    "\n"
	    "Commands:\n"
	    "  mode [disabled|permissive|enforcing]\n"
	    "      Get or set enforcement mode\n"
	    "\n"
	    "  default [allow|deny]\n"
	    "      Get or set default policy when no rule matches\n"
	    "\n"
	    "  stats\n"
	    "      Show statistics\n"
	    "\n"
	    "  status\n"
	    "      Show combined status (mode, stats, rules)\n"
	    "\n"
	    "  limits\n"
	    "      Show kernel limits, supported operations, and syntax\n"
	    "\n"
	    "  rule add \"<rule>\"\n"
	    "      Add a rule, prints assigned ID\n"
	    "      Format: action ops subject [ctx:...] -> object [ctx:...]\n"
	    "      Examples:\n"
	    "        mac_abac_ctl rule add \"deny exec * -> type=untrusted\"\n"
	    "        mac_abac_ctl rule add \"deny read * ctx:jail=any -> type=secret\"\n"
	    "        mac_abac_ctl rule add \"deny debug * -> * ctx:sandboxed=true\"\n"
	    "\n"
	    "  rule remove <id>\n"
	    "      Remove a rule by ID\n"
	    "\n"
	    "  rule load <file>\n"
	    "      Atomic load: clear all rules, load from file\n"
	    "      On parse error, existing rules remain unchanged\n"
	    "\n"
	    "  rule append <file>\n"
	    "      Append rules from file (keeps existing rules)\n"
	    "\n"
	    "  rule list\n"
	    "      List all loaded rules with IDs\n"
	    "\n"
	    "  rule clear\n"
	    "      Clear all rules\n"
	    "\n"
	    "  rule validate \"<rule>\"\n"
	    "      Validate a rule without loading it\n"
	    "      Returns OK if valid, ERROR if invalid\n"
	    "\n"
	    "  rule validate -f <file>\n"
	    "      Validate all rules in a file\n"
	    "\n"
	    "  label get <path>\n"
	    "      Get the ABAC of a file\n"
	    "\n"
	    "  label set <path> \"<label>\"\n"
	    "      Atomically set the persistent and cached ABAC label\n"
	    "      Example: mac_abac_ctl label set /bin/foo \"type=trusted,domain=system\"\n"
	    "\n"
	    "  label setatomic <path> \"<label>\"\n"
	    "      Alias for label set\n"
	    "      Example: mac_abac_ctl label setatomic /bin/foo \"type=trusted\"\n"
	    "\n"
	    "  label refresh <path>\n"
	    "      Refresh the in-memory cached label from extattr\n"
	    "\n"
	    "  label remove <path>\n"
	    "      Remove the ABAC from a file\n"
	    "\n"
	    "  label setrecursive <path> \"<label>\" [-v] [-d|-f]\n"
	    "      Recursively set labels on a directory tree\n"
	    "      Options:\n"
	    "        -v  Verbose (print each file)\n"
	    "        -d  Directories only\n"
	    "        -f  Files only\n"
	    "      Example: mac_abac_ctl label setrecursive /var/www \"type=web\" -v\n"
	    "\n"
	    "  test <operation> <subject-label> <object-label>\n"
	    "      Test if an operation would be allowed\n"
	    "      Example: mac_abac_ctl test exec \"type=user\" \"type=untrusted\"\n"
	    "\n"
	    "  set enable <N> | <start>-<end> | all\n"
	    "      Enable rule set(s)\n"
	    "\n"
	    "  set disable <N> | <start>-<end> | all\n"
	    "      Disable rule set(s)\n"
	    "\n"
	    "  set swap <A> <B>\n"
	    "      Swap two sets atomically\n"
	    "\n"
	    "  set move <from> <to>\n"
	    "      Move all rules from one set to another\n"
	    "\n"
	    "  set clear <N>\n"
	    "      Clear all rules in set\n"
	    "\n"
	    "  set list [<start>-<end>]\n"
	    "      Show set status and rule counts\n"
	    "\n"
	    "  lock\n"
	    "      Lock the policy (cannot be modified until reboot)\n"
	    "\n"
	    "  log [level]\n"
	    "      Get or set the audit log level\n"
	    "      Levels: none (0), error (1), admin (2), deny (3), all (4)\n"
	    "      Default: admin (log policy changes, not access checks)\n"
	    "\n"
	    "Note: Audit events are logged via FreeBSD's standard audit subsystem.\n"
	    "Use 'praudit' and 'auditreduce' to view MAC policy decisions.\n"
	);
	exit(EX_USAGE);
}

/*
 * mode [disabled|permissive|enforcing]
 */
int
cmd_mode(int argc, char *argv[])
{
	int mode;
	const char *modestr;

	if (argc == 0) {
		/* Get mode */
		if (abac_syscall(ABAC_SYS_GETMODE, &mode) < 0)
			err(EX_OSERR, "GETMODE");

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
		printf("%s\n", modestr);
		return (0);
	}

	/* Set mode */
	if (strcmp(argv[0], "disabled") == 0)
		mode = ABAC_MODE_DISABLED;
	else if (strcmp(argv[0], "permissive") == 0)
		mode = ABAC_MODE_PERMISSIVE;
	else if (strcmp(argv[0], "enforcing") == 0)
		mode = ABAC_MODE_ENFORCING;
	else
		errx(EX_USAGE, "invalid mode: %s", argv[0]);

	if (abac_syscall(ABAC_SYS_SETMODE, &mode) < 0)
		err(EX_OSERR, "SETMODE");

	printf("mode set to %s\n", argv[0]);
	return (0);
}

/*
 * default [allow|deny]
 */
int
cmd_default(int argc, char *argv[])
{
	int policy;
	const char *policystr;

	if (argc == 0) {
		/* Get default policy */
		if (abac_syscall(ABAC_SYS_GETDEFPOL, &policy) < 0)
			err(EX_OSERR, "GETDEFPOL");

		policystr = (policy == 0) ? "allow" : "deny";
		printf("%s\n", policystr);
		return (0);
	}

	/* Set default policy */
	if (strcmp(argv[0], "allow") == 0)
		policy = 0;
	else if (strcmp(argv[0], "deny") == 0)
		policy = 1;
	else
		errx(EX_USAGE, "invalid default policy: %s (use 'allow' or 'deny')",
		    argv[0]);

	if (abac_syscall(ABAC_SYS_SETDEFPOL, &policy) < 0)
		err(EX_OSERR, "SETDEFPOL");

	printf("default policy set to %s\n", argv[0]);
	return (0);
}

/*
 * stats
 */
int
cmd_stats(int argc __unused, char *argv[] __unused)
{
	struct abac_stats stats;

	if (abac_syscall(ABAC_SYS_GETSTATS, &stats) < 0)
		err(EX_OSERR, "GETSTATS");

	printf("ABAC Statistics:\n");
	printf("  Access checks:    %ju\n", (uintmax_t)stats.vs_checks);
	printf("  Allowed:          %ju\n", (uintmax_t)stats.vs_allowed);
	printf("  Denied:           %ju\n", (uintmax_t)stats.vs_denied);
	printf("  Labels read:      %ju\n", (uintmax_t)stats.vs_labels_read);
	printf("  Default labels:   %ju\n", (uintmax_t)stats.vs_labels_default);
	printf("  Active rules:     %u\n", stats.vs_rule_count);

	return (0);
}

/*
 * status - combined view of mode, stats, rules
 */
int
cmd_status(int argc __unused, char *argv[] __unused)
{
	struct abac_stats stats;
	struct abac_rule_list_arg list_arg;
	int mode, defpol, locked, loglevel;
	const char *modestr, *defpolstr, *logstr;

	/* Get mode */
	if (abac_syscall(ABAC_SYS_GETMODE, &mode) < 0)
		err(EX_OSERR, "GETMODE");

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
	if (abac_syscall(ABAC_SYS_GETDEFPOL, &defpol) < 0)
		err(EX_OSERR, "GETDEFPOL");

	defpolstr = (defpol == 0) ? "allow" : "deny";

	/* Get locked state */
	if (abac_syscall(ABAC_SYS_GETLOCKED, &locked) < 0)
		err(EX_OSERR, "GETLOCKED");

	/* Get log level */
	if (abac_syscall(ABAC_SYS_GETLOGLEVEL, &loglevel) < 0)
		err(EX_OSERR, "GETLOGLEVEL");

	switch (loglevel) {
	case ABAC_LOG_NONE:
		logstr = "none";
		break;
	case ABAC_LOG_ERROR:
		logstr = "error";
		break;
	case ABAC_LOG_ADMIN:
		logstr = "admin";
		break;
	case ABAC_LOG_DENY:
		logstr = "deny";
		break;
	case ABAC_LOG_ALL:
		logstr = "all";
		break;
	default:
		logstr = "unknown";
		break;
	}

	/* Get stats */
	if (abac_syscall(ABAC_SYS_GETSTATS, &stats) < 0)
		err(EX_OSERR, "GETSTATS");

	/* Get rule count */
	memset(&list_arg, 0, sizeof(list_arg));
	if (abac_syscall(ABAC_SYS_RULE_LIST, &list_arg) < 0)
		err(EX_OSERR, "RULE_LIST");

	/* Print combined status */
	printf("ABAC Status:\n");
	printf("  Mode:             %s\n", modestr);
	printf("  Default policy:   %s\n", defpolstr);
	printf("  Locked:           %s\n", locked ? "yes (until reboot)" : "no");
	printf("  Log level:        %s\n", logstr);
	printf("  Active rules:     %u\n", list_arg.vrl_total);
	printf("\n");
	printf("Statistics:\n");
	printf("  Access checks:    %ju\n", (uintmax_t)stats.vs_checks);
	printf("  Allowed:          %ju\n", (uintmax_t)stats.vs_allowed);
	printf("  Denied:           %ju\n", (uintmax_t)stats.vs_denied);

	if (stats.vs_checks > 0) {
		double deny_pct = (100.0 * stats.vs_denied) / stats.vs_checks;
		printf("  Denial rate:      %.1f%%\n", deny_pct);
	}

	printf("\n");
	printf("Note: Audit events are logged to kernel message buffer (dmesg)\n");
	printf("at the configured log level. Use 'sysctl security.mac.mac_abac'\n");
	printf("to view current settings.\n");

	return (0);
}

/*
 * lock - lock the policy until reboot
 */
int
cmd_lock(int argc __unused, char *argv[] __unused)
{
	int locked;

	/* Check if already locked */
	if (abac_syscall(ABAC_SYS_GETLOCKED, &locked) < 0)
		err(EX_OSERR, "GETLOCKED");

	if (locked) {
		printf("Policy is already locked\n");
		return (0);
	}

	/* Lock the policy */
	if (abac_syscall(ABAC_SYS_LOCK, NULL) < 0)
		err(EX_OSERR, "LOCK");

	printf("Policy locked until reboot\n");
	printf("WARNING: No further rule or mode changes will be permitted\n");
	return (0);
}

/*
 * log [level] - get or set audit log level
 */
int
cmd_log(int argc, char *argv[])
{
	int level;
	const char *levelstr;

	if (argc == 0) {
		/* Get log level */
		if (abac_syscall(ABAC_SYS_GETLOGLEVEL, &level) < 0)
			err(EX_OSERR, "GETLOGLEVEL");

		switch (level) {
		case ABAC_LOG_NONE:
			levelstr = "none";
			break;
		case ABAC_LOG_ERROR:
			levelstr = "error";
			break;
		case ABAC_LOG_ADMIN:
			levelstr = "admin";
			break;
		case ABAC_LOG_DENY:
			levelstr = "deny";
			break;
		case ABAC_LOG_ALL:
			levelstr = "all";
			break;
		default:
			levelstr = "unknown";
			break;
		}
		printf("%s (%d)\n", levelstr, level);
		return (0);
	}

	/* Set log level */
	if (strcmp(argv[0], "none") == 0 || strcmp(argv[0], "0") == 0)
		level = ABAC_LOG_NONE;
	else if (strcmp(argv[0], "error") == 0 || strcmp(argv[0], "1") == 0)
		level = ABAC_LOG_ERROR;
	else if (strcmp(argv[0], "admin") == 0 || strcmp(argv[0], "2") == 0)
		level = ABAC_LOG_ADMIN;
	else if (strcmp(argv[0], "deny") == 0 || strcmp(argv[0], "3") == 0)
		level = ABAC_LOG_DENY;
	else if (strcmp(argv[0], "all") == 0 || strcmp(argv[0], "4") == 0)
		level = ABAC_LOG_ALL;
	else
		errx(EX_USAGE, "invalid log level: %s (use none/error/admin/deny/all or 0-4)",
		    argv[0]);

	if (abac_syscall(ABAC_SYS_SETLOGLEVEL, &level) < 0)
		err(EX_OSERR, "SETLOGLEVEL");

	printf("log level set to %s (%d)\n", argv[0], level);
	return (0);
}

/*
 * limits - show kernel limits and supported operations
 */
int
cmd_limits(int argc __unused, char *argv[] __unused)
{

	printf("ABAC Limits:\n");
	printf("\n");
	printf("  Label Limits (per label):\n");
	printf("    Max label size:       %d bytes\n", ABAC_MAX_LABEL_LEN);
	printf("    Max key length:       %d bytes\n", ABAC_MAX_KEY_LEN);
	printf("    Max value length:     %d bytes\n", ABAC_MAX_VALUE_LEN);
	printf("    Max key=value pairs:  %d\n", ABAC_MAX_PAIRS);
	printf("\n");
	printf("  System Limits:\n");
	printf("    Max rules:            %d\n", ABAC_MAX_RULES);
	printf("\n");
	printf("  Supported Operations:\n");
	printf("    %-12s  0x%08x  %s\n", "exec",       ABAC_OP_EXEC,       "execute file");
	printf("    %-12s  0x%08x  %s\n", "read",       ABAC_OP_READ,       "read file contents");
	printf("    %-12s  0x%08x  %s\n", "write",      ABAC_OP_WRITE,      "write file contents");
	printf("    %-12s  0x%08x  %s\n", "open",       ABAC_OP_OPEN,       "open file");
	printf("    %-12s  0x%08x  %s\n", "mmap",       ABAC_OP_MMAP,       "memory map file");
	printf("    %-12s  0x%08x  %s\n", "access",     ABAC_OP_ACCESS,     "access() check");
	printf("    %-12s  0x%08x  %s\n", "setextattr", ABAC_OP_SETEXTATTR, "set extended attr");
	printf("    %-12s  0x%08x  %s\n", "getextattr", ABAC_OP_GETEXTATTR, "get extended attr");
	printf("    %-12s  0x%08x  %s\n", "debug",      ABAC_OP_DEBUG,      "ptrace/procfs debug");
	printf("    %-12s  0x%08x  %s\n", "signal",     ABAC_OP_SIGNAL,     "send signal");
	printf("    %-12s  0x%08x  %s\n", "sched",      ABAC_OP_SCHED,      "scheduler control");
	printf("    %-12s  0x%08x  %s\n", "link",       ABAC_OP_LINK,       "create hard link");
	printf("    %-12s  0x%08x  %s\n", "rename",     ABAC_OP_RENAME,     "rename file");
	printf("    %-12s  0x%08x  %s\n", "unlink",     ABAC_OP_UNLINK,     "unlink/delete file");
	printf("    %-12s  0x%08x  %s\n", "chdir",      ABAC_OP_CHDIR,      "change directory");
	printf("    %-12s  0x%08x  %s\n", "connect",    ABAC_OP_CONNECT,    "socket connect");
	printf("    %-12s  0x%08x  %s\n", "bind",       ABAC_OP_BIND,       "socket bind");
	printf("    %-12s  0x%08x  %s\n", "listen",     ABAC_OP_LISTEN,     "socket listen");
	printf("    %-12s  0x%08x  %s\n", "accept",     ABAC_OP_ACCEPT,     "socket accept");
	printf("    %-12s  0x%08x  %s\n", "send",       ABAC_OP_SEND,       "socket send");
	printf("    %-12s  0x%08x  %s\n", "receive",    ABAC_OP_RECEIVE,    "socket receive");
	printf("    %-12s  0x%08x  %s\n", "deliver",    ABAC_OP_DELIVER,    "packet delivery to socket");
	printf("    %-12s  0x%08x  %s\n", "stat",       ABAC_OP_STAT,       "get file status");
	printf("    %-12s  0x%08x  %s\n", "wait",       ABAC_OP_WAIT,       "wait on process");
	printf("    %-12s  0x%08x  %s\n", "mprotect",   ABAC_OP_MPROTECT,   "memory protection");
	printf("    %-12s  0x%08x  %s\n", "audit",      ABAC_OP_AUDIT,      "audit operations");
	printf("    %-12s  0x%08x  %s\n", "all",        ABAC_OP_ALL,        "all operations");
	printf("\n");
	printf("  Rule Syntax:\n");
	printf("    action operation subject -> object\n");
	printf("\n");
	printf("  Actions:\n");
	printf("    allow       - permit the operation\n");
	printf("    deny        - block the operation (returns EACCES)\n");
	printf("\n");
	printf("  Pattern Format:\n");
	printf("    *                   - match anything (wildcard)\n");
	printf("    type=value          - match type field\n");
	printf("    type=a,domain=b     - match multiple fields\n");
	printf("    !pattern            - negate the match\n");

	return (0);
}

int
main(int argc, char *argv[])
{
	if (argc < 2)
		usage();

	argc--;
	argv++;

	if (strcmp(argv[0], "mode") == 0)
		return (cmd_mode(argc - 1, argv + 1));
	else if (strcmp(argv[0], "default") == 0)
		return (cmd_default(argc - 1, argv + 1));
	else if (strcmp(argv[0], "stats") == 0)
		return (cmd_stats(argc - 1, argv + 1));
	else if (strcmp(argv[0], "status") == 0)
		return (cmd_status(argc - 1, argv + 1));
	else if (strcmp(argv[0], "limits") == 0)
		return (cmd_limits(argc - 1, argv + 1));
	else if (strcmp(argv[0], "rule") == 0)
		return (cmd_rule(argc - 1, argv + 1));
	else if (strcmp(argv[0], "set") == 0)
		return (cmd_set(argc - 1, argv + 1));
	else if (strcmp(argv[0], "label") == 0)
		return (cmd_label(argc - 1, argv + 1));
	else if (strcmp(argv[0], "test") == 0)
		return (cmd_test(argc - 1, argv + 1));
	else if (strcmp(argv[0], "lock") == 0)
		return (cmd_lock(argc - 1, argv + 1));
	else if (strcmp(argv[0], "log") == 0)
		return (cmd_log(argc - 1, argv + 1));
	else if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "-h") == 0)
		usage();
	else
		errx(EX_USAGE, "unknown command: %s", argv[0]);

	return (0);
}
