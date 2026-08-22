/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abac_ctl - Label and test command handlers
 *
 * Handles: label get|set|remove, test
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/mac.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>

#include <security/mac_abac/mac_abac.h>
#include "mac_abacd.h"
#include "mac_abac_ctl.h"

/*
 * Set label atomically on a single file.
 * Returns 0 on success, -1 on error (with errno set).
 */
static int
setlabel_atomic(const char *path, const char *label_newline_fmt)
{
	struct abac_setlabel_arg *setlabel_arg;
	size_t label_len, total_len;
	int fd, ret;

	label_len = strlen(label_newline_fmt) + 1;
	total_len = sizeof(struct abac_setlabel_arg) + label_len;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);

	setlabel_arg = calloc(1, total_len);
	if (setlabel_arg == NULL) {
		close(fd);
		return (-1);
	}

	setlabel_arg->vsl_fd = fd;
	setlabel_arg->vsl_label_len = label_len;
	memcpy((char *)setlabel_arg + sizeof(struct abac_setlabel_arg),
	    label_newline_fmt, label_len);

	ret = mac_syscall(ABAC_POLICY_NAME, ABAC_SYS_SETLABEL, setlabel_arg);
	free(setlabel_arg);
	close(fd);

	return (ret);
}

/*
 * Parse operation name to bitmask
 */
static uint32_t
parse_operation(const char *opstr)
{
	uint32_t operation;

	if (mac_abacd_parse_operations(opstr, &operation) != 0 ||
	    operation == ABAC_OP_ALL || (operation & (operation - 1)) != 0)
		return (0);
	return (operation);
}

/*
 * label get|set|remove <path>
 */
int
cmd_label(int argc, char *argv[])
{
	char buf[ABAC_MAX_LABEL_LEN];
	ssize_t len;
	int ret;

	if (argc < 2)
		usage();

	if (strcmp(argv[0], "get") == 0) {
		char *p;

		len = extattr_get_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    get_extattr_name(), buf, sizeof(buf) - 1);
		if (len < 0) {
			if (errno == ENOATTR) {
				printf("(no label)\n");
				return (0);
			}
			err(EX_OSERR, "extattr_get_file");
		}
		buf[len] = '\0';

		/*
		 * Convert newlines to commas for display.
		 * Storage: "type=app\ndomain=web\n"
		 * Display: "type=app,domain=web"
		 */
		for (p = buf; *p; p++) {
			if (*p == '\n') {
				if (*(p + 1) == '\0' || *(p + 1) == '\n')
					*p = '\0';  /* Remove trailing newline */
				else
					*p = ',';   /* Convert to comma */
			}
		}
		printf("%s\n", buf);

	} else if (strcmp(argv[0], "set") == 0 ||
	    strcmp(argv[0], "setatomic") == 0) {
		char *converted;

		if (argc < 3)
			errx(EX_USAGE, "label %s requires path and label", argv[0]);

		/*
		 * Convert from comma format (user-friendly) to newline format
		 * (storage format). User types: type=app,domain=web
		 * We store: type=app\ndomain=web\n
		 */
		converted = convert_label_format(argv[2]);
		if (converted == NULL)
			errx(EX_DATAERR, "invalid label format");

		ret = setlabel_atomic(argv[1], converted);
		free(converted);
		if (ret < 0)
			err(EX_OSERR, "SETLABEL");

		printf("label set atomically on %s\n", argv[1]);

	} else if (strcmp(argv[0], "remove") == 0) {
		int fd;

		fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			err(EX_OSERR, "open");
		ret = mac_syscall(ABAC_POLICY_NAME, ABAC_SYS_REMOVELABEL, &fd);
		close(fd);
		if (ret < 0) {
			if (errno == ENOATTR) {
				printf("(no label to remove)\n");
				return (0);
			}
			err(EX_OSERR, "REMOVELABEL");
		}
		printf("label removed from %s\n", argv[1]);

	} else if (strcmp(argv[0], "refresh") == 0) {
		/*
		 * Refresh the kernel's cached vnode label by re-reading
		 * from extattr. Useful after setextattr.
		 */
		int fd;

		fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			err(EX_OSERR, "open");

		ret = mac_syscall(ABAC_POLICY_NAME, ABAC_SYS_REFRESH, &fd);
		close(fd);

		if (ret < 0)
			err(EX_OSERR, "REFRESH");

		printf("label refreshed for %s\n", argv[1]);

	} else if (strcmp(argv[0], "setrecursive") == 0) {
		/*
		 * Recursively set labels on a directory tree.
		 * Usage: label setrecursive <path> <label> [options]
		 *
		 * Options:
		 *   -v  verbose (print each file)
		 *   -d  directories only
		 *   -f  files only
		 */
		FTS *ftsp;
		FTSENT *p;
		char *paths[2];
		char *converted;
		int verbose = 0;
		int dirs_only = 0;
		int files_only = 0;
		int labeled = 0;
		int errors = 0;
		int i;

		if (argc < 3)
			errx(EX_USAGE, "label setrecursive requires path and label");

		/* Parse options after path and label */
		for (i = 3; i < argc; i++) {
			if (strcmp(argv[i], "-v") == 0)
				verbose = 1;
			else if (strcmp(argv[i], "-d") == 0)
				dirs_only = 1;
			else if (strcmp(argv[i], "-f") == 0)
				files_only = 1;
			else
				errx(EX_USAGE, "unknown option: %s", argv[i]);
		}

		if (dirs_only && files_only)
			errx(EX_USAGE, "-d and -f are mutually exclusive");

		/* Convert label format */
		converted = convert_label_format(argv[2]);
		if (converted == NULL)
			errx(EX_DATAERR, "invalid label format");

		/* Set up fts */
		paths[0] = argv[1];
		paths[1] = NULL;

		ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
		if (ftsp == NULL) {
			free(converted);
			err(EX_OSERR, "fts_open");
		}

		while ((p = fts_read(ftsp)) != NULL) {
			switch (p->fts_info) {
			case FTS_D:		/* Directory (preorder) */
				if (files_only)
					continue;
				break;
			case FTS_F:		/* Regular file */
				if (dirs_only)
					continue;
				break;
			case FTS_SL:		/* Symbolic link */
			case FTS_SLNONE:	/* Symbolic link (no target) */
				/* Skip symlinks - can't set extattr on them */
				continue;
			case FTS_DP:		/* Directory (postorder) */
				/* Skip - we labeled in preorder */
				continue;
			case FTS_DNR:		/* Unreadable directory */
			case FTS_ERR:		/* Error */
			case FTS_NS:		/* No stat info */
				warnx("%s: %s", p->fts_path, strerror(p->fts_errno));
				errors++;
				continue;
			default:
				/* Other types (block, char, fifo, socket) */
				if (dirs_only)
					continue;
				break;
			}

			/* Set label atomically */
			if (setlabel_atomic(p->fts_accpath, converted) < 0) {
				warn("%s", p->fts_path);
				errors++;
			} else {
				labeled++;
				if (verbose)
					printf("%s\n", p->fts_path);
			}
		}

		if (errno != 0)
			warn("fts_read");

		fts_close(ftsp);
		free(converted);

		printf("labeled %d items", labeled);
		if (errors > 0)
			printf(" (%d errors)", errors);
		printf("\n");

		return (errors > 0 ? 1 : 0);

	} else {
		errx(EX_USAGE, "unknown label command: %s", argv[0]);
	}

	return (0);
}

/*
 * test <operation> <subject-label> <object-label>
 *
 * Test if an operation would be allowed without actually performing it.
 */
int
cmd_test(int argc, char *argv[])
{
	struct abac_test_arg *test_arg;
	char *buf;
	size_t subject_len, object_len, total_len;
	uint32_t op;

	if (argc < 3)
		errx(EX_USAGE, "test requires: <operation> <subject-label> <object-label>");

	/* Parse operation */
	op = parse_operation(argv[0]);
	if (op == 0)
		errx(EX_USAGE, "unknown operation: %s", argv[0]);

	/* Build test argument */
	subject_len = strlen(argv[1]) + 1;
	object_len = strlen(argv[2]) + 1;
	total_len = sizeof(struct abac_test_arg) + subject_len + object_len;

	buf = calloc(1, total_len);
	if (buf == NULL)
		err(EX_OSERR, "calloc");

	test_arg = (struct abac_test_arg *)buf;
	test_arg->vt_operation = op;
	test_arg->vt_subject_len = subject_len;
	test_arg->vt_object_len = object_len;

	memcpy(buf + sizeof(struct abac_test_arg), argv[1], subject_len);
	memcpy(buf + sizeof(struct abac_test_arg) + subject_len, argv[2], object_len);

	/* Perform test */
	if (abac_syscall(ABAC_SYS_TEST, buf) < 0) {
		free(buf);
		err(EX_OSERR, "TEST");
	}

	/* Print result */
	printf("Operation:   %s\n", argv[0]);
	printf("Subject:     %s\n", argv[1]);
	printf("Object:      %s\n", argv[2]);
	printf("Result:      %s\n", test_arg->vt_result == 0 ? "ALLOW" : "DENY");

	if (test_arg->vt_rule_id != 0)
		printf("Matched:     rule %u\n", test_arg->vt_rule_id);
	else
		printf("Matched:     (default policy)\n");

	int result = (test_arg->vt_result == 0) ? 0 : 1;
	free(buf);

	/* Exit with non-zero if denied, for scripting */
	return result;
}
