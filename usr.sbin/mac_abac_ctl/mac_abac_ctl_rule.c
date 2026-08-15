/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abac_ctl - Rule command handlers
 *
 * Handles: rule add|remove|clear|list|load|append|validate
 *
 * Supports both line format (.rules) and UCL/JSON format (.ucl, .json, .conf)
 */

#include <sys/types.h>
#include <sys/mac.h>

#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>

#include <security/mac_abac/mac_abac.h>
#include "mac_abacd.h"
#include "mac_abac_ctl.h"

/*
 * Maximum rule line size for file parsing.
 * A full rule: action + ops + subject + "->" + object + contexts + "=>" + newlabel
 * Approximately: 12 + 200 + 1040 + 4 + 1040 + 200 + 4 + 1040 = ~3540 bytes
 */
#define ABAC_MAX_RULE_LINE	(3 * ABAC_PATTERN_MAX_LEN + 512)

/*
 * Initial buffer size for rule loading (grows dynamically).
 */
#define ABAC_INITIAL_LOAD_BUFSIZE	8192

/*
 * Context for UCL rule loading callback
 */
struct ucl_load_ctx {
	char	*buf;
	size_t	 buflen;
	size_t	 bufused;
	int	 count;
	int	 errors;
	int	 set_override;	/* -1 = use parsed value, >= 0 = override */
};

/*
 * Stub implementations for mac_abacd functions used by parse_ucl.c
 * These are only needed when linking parse_ucl.o into mac_abac_ctl.
 */
void
mac_abacd_log(int priority __unused, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

int
mac_abacd_set_mode(int mode __unused)
{
	/* mac_abac_ctl doesn't use mode from UCL files - use 'mac_abac_ctl mode' */
	return (0);
}

int
mac_abacd_set_default_policy(int policy __unused)
{
	/* mac_abac_ctl doesn't use default policy from UCL files - use 'mac_abac_ctl default' */
	return (0);
}

int
mac_abacd_add_rule(struct abac_rule_io *rule __unused)
{
	/* Not used - we use the callback interface instead */
	return (0);
}

/*
 * Check if file has UCL/JSON extension
 */
static int
is_ucl_file(const char *path)
{
	const char *ext;

	ext = strrchr(path, '.');
	if (ext == NULL)
		return (0);

	return (strcasecmp(ext, ".ucl") == 0 ||
	    strcasecmp(ext, ".json") == 0 ||
	    strcasecmp(ext, ".conf") == 0);
}

/*
 * Build a rule_arg buffer from parsed rule
 *
 * The daemon's mac_abacd_parse_line() returns abac_rule_io (userland format).
 * We convert it to abac_rule_arg (kernel mac_syscall format).
 * If set_override >= 0, use that set instead of the parsed value.
 */
static int
build_rule_arg_with_set(const char *rule_str, char **bufp, size_t *lenp, int set_override)
{
	struct abac_rule_io rule_io;
	struct abac_rule_arg *arg;
	char *buf, *data;
	size_t subject_len, object_len, newlabel_len, total_len;
	int ret;

	/* Parse using existing parser */
	ret = mac_abacd_parse_line(rule_str, &rule_io);
	if (ret != 0)
		return (ret);

	/* Calculate lengths (include null terminators) */
	subject_len = strlen(rule_io.vr_subject.vp_pattern) + 1;
	object_len = strlen(rule_io.vr_object.vp_pattern) + 1;
	newlabel_len = (rule_io.vr_action == ABAC_ACTION_TRANSITION) ?
	    strlen(rule_io.vr_newlabel) + 1 : 0;

	total_len = sizeof(struct abac_rule_arg) + subject_len + object_len + newlabel_len;

	buf = calloc(1, total_len);
	if (buf == NULL)
		return (-1);

	arg = (struct abac_rule_arg *)buf;
	arg->vr_action = rule_io.vr_action;
	arg->vr_set = (set_override >= 0) ? (uint16_t)set_override : rule_io.vr_set;
	arg->vr_operations = rule_io.vr_operations;
	arg->vr_subject_flags = rule_io.vr_subject.vp_flags;
	arg->vr_object_flags = rule_io.vr_object.vp_flags;
	/* Copy subject context constraints */
	arg->vr_subj_context.vc_flags = rule_io.vr_subj_context.vc_flags;
	arg->vr_subj_context.vc_cap_sandboxed = rule_io.vr_subj_context.vc_cap_sandboxed;
	arg->vr_subj_context.vc_has_tty = rule_io.vr_subj_context.vc_has_tty;
	arg->vr_subj_context.vc_jail_check = rule_io.vr_subj_context.vc_jail_check;
	arg->vr_subj_context.vc_uid = rule_io.vr_subj_context.vc_uid;
	arg->vr_subj_context.vc_gid = rule_io.vr_subj_context.vc_gid;
	/* Copy object context constraints */
	arg->vr_obj_context.vc_flags = rule_io.vr_obj_context.vc_flags;
	arg->vr_obj_context.vc_cap_sandboxed = rule_io.vr_obj_context.vc_cap_sandboxed;
	arg->vr_obj_context.vc_has_tty = rule_io.vr_obj_context.vc_has_tty;
	arg->vr_obj_context.vc_jail_check = rule_io.vr_obj_context.vc_jail_check;
	arg->vr_obj_context.vc_uid = rule_io.vr_obj_context.vc_uid;
	arg->vr_obj_context.vc_gid = rule_io.vr_obj_context.vc_gid;
	arg->vr_subject_len = subject_len;
	arg->vr_object_len = object_len;
	arg->vr_newlabel_len = newlabel_len;

	/* Copy strings */
	data = buf + sizeof(struct abac_rule_arg);
	memcpy(data, rule_io.vr_subject.vp_pattern, subject_len);
	data += subject_len;
	memcpy(data, rule_io.vr_object.vp_pattern, object_len);
	data += object_len;
	if (newlabel_len > 0)
		memcpy(data, rule_io.vr_newlabel, newlabel_len);

	*bufp = buf;
	*lenp = total_len;
	return (0);
}

/*
 * Build a rule_arg buffer from parsed rule (default set = use parsed value)
 */
static int
build_rule_arg(const char *rule_str, char **bufp, size_t *lenp)
{
	return build_rule_arg_with_set(rule_str, bufp, lenp, -1);
}

/*
 * Build rule_arg buffer from abac_rule_io
 * Used by UCL callback to convert parsed rules to kernel format.
 * If set_override >= 0, use that set instead of the parsed value.
 */
static int
build_rule_arg_from_io_with_set(struct abac_rule_io *rule_io, char **bufp, size_t *lenp, int set_override)
{
	struct abac_rule_arg *arg;
	char *buf, *data;
	size_t subject_len, object_len, newlabel_len, total_len;

	/* Calculate lengths (include null terminators) */
	subject_len = strlen(rule_io->vr_subject.vp_pattern) + 1;
	object_len = strlen(rule_io->vr_object.vp_pattern) + 1;
	newlabel_len = (rule_io->vr_action == ABAC_ACTION_TRANSITION) ?
	    strlen(rule_io->vr_newlabel) + 1 : 0;

	total_len = sizeof(struct abac_rule_arg) + subject_len + object_len + newlabel_len;

	buf = calloc(1, total_len);
	if (buf == NULL)
		return (-1);

	arg = (struct abac_rule_arg *)buf;
	arg->vr_action = rule_io->vr_action;
	arg->vr_set = (set_override >= 0) ? (uint16_t)set_override : rule_io->vr_set;
	arg->vr_operations = rule_io->vr_operations;
	arg->vr_subject_flags = rule_io->vr_subject.vp_flags;
	arg->vr_object_flags = rule_io->vr_object.vp_flags;
	/* Copy subject context constraints */
	arg->vr_subj_context.vc_flags = rule_io->vr_subj_context.vc_flags;
	arg->vr_subj_context.vc_cap_sandboxed = rule_io->vr_subj_context.vc_cap_sandboxed;
	arg->vr_subj_context.vc_has_tty = rule_io->vr_subj_context.vc_has_tty;
	arg->vr_subj_context.vc_jail_check = rule_io->vr_subj_context.vc_jail_check;
	arg->vr_subj_context.vc_uid = rule_io->vr_subj_context.vc_uid;
	arg->vr_subj_context.vc_gid = rule_io->vr_subj_context.vc_gid;
	/* Copy object context constraints */
	arg->vr_obj_context.vc_flags = rule_io->vr_obj_context.vc_flags;
	arg->vr_obj_context.vc_cap_sandboxed = rule_io->vr_obj_context.vc_cap_sandboxed;
	arg->vr_obj_context.vc_has_tty = rule_io->vr_obj_context.vc_has_tty;
	arg->vr_obj_context.vc_jail_check = rule_io->vr_obj_context.vc_jail_check;
	arg->vr_obj_context.vc_uid = rule_io->vr_obj_context.vc_uid;
	arg->vr_obj_context.vc_gid = rule_io->vr_obj_context.vc_gid;
	arg->vr_subject_len = subject_len;
	arg->vr_object_len = object_len;
	arg->vr_newlabel_len = newlabel_len;

	/* Copy strings */
	data = buf + sizeof(struct abac_rule_arg);
	memcpy(data, rule_io->vr_subject.vp_pattern, subject_len);
	data += subject_len;
	memcpy(data, rule_io->vr_object.vp_pattern, object_len);
	data += object_len;
	if (newlabel_len > 0)
		memcpy(data, rule_io->vr_newlabel, newlabel_len);

	*bufp = buf;
	*lenp = total_len;
	return (0);
}

/*
 * Callback for UCL rule parsing - adds rule to packed buffer
 */
static int
ucl_rule_callback(struct abac_rule_io *rule, void *ctx)
{
	struct ucl_load_ctx *lctx = ctx;
	char *rule_buf;
	size_t rule_len;

	if (build_rule_arg_from_io_with_set(rule, &rule_buf, &rule_len, lctx->set_override) < 0) {
		lctx->errors++;
		return (-1);
	}

	/* Grow buffer if needed */
	if (lctx->bufused + rule_len > lctx->buflen) {
		size_t newlen = lctx->buflen == 0 ? ABAC_INITIAL_LOAD_BUFSIZE :
		    lctx->buflen * 2;
		char *newbuf;

		while (newlen < lctx->bufused + rule_len)
			newlen *= 2;
		newbuf = realloc(lctx->buf, newlen);
		if (newbuf == NULL) {
			free(rule_buf);
			lctx->errors++;
			return (-1);
		}
		lctx->buf = newbuf;
		lctx->buflen = newlen;
	}

	/* Append rule to buffer */
	memcpy(lctx->buf + lctx->bufused, rule_buf, rule_len);
	lctx->bufused += rule_len;
	lctx->count++;

	free(rule_buf);
	return (0);
}

/*
 * Load rules from UCL/JSON file
 * If set_override >= 0, all rules go to that set regardless of file contents.
 */
static int
load_ucl_rules(const char *path, int set_override)
{
	struct ucl_load_ctx ctx;
	struct abac_rule_load_arg load_arg;

	memset(&ctx, 0, sizeof(ctx));
	ctx.set_override = set_override;

	if (mac_abacd_parse_ucl_with_callback(path, false, ucl_rule_callback, &ctx) < 0) {
		free(ctx.buf);
		return (-1);
	}

	if (ctx.errors > 0) {
		warnx("aborting load due to %d parse errors", ctx.errors);
		free(ctx.buf);
		return (-1);
	}

	if (ctx.count == 0) {
		printf("no rules to load (clearing existing rules)\n");
	}

	/* Atomic load via kernel syscall */
	memset(&load_arg, 0, sizeof(load_arg));
	load_arg.vrl_count = ctx.count;
	load_arg.vrl_buflen = ctx.bufused;
	load_arg.vrl_buf = ctx.buf;

	if (abac_syscall(ABAC_SYS_RULE_LOAD, &load_arg) < 0) {
		free(ctx.buf);
		err(EX_OSERR, "RULE_LOAD");
	}

	free(ctx.buf);

	printf("loaded %u rules from %s (atomic)\n", load_arg.vrl_loaded, path);
	return (0);
}

/*
 * rule add|remove|clear|list|load|append|validate
 */
int
cmd_rule(int argc, char *argv[])
{
	uint32_t id;
	int ret;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "add") == 0) {
		char *buf;
		size_t len;
		struct abac_rule_arg *arg;
		int set_override = -1;
		int rule_idx = 1;

		/* Parse options */
		while (rule_idx < argc && argv[rule_idx][0] == '-') {
			if (strcmp(argv[rule_idx], "-s") == 0) {
				char *endptr;
				unsigned long val;
				if (rule_idx + 1 >= argc)
					errx(EX_USAGE, "-s requires a set number");
				errno = 0;
				val = strtoul(argv[rule_idx + 1], &endptr, 10);
				if (errno != 0 || *endptr != '\0' ||
				    val >= ABAC_MAX_SETS)
					errx(EX_USAGE, "invalid set number: %s",
					    argv[rule_idx + 1]);
				set_override = (int)val;
				rule_idx += 2;
			} else {
				errx(EX_USAGE, "unknown option: %s", argv[rule_idx]);
			}
		}

		if (rule_idx >= argc)
			errx(EX_USAGE, "rule add requires a rule string");

		ret = build_rule_arg_with_set(argv[rule_idx], &buf, &len, set_override);
		if (ret < 0)
			errx(EX_DATAERR, "invalid rule syntax");
		if (ret > 0)
			errx(EX_DATAERR, "empty rule");

		if (abac_syscall(ABAC_SYS_RULE_ADD, buf) < 0) {
			free(buf);
			err(EX_OSERR, "RULE_ADD");
		}

		arg = (struct abac_rule_arg *)buf;
		printf("rule %u added (set %u)\n", arg->vr_id, arg->vr_set);
		free(buf);

	} else if (strcmp(argv[0], "append") == 0) {
		/*
		 * Append rules from file without clearing existing rules.
		 * Unlike 'load', this adds to existing rules.
		 */
		FILE *fp;
		char line[ABAC_MAX_RULE_LINE];
		char *start, *end, *comment;
		char *buf;
		size_t len;
		struct abac_rule_arg *arg;
		int lineno = 0;
		int added = 0;
		int errors = 0;

		if (argc < 2)
			errx(EX_USAGE, "rule append requires a file path");

		fp = fopen(argv[1], "r");
		if (fp == NULL)
			err(EX_NOINPUT, "open %s", argv[1]);

		while (fgets(line, sizeof(line), fp) != NULL) {
			lineno++;

			/* Strip comments */
			comment = strchr(line, '#');
			if (comment != NULL)
				*comment = '\0';

			/* Trim leading whitespace */
			start = line;
			while (*start == ' ' || *start == '\t')
				start++;

			/* Trim trailing whitespace */
			end = start + strlen(start) - 1;
			while (end > start && (*end == '\n' || *end == '\r' ||
			    *end == ' ' || *end == '\t')) {
				*end = '\0';
				end--;
			}

			/* Skip empty lines */
			if (*start == '\0')
				continue;

			/* Parse and add rule */
			ret = build_rule_arg(start, &buf, &len);
			if (ret < 0) {
				warnx("%s:%d: invalid rule syntax: %s",
				    argv[1], lineno, start);
				errors++;
				continue;
			}
			if (ret > 0) /* empty after parsing */
				continue;

			if (abac_syscall(ABAC_SYS_RULE_ADD, buf) < 0) {
				warn("%s:%d: failed to add rule", argv[1], lineno);
				free(buf);
				errors++;
				continue;
			}

			arg = (struct abac_rule_arg *)buf;
			printf("  rule %u added\n", arg->vr_id);
			free(buf);
			added++;
		}

		fclose(fp);

		printf("appended %d rules", added);
		if (errors > 0)
			printf(" (%d errors)", errors);
		printf("\n");

		return (errors > 0 ? 1 : 0);

	} else if (strcmp(argv[0], "remove") == 0) {
		char *endptr;
		unsigned long ulid;

		if (argc < 2)
			errx(EX_USAGE, "rule remove requires a rule ID");

		errno = 0;
		ulid = strtoul(argv[1], &endptr, 10);
		if (errno != 0 || *endptr != '\0' || argv[1][0] == '\0')
			errx(EX_USAGE, "invalid rule ID: %s", argv[1]);
		if (ulid > UINT32_MAX)
			errx(EX_USAGE, "rule ID out of range: %s", argv[1]);

		id = (uint32_t)ulid;
		if (abac_syscall(ABAC_SYS_RULE_REMOVE, &id) < 0)
			err(EX_OSERR, "RULE_REMOVE");

		printf("removed rule %u\n", id);

	} else if (strcmp(argv[0], "clear") == 0) {
		if (abac_syscall(ABAC_SYS_RULE_CLEAR, NULL) < 0)
			err(EX_OSERR, "RULE_CLEAR");

		printf("all rules cleared\n");

	} else if (strcmp(argv[0], "load") == 0) {
		/*
		 * Atomic rule load - like PF's pfctl -f
		 *
		 * Supports both line format (.rules) and UCL/JSON format
		 * (.ucl, .json, .conf). Format is auto-detected by extension.
		 *
		 * On success: old rules are cleared, new rules loaded
		 * On failure: old rules remain unchanged
		 *
		 * Use -s <set> to load all rules into a specific set.
		 */
		FILE *fp;
		char line[ABAC_MAX_RULE_LINE];
		char *start, *end, *comment;
		char *rule_buf;
		size_t rule_len;
		int lineno = 0;
		int rule_count = 0;
		int errors = 0;
		int set_override = -1;
		int file_idx = 1;
		const char *filepath;

		/* Dynamic buffer for packed rules */
		char *load_buf = NULL;
		size_t load_buflen = 0;
		size_t load_bufused = 0;

		struct abac_rule_load_arg load_arg;

		/* Parse options */
		while (file_idx < argc && argv[file_idx][0] == '-') {
			if (strcmp(argv[file_idx], "-s") == 0) {
				char *endptr;
				unsigned long val;
				if (file_idx + 1 >= argc)
					errx(EX_USAGE, "-s requires a set number");
				errno = 0;
				val = strtoul(argv[file_idx + 1], &endptr, 10);
				if (errno != 0 || *endptr != '\0' ||
				    val >= ABAC_MAX_SETS)
					errx(EX_USAGE, "invalid set number: %s",
					    argv[file_idx + 1]);
				set_override = (int)val;
				file_idx += 2;
			} else {
				errx(EX_USAGE, "unknown option: %s", argv[file_idx]);
			}
		}

		if (file_idx >= argc)
			errx(EX_USAGE, "rule load requires a file path");

		filepath = argv[file_idx];

		/* Check for trailing -s option (allow both orders) */
		if (file_idx + 1 < argc && strcmp(argv[file_idx + 1], "-s") == 0) {
			char *endptr;
			unsigned long val;
			if (file_idx + 2 >= argc)
				errx(EX_USAGE, "-s requires a set number");
			errno = 0;
			val = strtoul(argv[file_idx + 2], &endptr, 10);
			if (errno != 0 || *endptr != '\0' ||
			    val >= ABAC_MAX_SETS)
				errx(EX_USAGE, "invalid set number: %s",
				    argv[file_idx + 2]);
			set_override = (int)val;
		}

		/* Check file format and dispatch to appropriate loader */
		if (is_ucl_file(filepath)) {
			return load_ucl_rules(filepath, set_override);
		}

		/* Line format parsing */
		fp = fopen(filepath, "r");
		if (fp == NULL)
			err(EX_NOINPUT, "open %s", filepath);

		/* First pass: parse all rules into buffer */
		while (fgets(line, sizeof(line), fp) != NULL) {
			lineno++;

			/* Strip comments */
			comment = strchr(line, '#');
			if (comment != NULL)
				*comment = '\0';

			/* Trim leading whitespace */
			start = line;
			while (*start == ' ' || *start == '\t')
				start++;

			/* Trim trailing whitespace */
			end = start + strlen(start) - 1;
			while (end > start && (*end == '\n' || *end == '\r' ||
			    *end == ' ' || *end == '\t')) {
				*end = '\0';
				end--;
			}

			/* Skip empty lines */
			if (*start == '\0')
				continue;

			/* Parse rule */
			ret = build_rule_arg_with_set(start, &rule_buf, &rule_len, set_override);
			if (ret < 0) {
				warnx("%s:%d: invalid rule syntax: %s",
				    filepath, lineno, start);
				errors++;
				continue;
			}
			if (ret > 0) /* empty after parsing */
				continue;

			/* Grow buffer if needed */
			if (load_bufused + rule_len > load_buflen) {
				size_t newlen = load_buflen == 0 ?
				    ABAC_INITIAL_LOAD_BUFSIZE : load_buflen * 2;
				char *newbuf;
				while (newlen < load_bufused + rule_len)
					newlen *= 2;
				newbuf = realloc(load_buf, newlen);
				if (newbuf == NULL) {
					free(rule_buf);
					free(load_buf);
					fclose(fp);
					err(EX_OSERR, "realloc");
				}
				load_buf = newbuf;
				load_buflen = newlen;
			}

			/* Append rule to buffer */
			memcpy(load_buf + load_bufused, rule_buf, rule_len);
			load_bufused += rule_len;
			rule_count++;

			free(rule_buf);
		}

		fclose(fp);

		if (errors > 0) {
			warnx("aborting load due to %d parse errors", errors);
			free(load_buf);
			return (1);
		}

		if (rule_count == 0) {
			printf("no rules to load (clearing existing rules)\n");
		}

		/* Atomic load via kernel syscall */
		memset(&load_arg, 0, sizeof(load_arg));
		load_arg.vrl_count = rule_count;
		load_arg.vrl_buflen = load_bufused;
		load_arg.vrl_buf = load_buf;

		if (abac_syscall(ABAC_SYS_RULE_LOAD, &load_arg) < 0) {
			free(load_buf);
			err(EX_OSERR, "RULE_LOAD");
		}

		free(load_buf);

		if (set_override >= 0)
			printf("loaded %u rules to set %d (atomic)\n",
			    load_arg.vrl_loaded, set_override);
		else
			printf("loaded %u rules (atomic)\n", load_arg.vrl_loaded);
		return (0);

	} else if (strcmp(argv[0], "list") == 0) {
		struct abac_rule_list_arg list_arg;
		struct abac_rule_out *out;
		char *buf, *p;
		uint32_t i;
		const char *action_str;

		/* Query rule count first */
		memset(&list_arg, 0, sizeof(list_arg));
		if (abac_syscall(ABAC_SYS_RULE_LIST, &list_arg) < 0)
			err(EX_OSERR, "RULE_LIST");

		if (list_arg.vrl_total == 0) {
			printf("(no rules loaded)\n");
			return (0);
		}

		/* Allocate buffer for rules (estimate size per rule) */
		list_arg.vrl_buflen = list_arg.vrl_total *
		    (sizeof(struct abac_rule_out) + 3 * ABAC_PATTERN_MAX_LEN);
		buf = malloc(list_arg.vrl_buflen);
		if (buf == NULL)
			err(EX_OSERR, "malloc");

		list_arg.vrl_buf = buf;
		list_arg.vrl_offset = 0;

		if (abac_syscall(ABAC_SYS_RULE_LIST, &list_arg) < 0) {
			free(buf);
			err(EX_OSERR, "RULE_LIST");
		}

		printf("Loaded rules: %u\n\n", list_arg.vrl_count);

		/* Parse and print rules */
		p = buf;
		for (i = 0; i < list_arg.vrl_count; i++) {
			char opsbuf[128];
			const char *subject, *object, *newlabel;

			out = (struct abac_rule_out *)p;
			subject = p + sizeof(struct abac_rule_out);
			object = subject + out->vr_subject_len;
			newlabel = object + out->vr_object_len;

			switch (out->vr_action) {
			case ABAC_ACTION_ALLOW:
				action_str = "allow";
				break;
			case ABAC_ACTION_DENY:
				action_str = "deny";
				break;
			case ABAC_ACTION_TRANSITION:
				action_str = "transition";
				break;
			default:
				action_str = "unknown";
				break;
			}

			printf("  [%u", out->vr_id);
			if (out->vr_set != 0)
				printf(" set %u", out->vr_set);
			printf("] %s %s %s%s -> %s%s",
			    action_str,
			    ops_to_string(out->vr_operations, opsbuf, sizeof(opsbuf)),
			    (out->vr_subject_flags & ABAC_MATCH_NEGATE) ? "!" : "",
			    subject[0] ? subject : "*",
			    (out->vr_object_flags & ABAC_MATCH_NEGATE) ? "!" : "",
			    object[0] ? object : "*");

			if (out->vr_action == ABAC_ACTION_TRANSITION &&
			    out->vr_newlabel_len > 0)
				printf(" => %s", newlabel);

			/* Print subject context constraints if any */
			if (out->vr_subj_context.vc_flags != 0) {
				printf(" subj_context:");
				int first = 1;
				if (out->vr_subj_context.vc_flags & ABAC_CTX_CAP_SANDBOXED) {
					printf("%ssandboxed=%s", first ? "" : ",",
					    out->vr_subj_context.vc_cap_sandboxed ? "true" : "false");
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & ABAC_CTX_JAIL) {
					if (out->vr_subj_context.vc_jail_check == 0)
						printf("%sjail=host", first ? "" : ",");
					else if (out->vr_subj_context.vc_jail_check == -1)
						printf("%sjail=any", first ? "" : ",");
					else
						printf("%sjail=%d", first ? "" : ",",
						    out->vr_subj_context.vc_jail_check);
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & ABAC_CTX_UID) {
					printf("%suid=%u", first ? "" : ",",
					    out->vr_subj_context.vc_uid);
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & ABAC_CTX_GID) {
					printf("%sgid=%u", first ? "" : ",",
					    out->vr_subj_context.vc_gid);
					first = 0;
				}
			}

			/* Print object context constraints if any */
			if (out->vr_obj_context.vc_flags != 0) {
				printf(" obj_context:");
				int first = 1;
				if (out->vr_obj_context.vc_flags & ABAC_CTX_CAP_SANDBOXED) {
					printf("%ssandboxed=%s", first ? "" : ",",
					    out->vr_obj_context.vc_cap_sandboxed ? "true" : "false");
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & ABAC_CTX_JAIL) {
					if (out->vr_obj_context.vc_jail_check == 0)
						printf("%sjail=host", first ? "" : ",");
					else if (out->vr_obj_context.vc_jail_check == -1)
						printf("%sjail=any", first ? "" : ",");
					else
						printf("%sjail=%d", first ? "" : ",",
						    out->vr_obj_context.vc_jail_check);
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & ABAC_CTX_UID) {
					printf("%suid=%u", first ? "" : ",",
					    out->vr_obj_context.vc_uid);
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & ABAC_CTX_GID) {
					printf("%sgid=%u", first ? "" : ",",
					    out->vr_obj_context.vc_gid);
					first = 0;
				}
			}

			printf("\n");

			/* Advance to next rule */
			p += sizeof(struct abac_rule_out) +
			    out->vr_subject_len + out->vr_object_len +
			    out->vr_newlabel_len;
		}

		free(buf);

	} else if (strcmp(argv[0], "validate") == 0) {
		/*
		 * Validate a rule or file without loading into kernel.
		 * Supports both single rule validation and file validation (-f).
		 */
		int valid_count = 0;
		int warning_count = 0;
		int error_count = 0;

		if (argc < 2)
			errx(EX_USAGE, "rule validate requires a rule string or -f <file>");

		if (strcmp(argv[1], "-f") == 0) {
			/* File validation mode */
			FILE *fp;
			char line[ABAC_MAX_RULE_LINE];
			char *start, *end, *comment;
			int lineno = 0;
			struct abac_rule_io rule_io;

			if (argc < 3)
				errx(EX_USAGE, "rule validate -f requires a file path");

			fp = fopen(argv[2], "r");
			if (fp == NULL)
				err(EX_NOINPUT, "open %s", argv[2]);

			printf("Validating %s...\n", argv[2]);

			while (fgets(line, sizeof(line), fp) != NULL) {
				lineno++;

				/* Strip comments */
				comment = strchr(line, '#');
				if (comment != NULL)
					*comment = '\0';

				/* Trim leading whitespace */
				start = line;
				while (*start == ' ' || *start == '\t')
					start++;

				/* Trim trailing whitespace */
				end = start + strlen(start) - 1;
				while (end > start && (*end == '\n' || *end == '\r' ||
				    *end == ' ' || *end == '\t')) {
					*end = '\0';
					end--;
				}

				/* Skip empty lines */
				if (*start == '\0')
					continue;

				/* Parse rule */
				ret = mac_abacd_parse_line(start, &rule_io);
				if (ret < 0) {
					printf("  %s:%d: ERROR: invalid syntax: %s\n",
					    argv[2], lineno, start);
					error_count++;
					continue;
				}
				if (ret > 0) /* empty after parsing */
					continue;

				/* Check for warnings */
				if (rule_io.vr_action == ABAC_ACTION_TRANSITION &&
				    rule_io.vr_newlabel[0] == '\0') {
					printf("  %s:%d: WARNING: transition without newlabel: %s\n",
					    argv[2], lineno, start);
					warning_count++;
				}

				valid_count++;
			}

			fclose(fp);

			printf("\nValidation complete: %d valid, %d warnings, %d errors\n",
			    valid_count, warning_count, error_count);

			return (error_count > 0 ? 1 : 0);

		} else {
			/* Single rule validation mode */
			struct abac_rule_io rule_io;

			ret = mac_abacd_parse_line(argv[1], &rule_io);
			if (ret < 0) {
				printf("ERROR: invalid rule syntax\n");
				return (1);
			}
			if (ret > 0) {
				printf("ERROR: empty rule\n");
				return (1);
			}

			/* Check for warnings */
			if (rule_io.vr_action == ABAC_ACTION_TRANSITION &&
			    rule_io.vr_newlabel[0] == '\0') {
				printf("WARNING: transition rule without newlabel\n");
				printf("OK (with warnings)\n");
				return (0);
			}

			printf("OK\n");
			return (0);
		}

	} else {
		errx(EX_USAGE, "unknown rule command: %s", argv[0]);
	}

	return (0);
}
