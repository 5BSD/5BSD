/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * oeslogger - Log OES events as JSON (similar to macOS eslogger)
 *
 * Usage: oeslogger [-p] [-o file] [event_type ...]
 *   -o file  Write output to file (append mode; default: stdout)
 *   -p       Pretty-print JSON output
 *   -l       List available event names
 *
 * Examples:
 *   oeslogger                            # All events to stdout
 *   oeslogger -o /var/log/oes.ndjson     # Log to file
 *   oeslogger exec open create unlink    # Specific events only
 *   oeslogger -p exec fork exit          # Pretty-printed
 *   oeslogger exec open | jq .           # Pipe NDJSON to jq
 *
 * Output is one JSON object per line (NDJSON) unless -p is used.
 * Each event includes an "auth_capable" field indicating whether
 * the event type has an AUTH variant that could block operations.
 * Requires root or appropriate MAC privileges.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "liboes.h"

static volatile sig_atomic_t running = 1;
static bool pretty = false;
static FILE *outfp;

static void
sighandler(int sig __unused)
{
	running = 0;
}

/*
 * JSON output helpers.
 *
 * All helpers take a FILE *fp for output redirection (-o flag).
 * Strings are escaped for JSON safety.
 */

static void
json_escape_byte(unsigned char c, FILE *fp)
{

	switch (c) {
	case '"':  fputs("\\\"", fp); break;
	case '\\': fputs("\\\\", fp); break;
	case '\b': fputs("\\b", fp); break;
	case '\f': fputs("\\f", fp); break;
	case '\n': fputs("\\n", fp); break;
	case '\r': fputs("\\r", fp); break;
	case '\t': fputs("\\t", fp); break;
	default:
		if (c < 0x20 || c >= 0x80)
			fprintf(fp, "\\u%04x", c);
		else
			fputc(c, fp);
		break;
	}
}

static size_t
utf8_sequence_len(const unsigned char *s, size_t remaining)
{
	unsigned char c0;

	if (s == NULL || remaining == 0)
		return (0);

	c0 = s[0];
	if (c0 <= 0x7f)
		return (1);

	if (remaining >= 2 && c0 >= 0xc2 && c0 <= 0xdf &&
	    s[1] >= 0x80 && s[1] <= 0xbf)
		return (2);

	if (remaining >= 3) {
		if (c0 == 0xe0 &&
		    s[1] >= 0xa0 && s[1] <= 0xbf &&
		    s[2] >= 0x80 && s[2] <= 0xbf)
			return (3);
		if ((c0 >= 0xe1 && c0 <= 0xec) || (c0 >= 0xee && c0 <= 0xef)) {
			if (s[1] >= 0x80 && s[1] <= 0xbf &&
			    s[2] >= 0x80 && s[2] <= 0xbf)
				return (3);
		}
		if (c0 == 0xed &&
		    s[1] >= 0x80 && s[1] <= 0x9f &&
		    s[2] >= 0x80 && s[2] <= 0xbf)
			return (3);
	}

	if (remaining >= 4) {
		if (c0 == 0xf0 &&
		    s[1] >= 0x90 && s[1] <= 0xbf &&
		    s[2] >= 0x80 && s[2] <= 0xbf &&
		    s[3] >= 0x80 && s[3] <= 0xbf)
			return (4);
		if (c0 >= 0xf1 && c0 <= 0xf3 &&
		    s[1] >= 0x80 && s[1] <= 0xbf &&
		    s[2] >= 0x80 && s[2] <= 0xbf &&
		    s[3] >= 0x80 && s[3] <= 0xbf)
			return (4);
		if (c0 == 0xf4 &&
		    s[1] >= 0x80 && s[1] <= 0x8f &&
		    s[2] >= 0x80 && s[2] <= 0xbf &&
		    s[3] >= 0x80 && s[3] <= 0xbf)
			return (4);
	}

	return (0);
}

static void
json_escape_bytes(const unsigned char *s, size_t maxlen, bool stop_at_nul,
    FILE *fp)
{
	size_t i;

	if (s == NULL || maxlen == 0 || s[0] == '\0') {
		fputs("\"\"", fp);
		return;
	}

	fputc('"', fp);
	for (i = 0; i < maxlen; i++) {
		size_t utf8_len;

		if (stop_at_nul && s[i] == '\0')
			break;

		utf8_len = utf8_sequence_len(&s[i], maxlen - i);
		if (utf8_len > 1) {
			size_t j;

			for (j = 0; j < utf8_len; j++)
				fputc(s[i + j], fp);
			i += utf8_len - 1;
			continue;
		}

		json_escape_byte(s[i], fp);
	}
	fputc('"', fp);
}

static void
json_escape(const char *s, FILE *fp)
{

	if (s == NULL || s[0] == '\0') {
		fputs("\"\"", fp);
		return;
	}

	json_escape_bytes((const unsigned char *)s, strlen(s), false, fp);
}

/*
 * Bounded JSON string escape -- for buffers that may not be NUL-terminated.
 * Writes at most `maxlen` bytes from `s`.
 */
static void
json_escape_n(const char *s, size_t maxlen, FILE *fp)
{

	json_escape_bytes((const unsigned char *)s, maxlen, true, fp);
}

/* Indent helper for pretty-printing */
static void
indent(FILE *fp, int depth)
{
	int i;

	if (!pretty)
		return;
	for (i = 0; i < depth; i++)
		fputs("  ", fp);
}

static void
nl(FILE *fp)
{
	if (pretty)
		fputc('\n', fp);
}

static void
sep(FILE *fp)
{
	if (pretty)
		fputs(": ", fp);
	else
		fputc(':', fp);
}

/* Key-value primitives */
static void
json_kv_str(FILE *fp, int depth, const char *key, const char *val, bool comma)
{
	indent(fp, depth);
	json_escape(key, fp);
	sep(fp);
	json_escape(val, fp);
	if (comma) fputc(',', fp);
	nl(fp);
}

static void
json_kv_int(FILE *fp, int depth, const char *key, int64_t val, bool comma)
{
	indent(fp, depth);
	json_escape(key, fp);
	sep(fp);
	fprintf(fp, "%jd", (intmax_t)val);
	if (comma) fputc(',', fp);
	nl(fp);
}

static void
json_kv_uint(FILE *fp, int depth, const char *key, uint64_t val, bool comma)
{
	indent(fp, depth);
	json_escape(key, fp);
	sep(fp);
	fprintf(fp, "%ju", (uintmax_t)val);
	if (comma) fputc(',', fp);
	nl(fp);
}

static void
json_kv_bool(FILE *fp, int depth, const char *key, bool val, bool comma)
{
	indent(fp, depth);
	json_escape(key, fp);
	sep(fp);
	fputs(val ? "true" : "false", fp);
	if (comma) fputc(',', fp);
	nl(fp);
}

static void
obj_open(FILE *fp, int depth, const char *key, bool is_array)
{
	indent(fp, depth);
	if (key != NULL) {
		json_escape(key, fp);
		sep(fp);
	}
	fputc(is_array ? '[' : '{', fp);
	nl(fp);
}

static void
obj_close(FILE *fp, int depth, bool is_array, bool comma)
{
	indent(fp, depth);
	fputc(is_array ? ']' : '}', fp);
	if (comma) fputc(',', fp);
	nl(fp);
}

static const char *
abi_name(uint8_t abi)
{
	switch (abi) {
	case EP_ABI_FREEBSD: return "freebsd";
	case EP_ABI_LINUX:   return "linux";
	default:             return "unknown";
	}
}

/*
 * Emit process info as JSON object.
 * msg is needed to resolve string table offsets.
 */
static void
emit_process(FILE *fp, int depth, const char *key, const oes_message_t *msg,
    const oes_process_t *proc, bool comma)
{

	obj_open(fp, depth, key, false);

	/* Token (for muting correlation and pid-reuse detection) */
	json_kv_uint(fp, depth + 1, "token_id", proc->ep_token.ept_id, true);
	json_kv_uint(fp, depth + 1, "token_genid", proc->ep_token.ept_genid, true);
	json_kv_uint(fp, depth + 1, "exec_id", proc->ep_exec_id, true);

	/* IDs */
	json_kv_int(fp, depth + 1, "pid", proc->ep_pid, true);
	json_kv_int(fp, depth + 1, "ppid", proc->ep_ppid, true);
	json_kv_str(fp, depth + 1, "pcomm", proc->ep_pcomm, true);
	json_kv_int(fp, depth + 1, "pgid", proc->ep_pgid, true);
	json_kv_int(fp, depth + 1, "sid", proc->ep_sid, true);

	/* Credentials */
	json_kv_int(fp, depth + 1, "uid", proc->ep_uid, true);
	json_kv_int(fp, depth + 1, "ruid", proc->ep_ruid, true);
	json_kv_int(fp, depth + 1, "suid", proc->ep_suid, true);
	json_kv_int(fp, depth + 1, "gid", proc->ep_gid, true);
	json_kv_int(fp, depth + 1, "rgid", proc->ep_rgid, true);
	json_kv_int(fp, depth + 1, "sgid", proc->ep_sgid, true);

	/* ABI */
	json_kv_int(fp, depth + 1, "abi", proc->ep_abi, true);
	json_kv_str(fp, depth + 1, "abi_name", abi_name(proc->ep_abi), true);

	/* Timing */
	json_kv_int(fp, depth + 1, "start_sec", proc->ep_start_sec, true);
	json_kv_int(fp, depth + 1, "start_usec", proc->ep_start_usec, true);

	/* Supplementary groups (array holds up to 16, ngroups may be higher) */
	json_kv_int(fp, depth + 1, "ngroups", proc->ep_ngroups, true);
	if (proc->ep_ngroups > 0) {
		int gi;
		int n = proc->ep_ngroups < 16 ? proc->ep_ngroups : 16;

		obj_open(fp, depth + 1, "groups", true);
		for (gi = 0; gi < n; gi++) {
			indent(fp, depth + 2);
			fprintf(fp, "%d", proc->ep_groups[gi]);
			if (gi + 1 < n)
				fputc(',', fp);
			nl(fp);
		}
		obj_close(fp, depth + 1, true, true);
	}

	/* Audit info */
	json_kv_int(fp, depth + 1, "auid", proc->ep_auid, true);
	json_kv_uint(fp, depth + 1, "asid", proc->ep_asid, true);

	/* Jail */
	json_kv_int(fp, depth + 1, "jid", proc->ep_jid, true);
	if (proc->ep_jid > 0)
		json_kv_str(fp, depth + 1, "jailname",
		    oes_msg_string(msg, proc->ep_jailname_off), true);

	/* Names and paths */
	json_kv_str(fp, depth + 1, "comm", proc->ep_comm, true);
	json_kv_str(fp, depth + 1, "path",
	    oes_msg_string(msg, proc->ep_path_off), true);
	json_kv_str(fp, depth + 1, "cwd",
	    oes_msg_string(msg, proc->ep_cwd_off), true);
	json_kv_str(fp, depth + 1, "tty", proc->ep_tty, true);
	json_kv_str(fp, depth + 1, "login", proc->ep_login, true);
	json_kv_bool(fp, depth + 1, "path_unavailable",
	    (proc->ep_meta_flags & OES_PROC_META_PATH_UNAVAILABLE) != 0, true);

	/* All flags */
	json_kv_bool(fp, depth + 1, "setuid",
	    (proc->ep_flags & EP_FLAG_SETUID) != 0, true);
	json_kv_bool(fp, depth + 1, "setgid",
	    (proc->ep_flags & EP_FLAG_SETGID) != 0, true);
	json_kv_bool(fp, depth + 1, "jailed",
	    (proc->ep_flags & EP_FLAG_JAILED) != 0, true);
	json_kv_bool(fp, depth + 1, "capmode",
	    (proc->ep_flags & EP_FLAG_CAPMODE) != 0, true);
	json_kv_bool(fp, depth + 1, "traced",
	    (proc->ep_flags & EP_FLAG_TRACED) != 0, true);
	json_kv_bool(fp, depth + 1, "system",
	    (proc->ep_flags & EP_FLAG_SYSTEM) != 0, true);
	json_kv_bool(fp, depth + 1, "exiting",
	    (proc->ep_flags & EP_FLAG_WEXIT) != 0, true);
	json_kv_bool(fp, depth + 1, "did_exec",
	    (proc->ep_flags & EP_FLAG_EXEC) != 0, true);
	json_kv_bool(fp, depth + 1, "has_ctty",
	    (proc->ep_flags & EP_FLAG_CONTROLT) != 0, true);
	json_kv_bool(fp, depth + 1, "linux",
	    (proc->ep_flags & EP_FLAG_LINUX) != 0, false);

	obj_close(fp, depth, false, comma);
}

/*
 * Emit file info as JSON object
 */
static void
emit_file(FILE *fp, int depth, const char *key, const oes_message_t *msg,
    const oes_file_t *file, bool comma)
{
	const char *type_name;

	switch (file->ef_type) {
	case EF_TYPE_REG:  type_name = "file"; break;
	case EF_TYPE_DIR:  type_name = "directory"; break;
	case EF_TYPE_LNK:  type_name = "symlink"; break;
	case EF_TYPE_CHR:  type_name = "chardev"; break;
	case EF_TYPE_BLK:  type_name = "blockdev"; break;
	case EF_TYPE_FIFO: type_name = "fifo"; break;
	case EF_TYPE_SOCK: type_name = "socket"; break;
	default:           type_name = "unknown"; break;
	}

	obj_open(fp, depth, key, false);

	/* Token (for cache/muting correlation) */
	json_kv_uint(fp, depth + 1, "token_id", file->ef_token.eft_id, true);
	json_kv_uint(fp, depth + 1, "token_dev", file->ef_token.eft_dev, true);

	/* Identity */
	json_kv_str(fp, depth + 1, "path",
	    oes_msg_string(msg, file->ef_path_off), true);
	json_kv_str(fp, depth + 1, "type", type_name, true);
	json_kv_uint(fp, depth + 1, "ino", file->ef_ino, true);
	json_kv_uint(fp, depth + 1, "dev", file->ef_dev, true);
	json_kv_bool(fp, depth + 1, "path_unavailable",
	    (file->ef_meta_flags & OES_FILE_META_PATH_UNAVAILABLE) != 0, true);
	json_kv_bool(fp, depth + 1, "path_requested",
	    (file->ef_meta_flags & OES_FILE_META_PATH_REQUESTED) != 0, true);

	/* Size */
	json_kv_uint(fp, depth + 1, "size", file->ef_size, true);
	json_kv_uint(fp, depth + 1, "blocks", file->ef_blocks, true);

	/* Ownership and permissions */
	json_kv_int(fp, depth + 1, "uid", file->ef_uid, true);
	json_kv_int(fp, depth + 1, "gid", file->ef_gid, true);
	json_kv_uint(fp, depth + 1, "mode", file->ef_mode, true);
	{
		char obuf[16];
		snprintf(obuf, sizeof(obuf), "%07o", file->ef_mode);
		json_kv_str(fp, depth + 1, "mode_octal", obuf, true);
	}
	json_kv_uint(fp, depth + 1, "flags", file->ef_flags, true);
	json_kv_uint(fp, depth + 1, "nlink", file->ef_nlink, true);

	/* Timestamps */
	json_kv_int(fp, depth + 1, "atime", file->ef_atime, true);
	json_kv_int(fp, depth + 1, "mtime", file->ef_mtime, true);
	json_kv_int(fp, depth + 1, "ctime", file->ef_ctime, true);
	json_kv_int(fp, depth + 1, "birthtime", file->ef_birthtime, true);

	/* Filesystem */
	json_kv_str(fp, depth + 1, "fstype", file->ef_fstype, false);

	obj_close(fp, depth, false, comma);
}

/*
 * Emit a socket address
 */
static void
emit_sockaddr(FILE *fp, int depth, const char *key,
    const oes_sockaddr_t *addr, bool comma)
{
	char addrbuf[INET6_ADDRSTRLEN];

	obj_open(fp, depth, key, false);
	json_kv_int(fp, depth + 1, "family", addr->esa_family, true);

	switch (addr->esa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &addr->esa_addr.v4,
		    addrbuf, sizeof(addrbuf));
		json_kv_str(fp, depth + 1, "address", addrbuf, true);
		json_kv_int(fp, depth + 1, "port",
		    ntohs(addr->esa_port), false);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, addr->esa_addr.v6,
		    addrbuf, sizeof(addrbuf));
		json_kv_str(fp, depth + 1, "address", addrbuf, true);
		json_kv_int(fp, depth + 1, "port",
		    ntohs(addr->esa_port), false);
		break;
	case AF_UNIX:
		json_kv_str(fp, depth + 1, "path",
		    addr->esa_addr.path, false);
		break;
	default:
		json_kv_int(fp, depth + 1, "raw_family",
		    addr->esa_family, false);
		break;
	}
	obj_close(fp, depth, false, comma);
}

/*
 * Emit event-specific data.
 *
 * Dispatch by exact event type to avoid offset collisions between
 * AUTH and NOTIFY enums (e.g., NOTIFY_EXIT=0x1002 vs AUTH_OPEN=0x0002
 * would both be base 0x0002).
 */
static void
emit_event_data(FILE *fp, int depth, const oes_message_t *msg)
{
	oes_event_type_t ev = msg->em_event;

	switch (ev) {
	/* --- EXEC --- */
	case OES_EVENT_AUTH_EXEC:
	case OES_EVENT_NOTIFY_EXEC:
		obj_open(fp, depth, "event_data", false);
		emit_process(fp, depth + 1, "target", msg,
		    &msg->em_event_data.exec.target, true);
		emit_file(fp, depth + 1, "executable", msg,
		    &msg->em_event_data.exec.executable, true);
		json_kv_int(fp, depth + 1, "argc",
		    msg->em_event_data.exec.argc, true);
		json_kv_int(fp, depth + 1, "envc",
		    msg->em_event_data.exec.envc, true);
		json_kv_uint(fp, depth + 1, "argv_len",
		    msg->em_event_data.exec.argv_len, true);
		json_kv_uint(fp, depth + 1, "envp_len",
		    msg->em_event_data.exec.envp_len, true);
		json_kv_bool(fp, depth + 1, "argv_truncated",
		    (msg->em_event_data.exec.flags & EE_FLAG_ARGV_TRUNCATED) != 0, true);
		json_kv_bool(fp, depth + 1, "envp_truncated",
		    (msg->em_event_data.exec.flags & EE_FLAG_ENVP_TRUNCATED) != 0, true);

		/*
		 * Always emit both argv and envp arrays (empty if no data)
		 * to avoid trailing comma issues with conditional blocks.
		 * Use json_escape_n for bounded access into the args buffer.
		 */
		{
			uint32_t argv_off = msg->em_event_data.exec.argv_off;
			uint32_t argv_len = msg->em_event_data.exec.argv_len;
			uint32_t envp_off = msg->em_event_data.exec.envp_off;
			uint32_t envp_len = msg->em_event_data.exec.envp_len;
			const char *argv_data = (argv_off > 0 &&
			    argv_off + argv_len <= msg->em_size) ?
			    (const char *)msg + argv_off : NULL;
			const char *envp_data = (envp_off > 0 &&
			    envp_off + envp_len <= msg->em_size) ?
			    (const char *)msg + envp_off : NULL;

			obj_open(fp, depth + 1, "argv", true);
			if (argv_data != NULL && argv_len > 0) {
				const char *p = argv_data;
				const char *end = p + argv_len;
				size_t slen;

				while (p < end) {
					slen = strnlen(p, (size_t)(end - p));
					indent(fp, depth + 2);
					json_escape_n(p, slen, fp);
					p += slen + 1;
					if (p < end) fputc(',', fp);
					nl(fp);
				}
			}
			obj_close(fp, depth + 1, true, true);

			obj_open(fp, depth + 1, "envp", true);
			if (envp_data != NULL && envp_len > 0) {
				const char *p = envp_data;
				const char *end = p + envp_len;
				size_t slen;

				while (p < end) {
					slen = strnlen(p, (size_t)(end - p));
					indent(fp, depth + 2);
					json_escape_n(p, slen, fp);
					p += slen + 1;
					if (p < end) fputc(',', fp);
					nl(fp);
				}
			}
			obj_close(fp, depth + 1, true, false);
		}

		obj_close(fp, depth, false, false);
		break;

	/* --- OPEN --- */
	case OES_EVENT_AUTH_OPEN:
	case OES_EVENT_NOTIFY_OPEN:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.open.file, true);
		json_kv_int(fp, depth + 1, "flags",
		    msg->em_event_data.open.flags, true);
		json_kv_uint(fp, depth + 1, "mode",
		    msg->em_event_data.open.mode, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- CREATE --- */
	case OES_EVENT_AUTH_CREATE:
	case OES_EVENT_NOTIFY_CREATE:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.create.dir, true);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.create.file, true);
		json_kv_uint(fp, depth + 1, "mode",
		    msg->em_event_data.create.mode, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- UNLINK --- */
	case OES_EVENT_AUTH_UNLINK:
	case OES_EVENT_NOTIFY_UNLINK:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.unlink.dir, true);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.unlink.file, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- RENAME --- */
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_NOTIFY_RENAME:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "src_dir", msg,
		    &msg->em_event_data.rename.src_dir, true);
		emit_file(fp, depth + 1, "src_file", msg,
		    &msg->em_event_data.rename.src_file, true);
		emit_file(fp, depth + 1, "dst_dir", msg,
		    &msg->em_event_data.rename.dst_dir, true);
		json_kv_str(fp, depth + 1, "dst_name",
		    oes_msg_string(msg, msg->em_event_data.rename.dst_name_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	/* --- LINK --- */
	case OES_EVENT_AUTH_LINK:
	case OES_EVENT_NOTIFY_LINK:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "target", msg,
		    &msg->em_event_data.link.target, true);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.link.dir, true);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.link.name_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	/* --- MOUNT --- */
	case OES_EVENT_AUTH_MOUNT:
	case OES_EVENT_NOTIFY_MOUNT:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "mountpoint", msg,
		    &msg->em_event_data.mount.mountpoint, true);
		json_kv_str(fp, depth + 1, "fstype",
		    msg->em_event_data.mount.fstype, true);
		json_kv_str(fp, depth + 1, "source",
		    oes_msg_string(msg, msg->em_event_data.mount.source_off),
		    true);
		json_kv_uint(fp, depth + 1, "flags",
		    msg->em_event_data.mount.flags, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- KLDLOAD --- */
	case OES_EVENT_AUTH_KLDLOAD:
	case OES_EVENT_NOTIFY_KLDLOAD:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.kldload.file, true);
		json_kv_str(fp, depth + 1, "name",
		    msg->em_event_data.kldload.name, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- MMAP --- */
	case OES_EVENT_AUTH_MMAP:
	case OES_EVENT_NOTIFY_MMAP:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.mmap.file, true);
		json_kv_uint(fp, depth + 1, "addr",
		    msg->em_event_data.mmap.addr, true);
		json_kv_uint(fp, depth + 1, "len",
		    msg->em_event_data.mmap.len, true);
		json_kv_int(fp, depth + 1, "prot",
		    msg->em_event_data.mmap.prot, true);
		json_kv_int(fp, depth + 1, "flags",
		    msg->em_event_data.mmap.flags, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- MPROTECT --- */
	case OES_EVENT_AUTH_MPROTECT:
	case OES_EVENT_NOTIFY_MPROTECT:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.mprotect.file, true);
		json_kv_int(fp, depth + 1, "prot",
		    msg->em_event_data.mprotect.prot, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- CHDIR --- */
	case OES_EVENT_AUTH_CHDIR:
	case OES_EVENT_NOTIFY_CHDIR:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.chdir.dir, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- CHROOT --- */
	case OES_EVENT_AUTH_CHROOT:
	case OES_EVENT_NOTIFY_CHROOT:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.chroot.dir, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SETEXTATTR --- */
	case OES_EVENT_AUTH_SETEXTATTR:
	case OES_EVENT_NOTIFY_SETEXTATTR:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.setextattr.file, true);
		json_kv_int(fp, depth + 1, "namespace",
		    msg->em_event_data.setextattr.attrnamespace, true);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.setextattr.name_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	/* --- PTRACE --- */
	case OES_EVENT_AUTH_PTRACE:
	case OES_EVENT_NOTIFY_PTRACE:
		obj_open(fp, depth, "event_data", false);
		emit_process(fp, depth + 1, "target", msg,
		    &msg->em_event_data.ptrace.target, true);
		json_kv_int(fp, depth + 1, "request",
		    msg->em_event_data.ptrace.request, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- ACCESS --- */
	case OES_EVENT_AUTH_ACCESS:
	case OES_EVENT_NOTIFY_ACCESS:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.access.file, true);
		json_kv_int(fp, depth + 1, "accmode",
		    msg->em_event_data.access.accmode, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- READ / WRITE --- */
	case OES_EVENT_AUTH_READ:
	case OES_EVENT_NOTIFY_READ:
	case OES_EVENT_AUTH_WRITE:
	case OES_EVENT_NOTIFY_WRITE:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.rw.file, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- LOOKUP --- */
	case OES_EVENT_AUTH_LOOKUP:
	case OES_EVENT_NOTIFY_LOOKUP:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.lookup.dir, true);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.lookup.name_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SETMODE --- */
	case OES_EVENT_AUTH_SETMODE:
	case OES_EVENT_NOTIFY_SETMODE:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.setmode.file, true);
		json_kv_uint(fp, depth + 1, "mode",
		    msg->em_event_data.setmode.mode, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SETOWNER --- */
	case OES_EVENT_AUTH_SETOWNER:
	case OES_EVENT_NOTIFY_SETOWNER:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.setowner.file, true);
		json_kv_int(fp, depth + 1, "uid",
		    msg->em_event_data.setowner.uid, true);
		json_kv_int(fp, depth + 1, "gid",
		    msg->em_event_data.setowner.gid, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SETFLAGS --- */
	case OES_EVENT_AUTH_SETFLAGS:
	case OES_EVENT_NOTIFY_SETFLAGS:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.setflags.file, true);
		json_kv_uint(fp, depth + 1, "flags",
		    msg->em_event_data.setflags.flags, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SETUTIMES --- */
	case OES_EVENT_AUTH_SETUTIMES:
	case OES_EVENT_NOTIFY_SETUTIMES:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.setutimes.file, true);
		json_kv_int(fp, depth + 1, "atime_sec",
		    msg->em_event_data.setutimes.atime.tv_sec, true);
		json_kv_int(fp, depth + 1, "atime_nsec",
		    msg->em_event_data.setutimes.atime.tv_nsec, true);
		json_kv_int(fp, depth + 1, "mtime_sec",
		    msg->em_event_data.setutimes.mtime.tv_sec, true);
		json_kv_int(fp, depth + 1, "mtime_nsec",
		    msg->em_event_data.setutimes.mtime.tv_nsec, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- STAT / POLL / REVOKE / READLINK / RELABEL (simple file events) --- */
	case OES_EVENT_AUTH_STAT:
	case OES_EVENT_NOTIFY_STAT:
	case OES_EVENT_AUTH_POLL:
	case OES_EVENT_NOTIFY_POLL:
	case OES_EVENT_AUTH_REVOKE:
	case OES_EVENT_NOTIFY_REVOKE:
	case OES_EVENT_AUTH_READLINK:
	case OES_EVENT_NOTIFY_READLINK:
	case OES_EVENT_AUTH_RELABEL:
	case OES_EVENT_NOTIFY_RELABEL:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.stat.file, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- READDIR --- */
	case OES_EVENT_AUTH_READDIR:
	case OES_EVENT_NOTIFY_READDIR:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "dir", msg,
		    &msg->em_event_data.readdir.dir, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- GETEXTATTR / DELETEEXTATTR / LISTEXTATTR --- */
	case OES_EVENT_AUTH_GETEXTATTR:
	case OES_EVENT_NOTIFY_GETEXTATTR:
	case OES_EVENT_AUTH_DELETEEXTATTR:
	case OES_EVENT_NOTIFY_DELETEEXTATTR:
	case OES_EVENT_AUTH_LISTEXTATTR:
	case OES_EVENT_NOTIFY_LISTEXTATTR:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.getextattr.file, true);
		json_kv_int(fp, depth + 1, "namespace",
		    msg->em_event_data.getextattr.attrnamespace, true);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.getextattr.name_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	/* --- GETACL / SETACL / DELETEACL --- */
	case OES_EVENT_AUTH_GETACL:
	case OES_EVENT_NOTIFY_GETACL:
	case OES_EVENT_AUTH_SETACL:
	case OES_EVENT_NOTIFY_SETACL:
	case OES_EVENT_AUTH_DELETEACL:
	case OES_EVENT_NOTIFY_DELETEACL:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.getacl.file, true);
		json_kv_int(fp, depth + 1, "acl_type",
		    msg->em_event_data.getacl.type, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SWAPON --- */
	case OES_EVENT_AUTH_SWAPON:
	case OES_EVENT_NOTIFY_SWAPON:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.swapon.file, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- SWAPOFF --- */
	case OES_EVENT_AUTH_SWAPOFF:
	case OES_EVENT_NOTIFY_SWAPOFF:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.swapoff.file, false);
		obj_close(fp, depth, false, false);
		break;

	/* --- NOTIFY-only events below (no AUTH equivalent) --- */

	case OES_EVENT_NOTIFY_EXIT:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "status",
		    msg->em_event_data.exit.status, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_FORK:
		obj_open(fp, depth, "event_data", false);
		emit_process(fp, depth + 1, "child", msg,
		    &msg->em_event_data.fork.child, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SIGNAL:
		obj_open(fp, depth, "event_data", false);
		emit_process(fp, depth + 1, "target", msg,
		    &msg->em_event_data.signal.target, true);
		json_kv_int(fp, depth + 1, "signum",
		    msg->em_event_data.signal.signum, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SETUID:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "uid",
		    msg->em_event_data.setuid.uid, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SETGID:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "gid",
		    msg->em_event_data.setgid.gid, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SOCKET_CONNECT:
	case OES_EVENT_NOTIFY_SOCKET_BIND:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "domain",
		    msg->em_event_data.socket_connect.socket.es_domain, true);
		json_kv_int(fp, depth + 1, "type",
		    msg->em_event_data.socket_connect.socket.es_type, true);
		json_kv_int(fp, depth + 1, "protocol",
		    msg->em_event_data.socket_connect.socket.es_protocol, true);
		emit_sockaddr(fp, depth + 1, "address",
		    &msg->em_event_data.socket_connect.address, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SOCKET_LISTEN:
	case OES_EVENT_NOTIFY_SOCKET_ACCEPT:
	case OES_EVENT_NOTIFY_SOCKET_SEND:
	case OES_EVENT_NOTIFY_SOCKET_RECEIVE:
	case OES_EVENT_NOTIFY_SOCKET_STAT:
	case OES_EVENT_NOTIFY_SOCKET_POLL:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "domain",
		    msg->em_event_data.socket_listen.socket.es_domain, true);
		json_kv_int(fp, depth + 1, "type",
		    msg->em_event_data.socket_listen.socket.es_type, true);
		json_kv_int(fp, depth + 1, "protocol",
		    msg->em_event_data.socket_listen.socket.es_protocol, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SOCKET_CREATE:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "domain",
		    msg->em_event_data.socket_create.domain, true);
		json_kv_int(fp, depth + 1, "type",
		    msg->em_event_data.socket_create.type, true);
		json_kv_int(fp, depth + 1, "protocol",
		    msg->em_event_data.socket_create.protocol, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_SYSCTL:
		obj_open(fp, depth, "event_data", false);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.sysctl.name_off),
		    true);
		json_kv_int(fp, depth + 1, "op",
		    msg->em_event_data.sysctl.op, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_KENV:
		obj_open(fp, depth, "event_data", false);
		json_kv_str(fp, depth + 1, "name",
		    oes_msg_string(msg, msg->em_event_data.kenv.name_off),
		    true);
		json_kv_int(fp, depth + 1, "op",
		    msg->em_event_data.kenv.op, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_REBOOT:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "howto",
		    msg->em_event_data.reboot.howto, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_UNMOUNT:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "mountpoint", msg,
		    &msg->em_event_data.unmount.mountpoint, true);
		json_kv_str(fp, depth + 1, "fstype",
		    msg->em_event_data.unmount.fstype, true);
		json_kv_str(fp, depth + 1, "source",
		    oes_msg_string(msg, msg->em_event_data.unmount.source_off),
		    true);
		json_kv_uint(fp, depth + 1, "flags",
		    msg->em_event_data.unmount.flags, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_KLDUNLOAD:
		obj_open(fp, depth, "event_data", false);
		emit_file(fp, depth + 1, "file", msg,
		    &msg->em_event_data.kldunload.file, true);
		json_kv_str(fp, depth + 1, "name",
		    msg->em_event_data.kldunload.name, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_PIPE_READ:
	case OES_EVENT_NOTIFY_PIPE_WRITE:
	case OES_EVENT_NOTIFY_PIPE_STAT:
	case OES_EVENT_NOTIFY_PIPE_POLL:
	case OES_EVENT_NOTIFY_PIPE_IOCTL:
		obj_open(fp, depth, "event_data", false);
		json_kv_uint(fp, depth + 1, "pipe_id",
		    msg->em_event_data.pipe.pipe_id, true);
		json_kv_uint(fp, depth + 1, "ioctl_cmd",
		    msg->em_event_data.pipe.ioctl_cmd, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_MOUNT_STAT:
		obj_open(fp, depth, "event_data", false);
		json_kv_str(fp, depth + 1, "fstype",
		    msg->em_event_data.mount_stat.fstype, true);
		json_kv_str(fp, depth + 1, "fspath",
		    oes_msg_string(msg, msg->em_event_data.mount_stat.fspath_off),
		    false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_PRIV_CHECK:
		obj_open(fp, depth, "event_data", false);
		json_kv_int(fp, depth + 1, "priv",
		    msg->em_event_data.priv.priv, false);
		obj_close(fp, depth, false, false);
		break;

	case OES_EVENT_NOTIFY_PROC_SCHED:
		obj_open(fp, depth, "event_data", false);
		emit_process(fp, depth + 1, "target", msg,
		    &msg->em_event_data.proc_sched.target, false);
		obj_close(fp, depth, false, false);
		break;

	default:
		/* Unknown event -- emit type number for debugging */
		obj_open(fp, depth, "event_data", false);
		json_kv_uint(fp, depth + 1, "raw_event_type", ev, false);
		obj_close(fp, depth, false, false);
		break;
	}
}

static oes_event_type_t
lookup_event(const char *name)
{
#define OES_EVENT_NAME_CASE(short_name, notify_event) \
	if (strcasecmp((short_name), name) == 0) return (notify_event);
	OES_NOTIFY_EVENT_NAME_LIST(OES_EVENT_NAME_CASE)
#undef OES_EVENT_NAME_CASE
	return (0);
}

static void
list_events(void)
{
	fprintf(stderr, "Available event names:\n");
#define OES_EVENT_NAME_CASE(short_name, notify_event) \
	fprintf(stderr, "  %s\n", (short_name));
	OES_NOTIFY_EVENT_NAME_LIST(OES_EVENT_NAME_CASE)
#undef OES_EVENT_NAME_CASE
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: oeslogger [-p] [-o file] [event_type ...]\n"
	    "  -o file  Write JSON output to file (default: stdout)\n"
	    "  -p       Pretty-print JSON output\n"
	    "  -l       List available event names\n"
	    "\n"
	    "With no event names, subscribes to all NOTIFY events.\n"
	    "Event names: exec, open, create, unlink, fork, exit, etc.\n"
	    "\n"
	    "Examples:\n"
	    "  oeslogger                        # All events to stdout\n"
	    "  oeslogger -o /var/log/oes.ndjson  # Log to file\n"
	    "  oeslogger -p exec fork exit       # Pretty-print selected events\n"
	    "  oeslogger exec open | jq .        # Pipe NDJSON to jq\n");
	exit(EX_USAGE);
}

/*
 * Check if an event type has an AUTH variant (can block operations).
 *
 * AUTH events are trivially auth_capable. For NOTIFY events, we check
 * if the corresponding AUTH event exists. NOTIFY-only events (exit, fork,
 * signal, setuid, setgid, all socket/pipe/reboot/sysctl/kenv/mount_stat/
 * priv_check/proc_sched) return false.
 */
static bool
event_has_auth(oes_event_type_t ev)
{

	if (OES_EVENT_IS_AUTH(ev))
		return (true);

#define OES_EVENT_AUTH_CASE(auth_event, notify_event) case notify_event: return (true);
	switch (ev) {
	OES_AUTH_NOTIFY_EVENT_LIST(OES_EVENT_AUTH_CASE)
	default:
		return (false);
	}
#undef OES_EVENT_AUTH_CASE
}

/*
 * Main event handler callback
 */
static bool
handle_event(oes_client_t *client __unused, const oes_message_t *msg,
    void *ctx __unused)
{
	struct timespec ts;
	FILE *fp = outfp;
	int d = pretty ? 1 : 0;

	if (!running)
		return (false);

	clock_gettime(CLOCK_REALTIME, &ts);

	obj_open(fp, 0, NULL, false);
	json_kv_str(fp, d, "event_type",
	    oes_event_name(msg->em_event), true);
	json_kv_uint(fp, d, "event_type_raw", msg->em_event, true);
	json_kv_uint(fp, d, "msg_id", msg->em_id, true);
	json_kv_str(fp, d, "action",
	    msg->em_action == OES_ACTION_AUTH ? "auth" : "notify", true);

	/*
	 * Indicate whether this event type has an AUTH variant.
	 * Useful for passive/notify observers to know which events
	 * could block operations when an AUTH client is present.
	 */
	json_kv_bool(fp, d, "auth_capable",
	    event_has_auth(msg->em_event), true);

	json_kv_uint(fp, d, "version", msg->em_version, true);
	json_kv_bool(fp, d, "strings_truncated",
	    (msg->em_flags & OES_MSG_FLAG_STRINGS_TRUNCATED) != 0, true);
	json_kv_bool(fp, d, "path_unavailable",
	    (msg->em_flags & OES_MSG_FLAG_PATH_UNAVAILABLE) != 0, true);

	/* Wall-clock timestamp for log correlation */
	{
		char tbuf[64];
		struct tm tm;
		time_t sec = ts.tv_sec;

		gmtime_r(&sec, &tm);
		snprintf(tbuf, sizeof(tbuf),
		    "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
		    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		    tm.tm_hour, tm.tm_min, tm.tm_sec,
		    ts.tv_nsec / 1000);
		json_kv_str(fp, d, "timestamp", tbuf, true);
	}

	/* Monotonic event time from kernel */
	json_kv_int(fp, d, "event_time_sec",
	    msg->em_time.tv_sec, true);
	json_kv_int(fp, d, "event_time_nsec",
	    msg->em_time.tv_nsec, true);

	/* AUTH deadline (non-zero for AUTH events) */
	if (msg->em_deadline.tv_sec != 0 || msg->em_deadline.tv_nsec != 0) {
		json_kv_int(fp, d, "deadline_sec",
		    msg->em_deadline.tv_sec, true);
		json_kv_int(fp, d, "deadline_nsec",
		    msg->em_deadline.tv_nsec, true);
	}

	emit_process(fp, d, "process", msg, &msg->em_process, true);
	emit_event_data(fp, d, msg);

	obj_close(fp, 0, false, false);
	if (!pretty)
		fputc('\n', fp);
	fflush(fp);

	return (running != 0);
}

int
main(int argc, char *argv[])
{
	oes_client_t *client;
	oes_event_type_t events[128];
	size_t nevents = 0;
	const char *outpath = NULL;
	int ch, i;

	while ((ch = getopt(argc, argv, "hlo:p")) != -1) {
		switch (ch) {
		case 'o':
			outpath = optarg;
			break;
		case 'p':
			pretty = true;
			break;
		case 'l':
			list_events();
			exit(0);
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Open output file or default to stdout */
	if (outpath != NULL) {
		outfp = fopen(outpath, "a");
		if (outfp == NULL)
			err(EX_CANTCREAT, "%s", outpath);
	} else {
		outfp = stdout;
	}

	/* Parse event names from remaining arguments */
	for (i = 0; i < argc; i++) {
		oes_event_type_t ev = lookup_event(argv[i]);
		if (ev == 0) {
			fprintf(stderr, "oeslogger: unknown event: %s\n",
			    argv[i]);
			list_events();
			exit(EX_USAGE);
		}
		if (nevents < nitems(events))
			events[nevents++] = ev;
	}

	/* Create client */
	client = oes_client_create();
	if (client == NULL)
		err(EX_OSERR, "oes_client_create (are you root?)");

	/*
	 * Always use NOTIFY mode. oeslogger is a passive observer --
	 * it never blocks operations. AUTH events are delivered as their
	 * NOTIFY equivalents; the auth_capable field in the JSON output
	 * indicates whether an AUTH client could block the operation.
	 */
	if (oes_set_mode(client, OES_MODE_NOTIFY, 0, 0) < 0)
		err(EX_OSERR, "oes_set_mode");

	if (nevents > 0) {
		if (oes_subscribe(client, events, nevents, OES_SUB_REPLACE) < 0)
			err(EX_OSERR, "oes_subscribe");
	} else {
		/* No specific events requested -- subscribe to everything */
		if (oes_subscribe_all(client, false, true) < 0)
			err(EX_OSERR, "oes_subscribe_all");
	}

	/* Mute ourselves to avoid feedback loops */
	if (oes_mute_self(client) < 0)
		err(EX_OSERR, "oes_mute_self");

	/* Mute noisy paths by default */
	oes_mute_path(client, "/dev/", OES_MUTE_PATH_PREFIX);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, SIG_IGN);

	/* Line-buffered output for piping */
	setvbuf(outfp, NULL, _IOLBF, 0);

	fprintf(stderr, "oeslogger: listening for events (Ctrl-C to stop)\n");
	if (outpath != NULL)
		fprintf(stderr, "oeslogger: writing to %s\n", outpath);

	/* Run the event loop */
	if (oes_dispatch(client, handle_event, NULL) < 0 && running)
		err(EX_OSERR, "oes_dispatch");

	oes_client_destroy(client);

	/* Flush and close output file */
	if (outfp != stdout) {
		fflush(outfp);
		fclose(outfp);
	}

	return (0);
}
