/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Output formatting — text and JSON record renderers.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/hwt.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void
print_timestamp(void)
{
	struct timespec ts;
	struct tm tm;

	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	printf("%02d:%02d:%02d.%06ld",
	    tm.tm_hour, tm.tm_min, tm.tm_sec,
	    ts.tv_nsec / 1000);
}

/*
 * JSON-escape a string into a caller-supplied buffer (no quotes).
 * Returns the number of bytes written (excluding NUL).
 *
 * Bytes >= 0x80 are escaped as \u00XX (latin-1 semantics): this is
 * lossy for UTF-8 input, but always produces valid JSON even for
 * hostile ELF symbol names or paths containing arbitrary bytes.
 * Worst case output is 6 bytes per input byte; on a too-small buffer
 * the output is truncated at a character boundary (an escape sequence
 * is never split), so the result is always a valid JSON string body.
 */
int
json_escape(char *dst, size_t dstlen, const char *src)
{
	size_t pos = 0;

	for (; *src != '\0' && pos + 7 < dstlen; src++) {
		unsigned char c = (unsigned char)*src;

		switch (c) {
		case '"':  dst[pos++] = '\\'; dst[pos++] = '"'; break;
		case '\\': dst[pos++] = '\\'; dst[pos++] = '\\'; break;
		case '\b': dst[pos++] = '\\'; dst[pos++] = 'b'; break;
		case '\f': dst[pos++] = '\\'; dst[pos++] = 'f'; break;
		case '\n': dst[pos++] = '\\'; dst[pos++] = 'n'; break;
		case '\r': dst[pos++] = '\\'; dst[pos++] = 'r'; break;
		case '\t': dst[pos++] = '\\'; dst[pos++] = 't'; break;
		default:
			if (c < 0x20 || c >= 0x80)
				pos += snprintf(dst + pos, dstlen - pos,
				    "\\u%04x", c);
			else
				dst[pos++] = c;
			break;
		}
	}
	dst[pos] = '\0';
	return ((int)pos);
}

static const char *
record_type_name(enum hwt_record_type t)
{

	switch (t) {
	case HWT_RECORD_MMAP:		return ("mmap");
	case HWT_RECORD_MUNMAP:		return ("munmap");
	case HWT_RECORD_EXECUTABLE:	return ("executable");
	case HWT_RECORD_KERNEL:		return ("kernel");
	case HWT_RECORD_THREAD_CREATE:	return ("thread_create");
	case HWT_RECORD_THREAD_SET_NAME: return ("thread_set_name");
	case HWT_RECORD_BUFFER:		return ("buffer");
	case HWT_RECORD_OVERFLOW:	return ("overflow");
	default:			return ("unknown");
	}
}

/* ------------------------------------------------------------------ */
/* Text output                                                         */
/* ------------------------------------------------------------------ */

void
fmt_record_text(const struct bsdtrace_record *rec, pid_t pid)
{

	print_timestamp();

	switch (rec->type) {
	case HWT_RECORD_EXECUTABLE:
		printf("  EXEC  pid=%d  %s  addr=0x%lx  base=0x%lx\n",
		    (int)pid,
		    rec->fullpath[0] ? rec->fullpath : "<unknown>",
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;

	case HWT_RECORD_MMAP:
		printf("  MMAP  pid=%d  %s  addr=0x%lx  base=0x%lx\n",
		    (int)pid,
		    rec->fullpath[0] ? rec->fullpath : "<anon>",
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;

	case HWT_RECORD_MUNMAP:
		printf("  MUNMAP  pid=%d", (int)pid);
		if (rec->addr != 0)
			printf("  addr=0x%lx", (unsigned long)rec->addr);
		putchar('\n');
		break;

	case HWT_RECORD_KERNEL:
		printf("  KERNEL  %s  addr=0x%lx  base=0x%lx\n",
		    rec->fullpath[0] ? rec->fullpath : "<kernel>",
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;

	case HWT_RECORD_THREAD_CREATE:
		printf("  THREAD_CREATE  pid=%d  tid=%d\n",
		    (int)pid, rec->thread_id);
		break;

	case HWT_RECORD_THREAD_SET_NAME:
		printf("  THREAD_NAME  pid=%d  tid=%d\n",
		    (int)pid, rec->thread_id);
		break;

	case HWT_RECORD_BUFFER:
		printf("  BUFFER  buf_id=%d  page=%d  offset=0x%lx\n",
		    rec->buf_id, rec->curpage,
		    (unsigned long)rec->offset);
		break;

	case HWT_RECORD_OVERFLOW:
		printf("  OVERFLOW  pid=%d  buf_id=%d  page=%d  offset=0x%lx\n",
		    (int)pid, rec->buf_id, rec->curpage,
		    (unsigned long)rec->offset);
		break;

	default:
		printf("  UNKNOWN  type=%d\n", rec->type);
		break;
	}
}

/* ------------------------------------------------------------------ */
/* JSON output                                                         */
/* ------------------------------------------------------------------ */

void
fmt_record_json(const struct bsdtrace_record *rec, pid_t pid)
{
	/*
	 * json_escape emits at most 6 bytes per input byte, so size for
	 * a full MAXPATHLEN path plus fixed field overhead — no
	 * truncation is possible below.
	 */
	char line[MAXPATHLEN * 6 + 256];
	char escaped[MAXPATHLEN * 6 + 1];
	struct timespec ts;
	struct tm tm;
	int pos;

	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);

	pos = snprintf(line, sizeof(line),
	    "{\"timestamp\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\""
	    ",\"kind\":\"%s\",\"pid\":%d",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec,
	    record_type_name(rec->type), (int)pid);

	switch (rec->type) {
	case HWT_RECORD_MMAP:
	case HWT_RECORD_EXECUTABLE:
	case HWT_RECORD_KERNEL:
		if (rec->fullpath[0]) {
			json_escape(escaped, sizeof(escaped),
			    rec->fullpath);
			pos += snprintf(line + pos, sizeof(line) - pos,
			    ",\"path\":\"%s\"", escaped);
		}
		pos += snprintf(line + pos, sizeof(line) - pos,
		    ",\"address\":\"0x%lx\""
		    ",\"base_address\":\"0x%lx\"",
		    (unsigned long)rec->addr,
		    (unsigned long)rec->baseaddr);
		break;

	case HWT_RECORD_MUNMAP:
		if (rec->addr != 0)
			pos += snprintf(line + pos, sizeof(line) - pos,
			    ",\"address\":\"0x%lx\"",
			    (unsigned long)rec->addr);
		break;

	case HWT_RECORD_THREAD_CREATE:
	case HWT_RECORD_THREAD_SET_NAME:
		pos += snprintf(line + pos, sizeof(line) - pos,
		    ",\"thread_id\":%d", rec->thread_id);
		break;

	case HWT_RECORD_BUFFER:
		pos += snprintf(line + pos, sizeof(line) - pos,
		    ",\"buf_id\":%d,\"page\":%d,\"offset\":%lu",
		    rec->buf_id, rec->curpage,
		    (unsigned long)rec->offset);
		break;

	case HWT_RECORD_OVERFLOW:
		pos += snprintf(line + pos, sizeof(line) - pos,
		    ",\"buf_id\":%d,\"page\":%d,\"offset\":%lu",
		    rec->buf_id, rec->curpage,
		    (unsigned long)rec->offset);
		break;

	default:
		break;
	}

	snprintf(line + pos, sizeof(line) - pos, "}\n");
	fputs(line, stdout);
}
