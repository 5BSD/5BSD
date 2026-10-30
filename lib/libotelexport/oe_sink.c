/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Output sink shared by the file-writing exporters.  A sink is either
 * a borrowed stdio stream (stdout by default) or a file the sink owns.
 * Owned files can rotate by size and/or age to numbered siblings
 * (path.1 is the newest rotated file, path.N the oldest kept) and can
 * be made durable: every flush, rotation and close fsyncs the file,
 * and rotations also fsync the containing directory.
 *
 * Records are written whole: rotation happens only between records,
 * so a reader never sees a JSON line split across two files.  The
 * first write error is sticky and reported once with the path and
 * errno text; later writes fail fast instead of flooding stderr.
 *
 * External rotation ("follow").  A file rotated by another program,
 * newsyslog(8), is renamed away and replaced by a new file under the
 * same name.  A following sink keeps writing whole records to the file
 * it has open (the rotated one) and reopens the path:
 *
 *  - before the next write after oe_sink_reopen_request(), which a
 *    SIGHUP handler calls (newsyslog signals the writer once the new
 *    file exists, and waits before compressing the old one);
 *  - at a flush that finds the path naming another file.  A path that
 *    is missing is left alone for a few flushes, because newsyslog
 *    renames the old file away before it moves the new one into place:
 *    creating the file in that window would write records into a file
 *    newsyslog is about to replace.
 *
 * So no record is lost or split, with or without the signal.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "otelexport.h"

#define	SINK_DEFAULT_KEEP	7
#define	SINK_MAX_KEEP		999
#define	SINK_DEFAULT_MODE	0644
/* Flushes that find a following sink's path missing before it is created. */
#define	SINK_MISSING_FLUSHES	3

struct oe_sink {
	FILE		*fp;
	char		*path;		/* NULL: borrowed stream */
	char		*dir;		/* containing directory (durable) */
	uint64_t	 size;		/* bytes in the current file */
	uint64_t	 rotate_size;
	time_t		 rotate_interval;
	unsigned	 keep;
	int		 durable;
	int		 error;
	struct timespec	 opened;	/* CLOCK_MONOTONIC */
	mode_t		 mode;		/* of a created file */
	int		 follow;	/* reopen after external rotation */
	unsigned	 missing;	/* flushes that found no file at path */
	sig_atomic_t	 reopen_seen;	/* reopen requests handled */
	dev_t		 dev;		/* the open file */
	ino_t		 ino;
};

/* Reopen requests (SIGHUP); compared against each sink's reopen_seen. */
static volatile sig_atomic_t reopen_requests;

void
oe_sink_reopen_request(void)
{

	reopen_requests++;
}

/*
 * Report the first failure.  Every caller runs only while no error is
 * recorded (the entry points check it), so this is reached once.
 */
static void
sink_fail(struct oe_sink *s, const char *what, int error)
{

	fprintf(stderr, "otelexport: %s: %s failed: %s\n",
	    s->path != NULL ? s->path : "<stream>", what, strerror(error));
	s->error = 1;
}

static int
sink_open_file(struct oe_sink *s)
{
	struct stat st;
	int fd;

	fd = open(s->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, s->mode);
	if (fd < 0) {
		sink_fail(s, "open", errno);
		return (-1);
	}
	if (fstat(fd, &st) != 0) {
		sink_fail(s, "fstat", errno);
		close(fd);
		return (-1);
	}
	if (!S_ISREG(st.st_mode)) {
		/*
		 * Rotation renames the file, so only regular files make
		 * sense; a FIFO or device would also defeat fsync.
		 */
		sink_fail(s, "open", EFTYPE);
		close(fd);
		return (-1);
	}
	s->fp = fdopen(fd, "a");
	if (s->fp == NULL) {
		sink_fail(s, "fdopen", errno);
		close(fd);
		return (-1);
	}
	s->size = (uint64_t)st.st_size;
	s->dev = st.st_dev;
	s->ino = st.st_ino;
	s->missing = 0;
	clock_gettime(CLOCK_MONOTONIC, &s->opened);
	return (0);
}

/* fflush plus, for durable owned files, fsync. */
static int
sink_sync(struct oe_sink *s)
{

	if (fflush(s->fp) != 0) {
		sink_fail(s, "write", errno);
		return (-1);
	}
	if (s->durable && s->path != NULL && fsync(fileno(s->fp)) != 0) {
		sink_fail(s, "fsync", errno);
		return (-1);
	}
	return (0);
}

static void
sync_dir(struct oe_sink *s)
{
	int fd;

	fd = open(s->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd >= 0) {
		(void)fsync(fd);
		close(fd);
	}
}

static int
sink_rotate(struct oe_sink *s)
{
	char from[PATH_MAX], to[PATH_MAX];
	unsigned i;

	if (sink_sync(s) != 0)
		return (-1);
	if (fclose(s->fp) != 0) {
		s->fp = NULL;
		sink_fail(s, "close", errno);
		return (-1);
	}
	s->fp = NULL;
	/* Drop the oldest, shift the rest up by one, then move path. */
	snprintf(to, sizeof(to), "%s.%u", s->path, s->keep);
	if (unlink(to) != 0 && errno != ENOENT) {
		sink_fail(s, "rotate", errno);
		return (-1);
	}
	for (i = s->keep; i > 1; i--) {
		snprintf(from, sizeof(from), "%s.%u", s->path, i - 1);
		snprintf(to, sizeof(to), "%s.%u", s->path, i);
		if (rename(from, to) != 0 && errno != ENOENT) {
			sink_fail(s, "rotate", errno);
			return (-1);
		}
	}
	snprintf(to, sizeof(to), "%s.1", s->path);
	if (rename(s->path, to) != 0) {
		sink_fail(s, "rotate", errno);
		return (-1);
	}
	if (s->durable)
		sync_dir(s);
	return (sink_open_file(s));
}

/*
 * Close the open file (after syncing it) and open path again: a new
 * file when the old one was rotated away.
 */
static int
sink_reopen(struct oe_sink *s)
{

	if (sink_sync(s) != 0)
		return (-1);
	if (fclose(s->fp) != 0) {
		s->fp = NULL;
		sink_fail(s, "close", errno);
		return (-1);
	}
	s->fp = NULL;
	if (sink_open_file(s) != 0)
		return (-1);
	/* The new file's directory entry is durable too. */
	if (s->durable)
		sync_dir(s);
	return (0);
}

/* A reopen request (SIGHUP) this sink has not acted on yet? */
static int
sink_reopen_due(struct oe_sink *s)
{
	sig_atomic_t req;

	if (!s->follow)
		return (0);
	req = reopen_requests;
	if (req == s->reopen_seen)
		return (0);
	s->reopen_seen = req;
	return (1);
}

/*
 * After external rotation: does path still name the open file?  A
 * missing path counts as rotated only after SINK_MISSING_FLUSHES
 * flushes (see the comment at the top).
 */
static int
sink_rotated_away(struct oe_sink *s)
{
	struct stat st;

	if (stat(s->path, &st) != 0) {
		if (errno != ENOENT)
			return (0);	/* undecidable: keep writing */
		return (++s->missing >= SINK_MISSING_FLUSHES);
	}
	s->missing = 0;
	return (st.st_dev != s->dev || st.st_ino != s->ino);
}

int
oe_sink_reopen(struct oe_sink *s)
{

	if (s->error)
		return (-1);
	if (s->path == NULL)
		return (0);
	return (sink_reopen(s));
}

static int
sink_interval_due(const struct oe_sink *s)
{
	struct timespec now;

	/* Only owned files rotate; callers check s->path first. */
	if (s->rotate_interval <= 0)
		return (0);
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - s->opened.tv_sec >= s->rotate_interval);
}

struct oe_sink *
oe_sink_open(const struct oe_sink_config *cfg)
{
	struct oe_sink *s;
	char *slash;

	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		fprintf(stderr, "otelexport: out of memory\n");
		return (NULL);
	}
	s->durable = cfg->durable;
	s->mode = cfg->mode != 0 ? cfg->mode : SINK_DEFAULT_MODE;
	s->follow = cfg->follow;
	s->reopen_seen = reopen_requests;
	s->rotate_size = cfg->rotate_size;
	s->rotate_interval = cfg->rotate_interval;
	s->keep = cfg->rotate_keep != 0 ? cfg->rotate_keep :
	    SINK_DEFAULT_KEEP;
	if (s->keep > SINK_MAX_KEEP) {
		fprintf(stderr, "otelexport: rotation keeps at most %d "
		    "files\n", SINK_MAX_KEEP);
		free(s);
		return (NULL);
	}
	if (cfg->path == NULL || strcmp(cfg->path, "-") == 0) {
		/* Borrowed stream: never rotated, closed or fsynced. */
		s->fp = cfg->fp != NULL ? cfg->fp : stdout;
		return (s);
	}
	if (strlen(cfg->path) + 5 > PATH_MAX) {
		/* Leave room for the ".NNN" rotation suffix. */
		fprintf(stderr, "otelexport: %s: path too long\n", cfg->path);
		free(s);
		return (NULL);
	}
	s->path = strdup(cfg->path);
	s->dir = strdup(cfg->path);
	if (s->path == NULL || s->dir == NULL) {
		fprintf(stderr, "otelexport: out of memory\n");
		goto fail;
	}
	slash = strrchr(s->dir, '/');
	if (slash == NULL)
		strlcpy(s->dir, ".", strlen(s->dir) + 1);
	else if (slash == s->dir)
		slash[1] = '\0';
	else
		*slash = '\0';
	if (sink_open_file(s) != 0)
		goto fail;
	return (s);

fail:
	free(s->path);
	free(s->dir);
	free(s);
	return (NULL);
}

int
oe_sink_write(struct oe_sink *s, const void *data, size_t len)
{

	if (s->error)		/* also covers a failed rotation's NULL fp */
		return (-1);
	if (s->path != NULL && sink_reopen_due(s) && sink_reopen(s) != 0)
		return (-1);
	if (s->path != NULL && s->size > 0 && ((s->rotate_size > 0 &&
	    s->size + len > s->rotate_size) || sink_interval_due(s)) &&
	    sink_rotate(s) != 0)
		return (-1);
	if (len > 0 && fwrite(data, 1, len, s->fp) != len) {
		sink_fail(s, "write", errno);
		return (-1);
	}
	s->size += len;
	return (0);
}

int
oe_sink_poll(struct oe_sink *s)
{
	struct stat st;

	if (s->error)		/* also covers a failed rotation's NULL fp */
		return (-1);
	if (s->path == NULL)
		return (0);
	/*
	 * A writer that bypasses oe_sink_write (libdtrace's own text
	 * output) grows the file behind our back; resynchronize the
	 * size from the file before deciding.
	 */
	if (fflush(s->fp) != 0) {
		sink_fail(s, "write", errno);
		return (-1);
	}
	(void)fstat(fileno(s->fp), &st);	/* an open descriptor */
	s->size = (uint64_t)st.st_size;
	if (s->size > 0 && ((s->rotate_size > 0 &&
	    s->size >= s->rotate_size) || sink_interval_due(s)))
		return (sink_rotate(s));
	return (0);
}

int
oe_sink_flush(struct oe_sink *s)
{

	if (s->error)		/* also covers a failed rotation's NULL fp */
		return (-1);
	if (sink_sync(s) != 0)
		return (-1);
	if (s->path != NULL && s->follow &&
	    (sink_reopen_due(s) || sink_rotated_away(s)))
		return (sink_reopen(s));
	return (0);
}

FILE *
oe_sink_stream(struct oe_sink *s)
{

	return (s->fp);
}

const char *
oe_sink_path(const struct oe_sink *s)
{

	return (s->path);
}

int
oe_sink_close(struct oe_sink *s)
{
	int ret;

	if (s == NULL)
		return (0);
	ret = s->error ? -1 : 0;
	if (s->fp != NULL && !s->error && sink_sync(s) != 0)
		ret = -1;
	if (s->path != NULL && s->fp != NULL && fclose(s->fp) != 0 &&
	    ret == 0) {
		sink_fail(s, "close", errno);
		ret = -1;
	}
	free(s->path);
	free(s->dir);
	free(s);
	return (ret);
}
