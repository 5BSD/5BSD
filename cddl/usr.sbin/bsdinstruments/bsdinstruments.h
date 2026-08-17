/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdinstruments — DTrace-backed profiling templates with
 * OpenTelemetry output.  C port of the ObservableBSD Swift tool.
 */

#ifndef _BSDINSTRUMENTS_H_
#define	_BSDINSTRUMENTS_H_

#include <sys/types.h>

#include <stdio.h>

#define	BSDINSTRUMENTS_VERSION	"0.1.0"

/* Profile sources, in increasing shadowing precedence. */
enum profile_origin {
	ORIGIN_BASE = 0,	/* /usr/share/bsdinstruments/profiles */
	ORIGIN_SYSTEM,		/* /usr/local/share/bsdinstruments/profiles */
	ORIGIN_USER,		/* ~/.bsdinstruments/profiles */
	ORIGIN_EXPLICIT		/* -f /path/to/script.d */
};

struct profile {
	char		*name;		/* filename minus .d */
	char		*descr;		/* first block-comment line */
	char		*source;	/* raw D source */
	enum profile_origin origin;
	struct profile	*next;
};

struct profile_list {
	struct profile	*head;
	size_t		 count;
};

/* CLI filter flags shared by watch and generate. */
struct filter_opts {
	int		 have_pid;
	pid_t		 pid;
	const char	*execname;
	int		 have_uid;
	uid_t		 uid;
	int		 have_gid;
	gid_t		 gid;
	int		 have_jail;
	int		 jail;
	const char	*where;
};

/* --param key=value pairs. */
struct param {
	const char	*name;
	const char	*value;
};

struct render_opts {
	const struct param *params;
	size_t		 nparams;
	const char	*predicate;	/* "/.../" or "" */
	const char	*predicate_and;	/* " && ..." or "" */
	int		 with_stack;
	int		 with_ustack;
	double		 duration;	/* <= 0: none */
};

const char *profile_origin_name(enum profile_origin);

/* profile.c */
void	 profile_list_load(struct profile_list *);
void	 profile_list_free(struct profile_list *);
struct profile *profile_lookup(const struct profile_list *, const char *);
struct profile *profile_load_file(const char *path);
void	 profile_free(struct profile *);
/*
 * Render to a malloc'd D source string; NULL on error with a
 * message on stderr (e.g. an unsatisfied ${param}).
 */
char	*profile_render(const struct profile *, const struct render_opts *);
/* Resolve a profile by catalog name or explicit -f path. */
struct profile *profile_resolve(const char *name, const char *file);

/* filter.c */
char	*filter_predicate(const struct filter_opts *);	   /* "/.../" or "" */
char	*filter_predicate_and(const struct filter_opts *); /* " && .." or "" */

/* watch.c */
enum watch_format {
	FORMAT_TEXT,
	FORMAT_JSON,
	FORMAT_OTEL,
	FORMAT_COLLAPSED
};

struct watch_opts {
	enum watch_format format;
	const char	*endpoint;
	const char	*bufsize;	/* NULL: default */
	const char	*switchrate;	/* NULL: default */
	int		 with_stack;
	int		 with_ustack;
};

int	 watch_run(const struct profile *, const char *rendered,
	    const struct watch_opts *);

/* subcommands */
int	 cmd_list(int argc, char **argv);
int	 cmd_watch(int argc, char **argv);
int	 cmd_generate(int argc, char **argv);
int	 cmd_probes(int argc, char **argv);

#endif /* !_BSDINSTRUMENTS_H_ */
