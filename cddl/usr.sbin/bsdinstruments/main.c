/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdinstruments — DTrace-backed profiling templates with
 * OpenTelemetry output.  Subcommand dispatch plus the list, watch,
 * and generate implementations (probes lives in probes.c).
 */

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"
#include "bsdinstruments.h"

static void __dead2
usage(void)
{

	fprintf(stderr,
	    "usage: bsdinstruments <subcommand> [args]\n"
	    "\n"
	    "Subcommands:\n"
	    "  list      List every profile bsdinstruments knows about.\n"
	    "  watch     Run a profile and stream its events.\n"
	    "  generate  Render a profile to D source without running it.\n"
	    "  probes    List DTrace probes available on this system.\n"
	    "\n"
	    "See bsdinstruments(8) or `bsdinstruments <subcommand> -h` for "
	    "details.\n");
	exit(2);
}

/* ---------------------------------------------------------------- */
/* bsdinstruments list						 	*/

static void
list_usage(void)
{

	fprintf(stderr,
	    "usage: bsdinstruments list [--json]\n"
	    "\n"
	    "Profiles load from /usr/share/bsdinstruments/profiles (base),\n"
	    "/usr/local/share/bsdinstruments/profiles (ports), and\n"
	    "~/.bsdinstruments/profiles (user).  User overrides ports\n"
	    "overrides base, with a stderr warning when shadowing "
	    "happens.\n");
	exit(2);
}

static int
profile_cmp(const void *a, const void *b)
{
	const struct profile *pa = *(const struct profile * const *)a;
	const struct profile *pb = *(const struct profile * const *)b;

	return (strcmp(pa->name, pb->name));
}

int
cmd_list(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "json", no_argument, NULL, 'j' },
		{ NULL, 0, NULL, 0 }
	};
	struct profile_list list;
	struct profile *p, **sorted;
	struct oe_buf b;
	size_t i, n, namewidth;
	int ch, json;

	json = 0;
	while ((ch = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (ch) {
		case 'j':
			json = 1;
			break;
		default:
			list_usage();
		}
	}
	if (optind != argc)
		list_usage();

	profile_list_load(&list);
	sorted = malloc(list.count * sizeof(*sorted));
	if (sorted == NULL)
		err(1, "malloc");
	n = 0;
	for (p = list.head; p != NULL; p = p->next)
		sorted[n++] = p;
	qsort(sorted, n, sizeof(*sorted), profile_cmp);

	if (json) {
		for (i = 0; i < n; i++) {
			oe_buf_init(&b);
			oe_buf_appendstr(&b, "{\"description\":\"");
			oe_buf_appendjson(&b, sorted[i]->descr);
			oe_buf_appendstr(&b, "\",\"name\":\"");
			oe_buf_appendjson(&b, sorted[i]->name);
			oe_buf_appendstr(&b, "\",\"origin\":\"");
			oe_buf_appendjson(&b,
			    profile_origin_name(sorted[i]->origin));
			oe_buf_appendstr(&b, "\"}");
			printf("%s\n", b.data != NULL ? b.data : "{}");
			oe_buf_free(&b);
		}
	} else if (n == 0) {
		printf("(no profiles found — the base, ports, and user "
		    "profile directories are all empty)\n");
	} else {
		namewidth = 4;
		for (i = 0; i < n; i++)
			if (strlen(sorted[i]->name) > namewidth)
				namewidth = strlen(sorted[i]->name);
		printf("%-*s  %-8s  %s\n", (int)namewidth, "NAME", "ORIGIN",
		    "DESCRIPTION");
		for (i = 0; i < namewidth + 25; i++)
			printf("-");
		printf("\n");
		for (i = 0; i < n; i++)
			printf("%-*s  %-8s  %s\n", (int)namewidth,
			    sorted[i]->name,
			    profile_origin_name(sorted[i]->origin),
			    sorted[i]->descr);
		printf("\n%zu profile%s\n", n, n == 1 ? "" : "s");
	}

	free(sorted);
	profile_list_free(&list);
	return (0);
}

/* ---------------------------------------------------------------- */
/* Shared option parsing for watch and generate			 	*/

struct common_args {
	const char	*profile;
	const char	*file;
	struct param	*params;
	size_t		 nparams;
	struct filter_opts filter;
	double		 duration;
	int		 with_stack;
	int		 with_ustack;
	/* watch only */
	enum watch_format format;
	const char	*endpoint;
	const char	*bufsize;
	const char	*switchrate;
};

enum {
	OPT_PARAM = 1000,
	OPT_PID,
	OPT_EXECNAME,
	OPT_UID,
	OPT_GID,
	OPT_JAIL,
	OPT_WHERE,
	OPT_DURATION,
	OPT_WITH_STACK,
	OPT_WITH_USTACK,
	OPT_FORMAT,
	OPT_ENDPOINT,
	OPT_BUFSIZE,
	OPT_SWITCHRATE
};

static const struct option watch_opts[] = {
	{ "param", required_argument, NULL, OPT_PARAM },
	{ "pid", required_argument, NULL, OPT_PID },
	{ "execname", required_argument, NULL, OPT_EXECNAME },
	{ "uid", required_argument, NULL, OPT_UID },
	{ "gid", required_argument, NULL, OPT_GID },
	{ "jail", required_argument, NULL, OPT_JAIL },
	{ "where", required_argument, NULL, OPT_WHERE },
	{ "duration", required_argument, NULL, OPT_DURATION },
	{ "with-stack", no_argument, NULL, OPT_WITH_STACK },
	{ "with-ustack", no_argument, NULL, OPT_WITH_USTACK },
	{ "format", required_argument, NULL, OPT_FORMAT },
	{ "endpoint", required_argument, NULL, OPT_ENDPOINT },
	{ "bufsize", required_argument, NULL, OPT_BUFSIZE },
	{ "switchrate", required_argument, NULL, OPT_SWITCHRATE },
	{ NULL, 0, NULL, 0 }
};

/*
 * strtoll with full validation: rejects garbage, trailing junk, and
 * out-of-range values with a usage error.
 */
static long long
parse_num(const char *arg, const char *what, long long lo, long long hi)
{
	long long v;
	char *end;

	errno = 0;
	v = strtoll(arg, &end, 10);
	if (end == arg || *end != '\0' || errno == ERANGE || v < lo ||
	    v > hi)
		errx(2, "%s expects an integer between %lld and %lld, "
		    "got '%s'", what, lo, hi, arg);
	return (v);
}

static void
add_param(struct common_args *ca, char *arg)
{
	char *eq;

	size_t i;

	eq = strchr(arg, '=');
	if (eq == NULL)
		errx(2, "--param expects key=value, got '%s'", arg);
	*eq = '\0';
	/* Repeated keys: the last occurrence wins (CLI convention). */
	for (i = 0; i < ca->nparams; i++) {
		if (strcmp(ca->params[i].name, arg) == 0) {
			ca->params[i].value = eq + 1;
			return;
		}
	}
	ca->params = reallocf(ca->params,
	    (ca->nparams + 1) * sizeof(*ca->params));
	if (ca->params == NULL)
		err(1, "malloc");
	ca->params[ca->nparams].name = arg;
	ca->params[ca->nparams].value = eq + 1;
	ca->nparams++;
}

static int
parse_common(int argc, char **argv, struct common_args *ca, int is_watch,
    void (*usage_fn)(void))
{
	int ch;

	memset(ca, 0, sizeof(*ca));
	ca->format = FORMAT_TEXT;
	ca->endpoint = "http://localhost:4318";

	while ((ch = getopt_long(argc, argv, "f:h", watch_opts,
	    NULL)) != -1) {
		switch (ch) {
		case 'f':
			ca->file = optarg;
			break;
		case OPT_PARAM:
			add_param(ca, optarg);
			break;
		case OPT_PID:
			ca->filter.have_pid = 1;
			ca->filter.pid =
			    (pid_t)parse_num(optarg, "--pid", 0, INT_MAX);
			break;
		case OPT_EXECNAME:
			ca->filter.execname = optarg;
			break;
		case OPT_UID:
			ca->filter.have_uid = 1;
			ca->filter.uid =
			    (uid_t)parse_num(optarg, "--uid", 0,
			    (long long)UINT_MAX);
			break;
		case OPT_GID:
			ca->filter.have_gid = 1;
			ca->filter.gid =
			    (gid_t)parse_num(optarg, "--gid", 0,
			    (long long)UINT_MAX);
			break;
		case OPT_JAIL:
			ca->filter.have_jail = 1;
			ca->filter.jail =
			    (int)parse_num(optarg, "--jail", 0, INT_MAX);
			break;
		case OPT_WHERE:
			ca->filter.where = optarg;
			break;
		case OPT_DURATION: {
			char *dend;

			ca->duration = strtod(optarg, &dend);
			/*
			 * Finite + capped: the render pipeline converts
			 * to nanoseconds in intmax_t, and inf/NaN or
			 * huge values would make that conversion UB.
			 */
			if (dend == optarg || *dend != '\0' ||
			    !isfinite(ca->duration) || ca->duration <= 0 ||
			    ca->duration > 1e8)
				errx(2, "--duration must be a positive "
				    "number of seconds (max 1e8)");
			break;
		}
		case OPT_WITH_STACK:
			ca->with_stack = 1;
			break;
		case OPT_WITH_USTACK:
			ca->with_ustack = 1;
			break;
		case OPT_FORMAT:
			if (!is_watch)
				usage_fn();
			if (strcmp(optarg, "text") == 0)
				ca->format = FORMAT_TEXT;
			else if (strcmp(optarg, "json") == 0)
				ca->format = FORMAT_JSON;
			else if (strcmp(optarg, "otel") == 0)
				ca->format = FORMAT_OTEL;
			else if (strcmp(optarg, "collapsed") == 0)
				ca->format = FORMAT_COLLAPSED;
			else
				errx(2, "--format must be text, json, otel, "
				    "or collapsed");
			break;
		case OPT_ENDPOINT:
		case OPT_BUFSIZE:
		case OPT_SWITCHRATE:
			if (!is_watch)
				usage_fn();
			if (ch == OPT_ENDPOINT)
				ca->endpoint = optarg;
			else if (ch == OPT_BUFSIZE)
				ca->bufsize = optarg;
			else
				ca->switchrate = optarg;
			break;
		default:
			usage_fn();
		}
	}
	if (optind < argc)
		ca->profile = argv[optind++];
	if (optind != argc)
		usage_fn();

	if (ca->profile == NULL && ca->file == NULL)
		errx(2, "provide a profile name or -f /path/to/script.d");
	if (ca->profile != NULL && ca->file != NULL)
		errx(2, "pass either a profile name or -f, not both");
	return (0);
}

static char *
render_from_args(struct common_args *ca, struct profile **pp)
{
	struct render_opts ro;
	struct profile *p;
	char *predicate, *predicate_and, *rendered;

	p = profile_resolve(ca->profile, ca->file);
	if (p == NULL)
		return (NULL);
	predicate = filter_predicate(&ca->filter);
	predicate_and = filter_predicate_and(&ca->filter);
	memset(&ro, 0, sizeof(ro));
	ro.params = ca->params;
	ro.nparams = ca->nparams;
	ro.predicate = predicate;
	ro.predicate_and = predicate_and;
	ro.with_stack = ca->with_stack;
	ro.with_ustack = ca->with_ustack;
	ro.duration = ca->duration;
	rendered = profile_render(p, &ro);
	free(predicate);
	free(predicate_and);
	if (rendered == NULL) {
		profile_free(p);
		return (NULL);
	}
	*pp = p;
	return (rendered);
}

/* ---------------------------------------------------------------- */
/* bsdinstruments watch						 	*/

static void __dead2
watch_usage(void)
{

	fprintf(stderr,
	    "usage: bsdinstruments watch [profile | -f script.d]\n"
	    "           [--param key=value ...] [--pid n] [--execname name]\n"
	    "           [--uid n] [--gid n] [--jail jid] [--where predicate]\n"
	    "           [--duration seconds] [--with-stack] [--with-ustack]\n"
	    "           [--format text|json|otel|collapsed]\n"
	    "           [--endpoint url] [--bufsize size] "
	    "[--switchrate rate]\n");
	exit(2);
}

int
cmd_watch(int argc, char **argv)
{
	struct common_args ca;
	struct watch_opts wo;
	struct profile *p;
	char *rendered;
	int ret;

	parse_common(argc, argv, &ca, 1, watch_usage);
	if (ca.format == FORMAT_COLLAPSED && !ca.with_stack &&
	    !ca.with_ustack)
		errx(2, "--format collapsed requires --with-stack and/or "
		    "--with-ustack");

	rendered = render_from_args(&ca, &p);
	if (rendered == NULL)
		return (1);

	memset(&wo, 0, sizeof(wo));
	wo.format = ca.format;
	wo.endpoint = ca.endpoint;
	wo.bufsize = ca.bufsize;
	wo.switchrate = ca.switchrate;
	wo.with_stack = ca.with_stack;
	wo.with_ustack = ca.with_ustack;

	ret = watch_run(p, rendered, &wo);
	free(rendered);
	profile_free(p);
	free(ca.params);
	return (ret);
}

/* ---------------------------------------------------------------- */
/* bsdinstruments generate					 	*/

static void __dead2
generate_usage(void)
{

	fprintf(stderr,
	    "usage: bsdinstruments generate [profile | -f script.d]\n"
	    "           [--param key=value ...] [--pid n] [--execname name]\n"
	    "           [--uid n] [--gid n] [--jail jid] [--where predicate]\n"
	    "           [--duration seconds] [--with-stack] "
	    "[--with-ustack]\n");
	exit(2);
}

int
cmd_generate(int argc, char **argv)
{
	struct common_args ca;
	struct profile *p;
	char *rendered;

	parse_common(argc, argv, &ca, 0, generate_usage);
	rendered = render_from_args(&ca, &p);
	if (rendered == NULL)
		return (1);
	printf("%s\n", rendered);
	free(rendered);
	profile_free(p);
	free(ca.params);
	return (0);
}

/* ---------------------------------------------------------------- */

int
main(int argc, char **argv)
{

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "--version") == 0) {
		printf("%s\n", BSDINSTRUMENTS_VERSION);
		return (0);
	}
	argc--;
	argv++;
	if (strcmp(argv[0], "list") == 0)
		return (cmd_list(argc, argv));
	if (strcmp(argv[0], "watch") == 0)
		return (cmd_watch(argc, argv));
	if (strcmp(argv[0], "generate") == 0)
		return (cmd_generate(argc, argv));
	if (strcmp(argv[0], "probes") == 0)
		return (cmd_probes(argc, argv));
	usage();
}
