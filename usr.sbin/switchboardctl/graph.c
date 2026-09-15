/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboardctl graph: draw the IPC anointment reach graph from the bundle
 * registry on disk (docs/ipc-anointments-design.md, "Graph tool").  No
 * running plane is consulted.  Nodes are every unit plus the two session
 * classes the principal policy defines; an edge exists where the consumer's
 * anointment set covers the endpoint's `requires`, or the endpoint is open.
 */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "libcapbundle.h"
#include "switchboardctl.h"

#define	GRAPH_POLICY_PATH	"/Capabilities/Config/principal-policy.ucl"
#define	GRAPH_SESSION_DEFAULT	"session.default"
#define	GRAPH_SESSION_ADMIN	"session.admin"
#define	GRAPH_UID_DEFAULT	((uid_t)65534)	/* nobody */
#define	GRAPH_UID_ADMIN		((uid_t)0)

enum graph_format { GRAPH_TEXT, GRAPH_DOT, GRAPH_JSON };

typedef char graph_name_t[CAPBUNDLE_LABEL_MAX];
typedef const char *(*graph_name_get_fn)(const struct capbundle_service *,
    unsigned, unsigned);

/* A consumer: a unit from a bundle, or one of the two session classes. */
struct gnode {
	char	 label[CAPBUNDLE_LABEL_MAX];
	char	 bundle[CAPBUNDLE_LABEL_MAX];	/* bundle id; "" for sessions */
	graph_name_t *anoint;
	unsigned nanoint;
	bool	 anoint_all;			/* sessions only: policy "*" */
	bool	 user_resolvable;		/* units: resolvable_by user */
	bool	 is_session;
	bool	 admin_domain;			/* sessions: sees system names */
	bool	 admin_rights;
	bool	 from_default_rule;
	uid_t	 uid;
};

/* An endpoint published by a unit, with the names a consumer must hold. */
struct gendpoint {
	char	 name[CAPBUNDLE_LABEL_MAX];
	unsigned owner;				/* index into nodes */
	graph_name_t *requires;
	unsigned nrequires;
};

struct gedge {
	unsigned from;				/* node */
	unsigned to;				/* endpoint */
};

struct gwarning {
	char	 kind[16];			/* "unreachable" | "dead" */
	char	 subject[CAPBUNDLE_LABEL_MAX];	/* endpoint or unit */
	char	 name[CAPBUNDLE_LABEL_MAX];	/* the anointment */
	char	 text[256];
};

struct graph {
	struct gnode	*nodes;
	unsigned	 nnodes, cnodes;
	struct gendpoint *eps;
	unsigned	 neps, ceps;
	struct gedge	*edges;
	unsigned	 nedges, cedges;
	struct gwarning	*warnings;
	unsigned	 nwarnings, cwarnings;
};

static void *
grow(void *base, unsigned *cap, unsigned need, size_t elem)
{
	unsigned ncap;
	void *p;

	if (need <= *cap)
		return (base);
	ncap = *cap == 0 ? 16 : *cap * 2;
	while (ncap < need)
		ncap *= 2;
	p = reallocarray(base, ncap, elem);
	if (p == NULL)
		err(EX_OSERR, "reallocarray");
	*cap = ncap;
	return (p);
}

static graph_name_t *
copy_names(unsigned n, graph_name_get_fn get,
    const struct capbundle_service *svc, unsigned idx)
{
	graph_name_t *out;
	unsigned i;

	if (n == 0)
		return (NULL);
	out = reallocarray(NULL, n, sizeof(*out));
	if (out == NULL)
		err(EX_OSERR, "reallocarray");
	for (i = 0; i < n; i++)
		strlcpy(out[i], get(svc, idx, i), sizeof(out[i]));
	return (out);
}

static const char *
get_anointment(const struct capbundle_service *svc, unsigned idx __unused,
    unsigned i)
{
	return (capbundle_svc_anointment(svc, i));
}

static const char *
get_require(const struct capbundle_service *svc, unsigned idx, unsigned i)
{
	return (capbundle_svc_requires(svc, idx, i));
}

/* ---- registry scan -------------------------------------------------- */

static int
graph_scan_cb(struct capbundle *b, void *arg)
{
	struct graph *g = arg;
	unsigned i, p;

	for (i = 0; i < capbundle_nservices(b); i++) {
		const struct capbundle_service *svc = capbundle_service(b, i);
		struct gnode *n;
		unsigned self;

		g->nodes = grow(g->nodes, &g->cnodes, g->nnodes + 1,
		    sizeof(*g->nodes));
		self = g->nnodes++;
		n = &g->nodes[self];
		memset(n, 0, sizeof(*n));
		strlcpy(n->label, capbundle_svc_label(svc), sizeof(n->label));
		strlcpy(n->bundle, capbundle_id(b), sizeof(n->bundle));
		n->nanoint = capbundle_svc_nanointments(svc);
		n->anoint = copy_names(n->nanoint, get_anointment, svc, 0);
		n->user_resolvable = capbundle_svc_user_resolvable(svc);

		for (p = 0; p < capbundle_svc_nprovides(svc); p++) {
			struct gendpoint *e;

			g->eps = grow(g->eps, &g->ceps, g->neps + 1,
			    sizeof(*g->eps));
			e = &g->eps[g->neps++];
			memset(e, 0, sizeof(*e));
			strlcpy(e->name, capbundle_svc_provides(svc, p),
			    sizeof(e->name));
			e->owner = self;
			e->nrequires = capbundle_svc_nrequires(svc, p);
			e->requires = copy_names(e->nrequires, get_require,
			    svc, p);
		}
	}
	capbundle_close(b);
	return (0);
}

/*
 * Scan one registry directory.  A default registry directory that is absent
 * is simply empty; an explicit --root that is absent is a mistake.
 */
static int
graph_scan(struct graph *g, const char *dir, bool explicit)
{
	int rc;

	rc = capbundle_scan_dir(dir, graph_scan_cb, g);
	if (rc == -1) {
		if (!explicit && (errno == ENOENT || errno == ENOTDIR))
			return (0);
		warn("graph: scanning %s", dir);
		return (-1);
	}
	return (0);
}

/* ---- sessions -------------------------------------------------------- */

static gid_t
graph_name2gid(void *ctx __unused, const char *group_name)
{
	struct group *gr;

	gr = getgrnam(group_name);
	return (gr != NULL ? gr->gr_gid : (gid_t)-1);
}

static void
graph_add_session(struct graph *g, int policy_fd, const char *label, uid_t uid,
    bool admin_domain)
{
	struct capbundle_principal_grant grant;
	struct gnode *n;
	unsigned i;

	if (capbundle_principal_resolve(policy_fd, uid, NULL, 0,
	    graph_name2gid, NULL, &grant) != 0)
		err(EX_SOFTWARE, "capbundle_principal_resolve");

	g->nodes = grow(g->nodes, &g->cnodes, g->nnodes + 1, sizeof(*g->nodes));
	n = &g->nodes[g->nnodes++];
	memset(n, 0, sizeof(*n));
	strlcpy(n->label, label, sizeof(n->label));
	n->is_session = true;
	n->uid = uid;
	n->admin_domain = admin_domain;
	n->anoint_all = grant.anoint_all;
	n->admin_rights = grant.admin_rights;
	n->from_default_rule = grant.from_default_rule;
	n->nanoint = grant.nanointments;
	if (n->nanoint != 0) {
		n->anoint = reallocarray(NULL, n->nanoint, sizeof(*n->anoint));
		if (n->anoint == NULL)
			err(EX_OSERR, "reallocarray");
		for (i = 0; i < n->nanoint; i++)
			strlcpy(n->anoint[i], grant.anointments[i],
			    sizeof(n->anoint[i]));
	}
}

/* ---- reach ----------------------------------------------------------- */

static bool
node_holds(const struct gnode *n, const char *name)
{
	unsigned i;

	if (n->anoint_all)
		return (true);
	for (i = 0; i < n->nanoint; i++)
		if (strcmp(n->anoint[i], name) == 0)
			return (true);
	return (false);
}

static bool
node_covers(const struct gnode *n, const struct gendpoint *e)
{
	unsigned i;

	for (i = 0; i < e->nrequires; i++)
		if (!node_holds(n, e->requires[i]))
			return (false);
	return (true);
}

/*
 * The design's edge rule.  Open endpoints keep today's resolvable_by rule for
 * sessions: a default (user-domain) session only sees providers that opted
 * into user resolution, an admin (system-domain) session sees every name.  A
 * gated endpoint is visible to whoever covers it, regardless of resolvable_by.
 * Units see every open endpoint; a unit never reaches itself.
 */
static bool
graph_reaches(const struct graph *g, unsigned from, unsigned to)
{
	const struct gnode *n = &g->nodes[from];
	const struct gendpoint *e = &g->eps[to];

	if (!n->is_session && e->owner == from)
		return (false);
	if (e->nrequires == 0) {
		if (n->is_session && !n->admin_domain)
			return (g->nodes[e->owner].user_resolvable);
		return (true);
	}
	return (node_covers(n, e));
}

static void
graph_add_warning(struct graph *g, const char *kind, const char *subject,
    const char *name, const char *fmt, ...) __printflike(5, 6);

static void
graph_add_warning(struct graph *g, const char *kind, const char *subject,
    const char *name, const char *fmt, ...)
{
	struct gwarning *w;
	va_list ap;

	g->warnings = grow(g->warnings, &g->cwarnings, g->nwarnings + 1,
	    sizeof(*g->warnings));
	w = &g->warnings[g->nwarnings++];
	memset(w, 0, sizeof(*w));
	strlcpy(w->kind, kind, sizeof(w->kind));
	strlcpy(w->subject, subject, sizeof(w->subject));
	strlcpy(w->name, name, sizeof(w->name));
	va_start(ap, fmt);
	vsnprintf(w->text, sizeof(w->text), fmt, ap);
	va_end(ap);
}

/*
 * Whether any node lists `name` explicitly.  A session's "*" is deliberately
 * not a declaration: the lint asks whether anything on the system was
 * written to hold this name, and the admin wildcard says nothing about that.
 */
static bool
graph_name_declared(const struct graph *g, const char *name)
{
	unsigned i, j;

	for (i = 0; i < g->nnodes; i++)
		for (j = 0; j < g->nodes[i].nanoint; j++)
			if (strcmp(g->nodes[i].anoint[j], name) == 0)
				return (true);
	return (false);
}

static bool
graph_name_required(const struct graph *g, const char *name)
{
	unsigned i, j;

	for (i = 0; i < g->neps; i++)
		for (j = 0; j < g->eps[i].nrequires; j++)
			if (strcmp(g->eps[i].requires[j], name) == 0)
				return (true);
	return (false);
}

static void
graph_lint(struct graph *g)
{
	unsigned i, j;

	/* (a) a gated endpoint requiring a name nothing declares. */
	for (i = 0; i < g->neps; i++) {
		const struct gendpoint *e = &g->eps[i];
		bool undeclared = false, reached = false;

		for (j = 0; j < e->nrequires; j++) {
			if (graph_name_declared(g, e->requires[j]))
				continue;
			undeclared = true;
			graph_add_warning(g, "unreachable", e->name,
			    e->requires[j],
			    "unreachable: %s requires \"%s\", which no unit "
			    "or principal declares", e->name, e->requires[j]);
		}
		if (e->nrequires == 0 || undeclared)
			continue;
		/* Every name is declared somewhere; does one unit hold all? */
		for (j = 0; j < g->nnodes && !reached; j++)
			if (!g->nodes[j].is_session && g->eps[i].owner != j &&
			    node_covers(&g->nodes[j], e))
				reached = true;
		for (j = 0; j < g->nnodes && !reached; j++)
			if (g->nodes[j].is_session && !g->nodes[j].anoint_all &&
			    node_covers(&g->nodes[j], e))
				reached = true;
		if (!reached)
			graph_add_warning(g, "unreachable", e->name, "",
			    "unreachable: %s requires %u names that no single "
			    "unit or principal holds together", e->name,
			    e->nrequires);
	}

	/* (b) a declared name nothing requires. */
	for (i = 0; i < g->nnodes; i++) {
		const struct gnode *n = &g->nodes[i];

		for (j = 0; j < n->nanoint; j++) {
			if (graph_name_required(g, n->anoint[j]))
				continue;
			graph_add_warning(g, "dead", n->label, n->anoint[j],
			    "dead declaration: %s %s \"%s\", which no endpoint "
			    "requires", n->label,
			    n->is_session ? "is granted" : "declares",
			    n->anoint[j]);
		}
	}
}

/* ---- ordering (stable output for golden files) ----------------------- */

static int
node_cmp(const void *a, const void *b)
{
	const struct gnode *x = a, *y = b;

	/* Sessions first, then units by label, then by bundle. */
	if (x->is_session != y->is_session)
		return (x->is_session ? -1 : 1);
	if (strcmp(x->label, y->label) != 0)
		return (strcmp(x->label, y->label));
	return (strcmp(x->bundle, y->bundle));
}

static int
ep_cmp(const void *a, const void *b)
{
	const struct gendpoint *x = a, *y = b;

	if (strcmp(x->name, y->name) != 0)
		return (strcmp(x->name, y->name));
	return (x->owner < y->owner ? -1 : x->owner > y->owner);
}

static void
graph_sort(struct graph *g)
{
	unsigned *remap, i;

	/* Sort nodes and rewrite endpoint owners through the permutation. */
	remap = calloc(g->nnodes, sizeof(*remap));
	if (remap == NULL)
		err(EX_OSERR, "calloc");
	{
		struct gnode *sorted;
		unsigned *order;

		order = calloc(g->nnodes, sizeof(*order));
		sorted = calloc(g->nnodes, sizeof(*sorted));
		if (order == NULL || sorted == NULL)
			err(EX_OSERR, "calloc");
		for (i = 0; i < g->nnodes; i++)
			order[i] = i;
		/* Insertion sort on indices: n is small, keeps remap simple. */
		for (i = 1; i < g->nnodes; i++) {
			unsigned k = order[i], j = i;

			while (j > 0 &&
			    node_cmp(&g->nodes[order[j - 1]], &g->nodes[k]) > 0) {
				order[j] = order[j - 1];
				j--;
			}
			order[j] = k;
		}
		for (i = 0; i < g->nnodes; i++) {
			sorted[i] = g->nodes[order[i]];
			remap[order[i]] = i;
		}
		free(g->nodes);
		g->nodes = sorted;
		g->cnodes = g->nnodes;
		free(order);
	}
	for (i = 0; i < g->neps; i++)
		g->eps[i].owner = remap[g->eps[i].owner];
	free(remap);
	qsort(g->eps, g->neps, sizeof(*g->eps), ep_cmp);
}

static void
graph_build_edges(struct graph *g)
{
	unsigned i, j;

	for (i = 0; i < g->nnodes; i++)
		for (j = 0; j < g->neps; j++) {
			if (!graph_reaches(g, i, j))
				continue;
			g->edges = grow(g->edges, &g->cedges, g->nedges + 1,
			    sizeof(*g->edges));
			g->edges[g->nedges].from = i;
			g->edges[g->nedges].to = j;
			g->nedges++;
		}
}

/* ---- output ---------------------------------------------------------- */

static void
print_escaped(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s == '"' || *s == '\\')
			putchar('\\');
		putchar(*s);
	}
}

static void
print_requires_list(const struct gendpoint *e, const char *sep)
{
	unsigned i;

	for (i = 0; i < e->nrequires; i++)
		printf("%s%s", i == 0 ? "" : sep, e->requires[i]);
}

static void
graph_print_text(const struct graph *g, bool lint)
{
	unsigned i, gated = 0;

	for (i = 0; i < g->nedges; i++) {
		const struct gedge *ed = &g->edges[i];
		const struct gendpoint *e = &g->eps[ed->to];

		printf("%s -> %s [", g->nodes[ed->from].label, e->name);
		if (e->nrequires == 0)
			printf("open");
		else {
			printf("via ");
			print_requires_list(e, ",");
		}
		printf("]\n");
	}
	if (lint)
		for (i = 0; i < g->nwarnings; i++)
			printf("warning: %s\n", g->warnings[i].text);
	for (i = 0; i < g->neps; i++)
		if (g->eps[i].nrequires != 0)
			gated++;
	printf("summary: %u units, 2 sessions, %u endpoints (%u gated), "
	    "%u edges, %u warnings%s\n", g->nnodes - 2, g->neps, gated,
	    g->nedges, g->nwarnings,
	    g->nodes[0].from_default_rule ?
	    " (principal policy absent: historical rule)" : "");
}

static void
graph_print_dot(const struct graph *g)
{
	unsigned i;

	printf("digraph anointments {\n"
	    "\trankdir=LR;\n"
	    "\tnode [fontname=\"Helvetica\"];\n");
	for (i = 0; i < g->nnodes; i++) {
		const struct gnode *n = &g->nodes[i];
		unsigned j;

		printf("\t\"n%u\" [shape=%s, label=\"", i,
		    n->is_session ? "ellipse" : "box");
		print_escaped(n->label);
		if (!n->is_session) {
			printf("\\n(");
			print_escaped(n->bundle);
			printf(")");
		}
		if (n->anoint_all)
			printf("\\nholds *");
		for (j = 0; j < n->nanoint; j++) {
			printf(j == 0 ? "\\nholds " : ", ");
			print_escaped(n->anoint[j]);
		}
		printf("\"];\n");
	}
	for (i = 0; i < g->neps; i++) {
		const struct gendpoint *e = &g->eps[i];

		printf("\t\"e%u\" [shape=%s, label=\"", i,
		    e->nrequires == 0 ? "plaintext" : "note");
		print_escaped(e->name);
		if (e->nrequires != 0) {
			unsigned j;

			printf("\\nrequires ");
			for (j = 0; j < e->nrequires; j++) {
				printf("%s", j == 0 ? "" : ", ");
				print_escaped(e->requires[j]);
			}
		}
		printf("\"];\n");
		/* Provider owns its endpoint: dotted, unlabelled. */
		printf("\t\"n%u\" -> \"e%u\" [style=dotted, arrowhead=none];\n",
		    e->owner, i);
	}
	for (i = 0; i < g->nedges; i++) {
		const struct gedge *ed = &g->edges[i];
		const struct gendpoint *e = &g->eps[ed->to];

		printf("\t\"n%u\" -> \"e%u\"", ed->from, ed->to);
		if (e->nrequires == 0)
			printf(" [style=solid];\n");
		else {
			unsigned j;

			printf(" [style=solid, color=firebrick, label=\"");
			for (j = 0; j < e->nrequires; j++) {
				printf("%s", j == 0 ? "" : ", ");
				print_escaped(e->requires[j]);
			}
			printf("\"];\n");
		}
	}
	printf("}\n");
}

static void
json_string(const char *s)
{
	putchar('"');
	print_escaped(s);
	putchar('"');
}

static void
json_names(const graph_name_t *names, unsigned n)
{
	unsigned i;

	putchar('[');
	for (i = 0; i < n; i++) {
		if (i != 0)
			printf(", ");
		json_string(names[i]);
	}
	putchar(']');
}

static void
graph_print_json(const struct graph *g)
{
	unsigned i, first;

	printf("{\n  \"units\": [\n");
	first = 1;
	for (i = 0; i < g->nnodes; i++) {
		const struct gnode *n = &g->nodes[i];

		if (n->is_session)
			continue;
		printf("%s    {\"label\": ", first ? "" : ",\n");
		first = 0;
		json_string(n->label);
		printf(", \"bundle\": ");
		json_string(n->bundle);
		printf(", \"anointments\": ");
		json_names(n->anoint, n->nanoint);
		printf(", \"user_resolvable\": %s}",
		    n->user_resolvable ? "true" : "false");
	}
	printf("\n  ],\n  \"sessions\": [\n");
	first = 1;
	for (i = 0; i < g->nnodes; i++) {
		const struct gnode *n = &g->nodes[i];

		if (!n->is_session)
			continue;
		printf("%s    {\"label\": ", first ? "" : ",\n");
		first = 0;
		json_string(n->label);
		printf(", \"uid\": %u, \"anointments\": ", (unsigned)n->uid);
		json_names(n->anoint, n->nanoint);
		printf(", \"anoint_all\": %s, \"admin_rights\": %s, "
		    "\"from_default_rule\": %s}",
		    n->anoint_all ? "true" : "false",
		    n->admin_rights ? "true" : "false",
		    n->from_default_rule ? "true" : "false");
	}
	printf("\n  ],\n  \"endpoints\": [\n");
	for (i = 0; i < g->neps; i++) {
		const struct gendpoint *e = &g->eps[i];

		printf("%s    {\"name\": ", i == 0 ? "" : ",\n");
		json_string(e->name);
		printf(", \"provider\": ");
		json_string(g->nodes[e->owner].label);
		printf(", \"requires\": ");
		json_names(e->requires, e->nrequires);
		printf("}");
	}
	printf("\n  ],\n  \"edges\": [\n");
	for (i = 0; i < g->nedges; i++) {
		const struct gedge *ed = &g->edges[i];
		const struct gendpoint *e = &g->eps[ed->to];

		printf("%s    {\"from\": ", i == 0 ? "" : ",\n");
		json_string(g->nodes[ed->from].label);
		printf(", \"to\": ");
		json_string(e->name);
		printf(", \"provider\": ");
		json_string(g->nodes[e->owner].label);
		printf(", \"via\": ");
		json_names(e->requires, e->nrequires);
		printf("}");
	}
	printf("\n  ],\n  \"warnings\": [\n");
	for (i = 0; i < g->nwarnings; i++) {
		const struct gwarning *w = &g->warnings[i];

		printf("%s    {\"kind\": ", i == 0 ? "" : ",\n");
		json_string(w->kind);
		printf(", \"subject\": ");
		json_string(w->subject);
		printf(", \"name\": ");
		json_string(w->name);
		printf(", \"text\": ");
		json_string(w->text);
		printf("}");
	}
	printf("\n  ]\n}\n");
}

static void
graph_free(struct graph *g)
{
	unsigned i;

	for (i = 0; i < g->nnodes; i++)
		free(g->nodes[i].anoint);
	for (i = 0; i < g->neps; i++)
		free(g->eps[i].requires);
	free(g->nodes);
	free(g->eps);
	free(g->edges);
	free(g->warnings);
}

static void
graph_usage(void)
{
	fprintf(stderr, "usage: switchboardctl graph [--text|--dot|--json] "
	    "[--lint] [--root dir]\n");
	exit(EX_USAGE);
}

int
cmd_graph(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "text", no_argument, NULL, 't' },
		{ "dot", no_argument, NULL, 'd' },
		{ "json", no_argument, NULL, 'j' },
		{ "lint", no_argument, NULL, 'l' },
		{ "root", required_argument, NULL, 'r' },
		{ NULL, 0, NULL, 0 }
	};
	struct graph g;
	const char *root = NULL, *policy_path, *system_dir, *user_dir;
	enum graph_format fmt = GRAPH_TEXT;
	bool lint = false;
	int ch, policy_fd, rc;

	optind = 1;
	optreset = 1;
	while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (ch) {
		case 't':
			fmt = GRAPH_TEXT;
			break;
		case 'd':
			fmt = GRAPH_DOT;
			break;
		case 'j':
			fmt = GRAPH_JSON;
			break;
		case 'l':
			lint = true;
			break;
		case 'r':
			root = optarg;
			break;
		default:
			graph_usage();
		}
	}
	if (argc - optind != 0)
		graph_usage();

	memset(&g, 0, sizeof(g));

	/* Sessions first so they sort ahead and node 0 carries policy state. */
	policy_path = getenv("SWITCHBOARD_PRINCIPAL_POLICY");
	if (policy_path == NULL || policy_path[0] == '\0')
		policy_path = GRAPH_POLICY_PATH;
	policy_fd = open(policy_path, O_RDONLY | O_CLOEXEC);
	graph_add_session(&g, policy_fd, GRAPH_SESSION_ADMIN, GRAPH_UID_ADMIN,
	    true);
	graph_add_session(&g, policy_fd, GRAPH_SESSION_DEFAULT,
	    GRAPH_UID_DEFAULT, false);
	if (policy_fd >= 0)
		close(policy_fd);
	else if (fmt != GRAPH_JSON)
		fprintf(stderr, "switchboardctl: graph: %s: %s; using the "
		    "historical principal rule\n", policy_path,
		    strerror(errno));

	if (root != NULL)
		rc = graph_scan(&g, root, true);
	else {
		system_dir = getenv("SWITCHBOARD_BUNDLE_DIR_SYSTEM");
		if (system_dir == NULL || system_dir[0] == '\0')
			system_dir = "/Capabilities/System";
		user_dir = getenv("SWITCHBOARD_BUNDLE_DIR_USER");
		if (user_dir == NULL || user_dir[0] == '\0')
			user_dir = "/Capabilities";
		rc = graph_scan(&g, system_dir, false);
		if (rc == 0)
			rc = graph_scan(&g, user_dir, false);
	}
	if (rc != 0) {
		graph_free(&g);
		return (1);
	}

	graph_sort(&g);
	graph_build_edges(&g);
	graph_lint(&g);

	switch (fmt) {
	case GRAPH_TEXT:
		graph_print_text(&g, lint);
		break;
	case GRAPH_DOT:
		graph_print_dot(&g);
		if (lint) {
			unsigned i;

			for (i = 0; i < g.nwarnings; i++)
				fprintf(stderr, "warning: %s\n",
				    g.warnings[i].text);
		}
		break;
	case GRAPH_JSON:
		graph_print_json(&g);
		break;
	}
	rc = (lint && g.nwarnings != 0) ? 2 : 0;
	graph_free(&g);
	return (rc);
}
