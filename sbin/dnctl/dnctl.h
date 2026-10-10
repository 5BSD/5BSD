#ifndef _DNCTL_H_
#define _DNCTL_H_

/*-
 * Copyright (c) 2002-2003 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * NEW command line interface for IP firewall facility
 */

/* Standalone shaping command options; this is not a kernel ABI. */
struct cmdline_opts {
	int do_quiet;
	int do_pipe;
	int do_force;
	int test_only;
	int verbose;
	int do_sort;
};

extern struct cmdline_opts g_co;

/*
 * _s_x is a structure that stores a string <-> token pairs, used in
 * various places in the parser. Entries are stored in arrays,
 * with an entry with s=NULL as terminator.
 * The search routine is match_token().
 * Often, an element with x=0 contains an error string.
 *
 */
struct _s_x {
	char const *s;
	int x;
};

enum tokens {
	TOK_NULL=0,
	TOK_PIPE,
	TOK_LINK,
	TOK_QUEUE,
	TOK_FLOWSET,
	TOK_SCHED,
	TOK_LIMIT,
	TOK_PLR,
	TOK_NOERROR,
	TOK_BUCKETS,
	TOK_DSTIP,
	TOK_SRCIP,
	TOK_DSTPORT,
	TOK_SRCPORT,
	TOK_ALL,
	TOK_MASK,
	TOK_FLOW_MASK,
	TOK_SCHED_MASK,
	TOK_BW,
	TOK_DELAY,
	TOK_PROFILE,
	TOK_BURST,
	TOK_RED,
	TOK_GRED,
	TOK_ECN,
	TOK_DROPTAIL,
	TOK_PROTO,
#ifdef NEW_AQM
	/* AQM tokens*/
	TOK_NO_ECN,
	TOK_CODEL,
	TOK_FQ_CODEL,
	TOK_TARGET,
	TOK_INTERVAL,
	TOK_FLOWS,
	TOK_QUANTUM,
	TOK_PIE,
	TOK_FQ_PIE,
	TOK_TUPDATE,
	TOK_MAX_BURST,
	TOK_MAX_ECNTH,
	TOK_ALPHA,
	TOK_BETA,
	TOK_CAPDROP,
	TOK_NO_CAPDROP,
	TOK_ONOFF,
	TOK_DRE,
	TOK_TS,
	TOK_DERAND,
	TOK_NO_DERAND,
#endif
	/* dummynet tokens */
	TOK_WEIGHT,
	TOK_LMAX,
	TOK_PRI,
	TOK_TYPE,
	TOK_FLOWID,
	TOK_DSTIP6,
	TOK_SRCIP6,
};

/*
 * the following macro returns an error message if we run out of
 * arguments.
 */
#define NEED(_p, msg)      {if (!_p) errx(EX_USAGE, msg);}
#define NEED1(msg)      {if (!(*av)) errx(EX_USAGE, msg);}

struct buf_pr {
	char	*buf;	/* allocated buffer */
	char	*ptr;	/* current pointer */
	size_t	size;	/* total buffer size */
	size_t	avail;	/* available storage */
	size_t	needed;	/* length needed */
};

int pr_u64(struct buf_pr *bp, void *pd, int width);
int bp_alloc(struct buf_pr *b, size_t size);
void bp_free(struct buf_pr *b);
int bprintf(struct buf_pr *b, const char *format, ...) __printflike(2, 3);


/* memory allocation support */
void *safe_calloc(size_t number, size_t size);
void *safe_realloc(void *ptr, size_t size);

/* string comparison functions used for historical compatibility */
int _substrcmp(const char *str1, const char* str2);
int _substrcmp2(const char *str1, const char* str2, const char* str3);
/* Utility functions used by the shaping parser. */
int match_token(struct _s_x *table, const char *string);
int do_cmd(int optname, void *optval, uintptr_t optlen);

struct in6_addr;
void n2mask(struct in6_addr *mask, int n);


/* Shared Dummynet parser and formatting entry points. */
void bp_flush(struct buf_pr *b);
void ipfw_config_pipe(int ac, char **av);
void dummynet_list(int ac, char *av[], int show_counters);
void dummynet_flush(void);
int ipfw_delete_pipe(int pipe_or_queue, int n);

#endif
