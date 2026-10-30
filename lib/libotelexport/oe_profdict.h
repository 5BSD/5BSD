/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal profiles dictionary builder (experimental OTLP profiles,
 * opentelemetry-proto 1.10 v1development): the request-wide
 * ProfilesDictionary tables and the merged samples of one profile, built
 * from the encoding-free struct oe_profile and independent of any wire
 * encoding.  oe_otlpprof.c writes them as OTLP JSON, which the protobuf
 * transports transcode like every other request.
 *
 * Every table starts with its zero value (index 0 means "not set"), and
 * entries are interned by value, so a table holds no duplicates.  Each
 * table is bounded; a sample that would need an entry beyond the bound
 * is dropped and counted.
 */

#ifndef _OE_PROFDICT_H_
#define	_OE_PROFDICT_H_

#include <stdint.h>

#include "otelexport.h"

/* Entries per table, the zero value included. */
#define	OE_PROFDICT_DEFAULT_MAX	(256 * 1024)

struct oe_pd_mapping {
	int32_t		 filename;	/* string index */
};

struct oe_pd_function {
	int32_t		 name;
	int32_t		 system_name;
};

struct oe_pd_location {
	int32_t		 mapping;
	uint64_t	 address;
	int32_t		 function;	/* 0: no line */
};

struct oe_pd_stack {
	int32_t		*locations;	/* leaf first */
	size_t		 n;
};

struct oe_pd_link {
	uint8_t		 trace_id[OE_TRACE_ID_LEN];
	uint8_t		 span_id[OE_SPAN_ID_LEN];
};

/*
 * An attribute: the key is a string index; a string value is held here
 * (AnyValue carries it inline: it is not a string table entry).
 */
struct oe_pd_attr {
	int32_t		 key;		/* string index */
	enum oe_value_type type;
	char		*s;		/* OE_VAL_STRING, owned */
	int64_t		 i;
	double		 d;
};

/* One merged sample of a profile. */
struct oe_pd_sample {
	int32_t		 stack;
	int32_t		*attrs;		/* attribute indices, unique keys */
	size_t		 nattrs;
	int32_t		 link;
	int		 shape;		/* see oe_profdict.c */
	int64_t		*values;
	size_t		 nvalues, capvalues;
	uint64_t	*timestamps;
	size_t		 ntimestamps, captimestamps;
};

struct oe_pd_map;

struct oe_profdict {
	size_t		 max;		/* entries per table */
	char		**strings;
	size_t		 nstrings, capstrings;
	struct oe_pd_mapping *mappings;
	size_t		 nmappings, capmappings;
	struct oe_pd_function *functions;
	size_t		 nfunctions, capfunctions;
	struct oe_pd_location *locations;
	size_t		 nlocations, caplocations;
	struct oe_pd_stack *stacks;
	size_t		 nstacks, capstacks;
	struct oe_pd_link *links;
	size_t		 nlinks, caplinks;
	struct oe_pd_attr *attrs;
	size_t		 nattrs, capattrs;
	struct oe_pd_sample *samples;	/* of the profile being added */
	size_t		 nsamples, capsamples;
	struct oe_pd_map *map;		/* value -> index, all tables */
	uint64_t	 dropped;	/* samples over a bound */
	int		 error;		/* allocation failed */
};

/* max 0 is OE_PROFDICT_DEFAULT_MAX.  Returns 0, or -1 without memory. */
int	 oe_profdict_init(struct oe_profdict *, size_t max);
void	 oe_profdict_fini(struct oe_profdict *);

/* Intern a string; its index, or -1 (bound or memory). */
int32_t	 oe_profdict_string(struct oe_profdict *, const char *);

/*
 * Intern a profile-level attribute (unique keys are the caller's
 * business); its index or -1.
 */
int32_t	 oe_profdict_attr(struct oe_profdict *, const struct oe_kv *);

/*
 * Add one sample: intern its frames, stack, attributes (the context
 * attributes of oe_context_kvs() and the sample's own, a later key
 * replacing an earlier one) and link, and merge it into the sample of
 * the same identity.  Returns 0, or -1 when it was dropped (counted in
 * "dropped", or "error" set without memory).
 */
int	 oe_profdict_sample(struct oe_profdict *,
	    const struct oe_profile_sample *);

#endif /* !_OE_PROFDICT_H_ */
