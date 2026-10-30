/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The experimental OTLP profiles signal and metric exemplars: the
 * profiles dictionary builder (oe_profdict.c), the profile request
 * encoder (oe_otlpprof.c), profiles through the OTLP exporter
 * (http/protobuf, gRPC, the http/json refusal, the spool) and the OTLP
 * JSON Lines file exporter, and exemplars on every metric data point
 * kind.  What the library produces is checked by independent means: the
 * C++ protobuf oracle (pbcpp/otlp_pb_oracle) resolves each profile
 * through its dictionary and checks the dictionary rules, the JSON
 * validator (otlp_validate.c) checks the OTLP JSON, and expected results
 * are written out by hand.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"
#include "oe_profdict.h"
#include "grpc_testsrv.h"
#include "otel_testutil.h"
#include "otlp_validate.h"

/* ---------------------------------------------------------------- */
/* Helpers								*/

static const char *
oracle(const atf_tc_t *tc)
{
	static char path[PATH_MAX];
	const char *srcdir = atf_tc_get_config_var(tc, "srcdir");

	snprintf(path, sizeof(path), "%s/otlp_pb_oracle", srcdir);
	if (access(path, X_OK) != 0)
		snprintf(path, sizeof(path), "%s/pbcpp/otlp_pb_oracle", srcdir);
	return (path);
}

static void
write_file(const char *path, const void *p, size_t len)
{
	FILE *fp;

	ATF_REQUIRE((fp = fopen(path, "w")) != NULL);
	ATF_REQUIRE_EQ(len, fwrite(p, 1, len, fp));
	ATF_REQUIRE_EQ(0, fclose(fp));
}

static char *
read_file(const char *path)
{
	struct stat st;
	char *buf;
	int fd;

	ATF_REQUIRE((fd = open(path, O_RDONLY)) >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &st));
	ATF_REQUIRE((buf = calloc(1, (size_t)st.st_size + 1)) != NULL);
	ATF_REQUIRE_EQ(st.st_size, read(fd, buf, (size_t)st.st_size));
	close(fd);
	return (buf);
}

static int
run_oracle(const atf_tc_t *tc, const char *args, const char *out)
{
	char cmd[2048];
	int st;

	snprintf(cmd, sizeof(cmd), "%s %s > %s 2>&1", oracle(tc), args, out);
	st = system(cmd);
	return (WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

/* The oracle's resolved samples of a binary profiles request. */
static char *
oracle_profile(const atf_tc_t *tc, const void *pb, size_t len)
{

	write_file("prof.pb", pb, len);
	ATF_REQUIRE_EQ_MSG(0, run_oracle(tc, "profile prof.pb", "prof.txt"),
	    "%s", read_file("prof.txt"));
	return (read_file("prof.txt"));
}

static int saved_stderr = -1;

static void
capture_start(void)
{
	int fd;

	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	fd = open("stderr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

static char *
capture_end(void)
{
	char *s;

	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);
	s = read_file("stderr.txt");
	fprintf(stderr, "%s", s);
	return (s);
}

/* Validate one OTLP JSON request with the independent validator. */
static void
validate_json(const char *json, size_t len, struct otlp_counts *c)
{
	struct jv *v;
	char err[512];

	memset(c, 0, sizeof(*c));
	v = jv_parse(json, len, err, sizeof(err));
	ATF_REQUIRE_MSG(v != NULL, "%s", err);
	ATF_CHECK_EQ_MSG(0, otlp_validate_request(v, c, err, sizeof(err)),
	    "%s", err);
	jv_free(v);
}

static struct oe_resource res;

static struct oe_exporter *otlp_exporter(const char *, const char *,
    const char *, int);

static const struct oe_resource *
resource(void)
{

	memset(&res, 0, sizeof(res));
	res.service_name = "svc";
	res.service_version = "9.9";
	return (&res);
}

/* ---------------------------------------------------------------- */
/* A known profile							*/

/* Frame strings (struct oe_frame members are not const). */
static char s_kernel[] = "kernel", s_spin[] = "spin_loop",
    s_main[] = "main_loop", s_aout[] = "a.out", s_busy[] = "busy",
    s_libc[] = "libc.so.7", s_1234[] = "0x1234", s_guest[] = "guest[3]",
    s_dead[] = "0xdead", s_nomod[] = "nomodule";

static struct oe_frame kframes[] = {
	{ 0, s_kernel, s_spin, 0x10, 1 },
	{ 0, s_kernel, s_main, 0, 0 },
};
static struct oe_frame uframes[] = {
	{ 0, s_aout, s_busy, 0x4, 1 },
	{ 0x1234, s_libc, s_1234, 0, 0 },
};
/* The same functions at other offsets: the same locations. */
static struct oe_frame kframes2[] = {
	{ 0, s_kernel, s_spin, 0x18, 1 },
	{ 0, s_kernel, s_main, 0x2, 1 },
};
static struct oe_frame addrframe[] = { { 0xffff0001, NULL, NULL, 0, 0 } };
static struct oe_frame guestframes[] = {
	{ 0, s_guest, s_dead, 0, 0 },
	{ 0, NULL, s_nomod, 0, 0 },
};

static struct timespec t1 = { 1700000000, 1 }, t2 = { 1700000000, 2 },
    t3 = { 1700000000, 3 };

/*
 * The samples, and what the oracle must resolve them to (sorted, as it
 * prints them).
 */
static void
known_samples(struct oe_profile_sample s[4])
{

	memset(s, 0, 4 * sizeof(*s));
	s[0].stack = kframes;
	s[0].nstack = 2;
	s[0].ustack = uframes;
	s[0].nustack = 2;
	s[0].timestamps = &t1;
	s[0].ntimestamps = 1;
	s[0].pid = 42;
	s[0].execname = "busy";
	s[0].ctx.flags = OE_CTX_CPU;
	s[0].ctx.cpu = 1;
	s[1] = s[0];
	s[1].stack = kframes2;
	s[1].timestamps = &t2;
	s[2].stack = addrframe;
	s[2].nstack = 1;
	s[2].timestamps = &t3;
	s[2].ntimestamps = 1;
	s[2].ctx.flags = OE_CTX_CPU;
	s[2].ctx.cpu = 0;
	memcpy(s[2].trace_id, "\001\002\003\004\005\006\007\010\011\012\013"
	    "\014\015\016\017\020", OE_TRACE_ID_LEN);
	memcpy(s[2].span_id, "\021\022\023\024\025\026\027\030",
	    OE_SPAN_ID_LEN);
	s[3].stack = guestframes;
	s[3].nstack = 2;
	s[3].timestamps = &t3;
	s[3].ntimestamps = 1;
}

static const char known_resolved[] =
    "svc|samples/count|cpu.logical_number=0,link="
    "0102030405060708090a0b0c0d0e0f10/1112131415161718|0xffff0001|1\n"
    "svc|samples/count|cpu.logical_number=1,process.executable.name=busy,"
    "process.pid=42|kernel`spin_loop;kernel`main_loop;a.out`busy;"
    "libc.so.7`0x1234|2\n"
    "svc|samples/count||guest[3]`0xdead;nomodule|1\n";

static void
known_profile(struct oe_profile *pr, struct oe_profile_sample s[4],
    struct oe_kv *attr)
{

	known_samples(s);
	memset(pr, 0, sizeof(*pr));
	pr->profile = "prof";
	pr->sample_type = "samples";
	pr->sample_unit = "count";
	pr->period_type = "cpu";
	pr->period_unit = "nanoseconds";
	pr->period = 1003009;
	pr->start = t1;
	pr->end.tv_sec = t1.tv_sec + 10;
	pr->samples = s;
	pr->nsamples = 4;
	attr->key = "dtrace.probe";
	attr->type = OE_VAL_STRING;
	attr->s = "profile:::profile-997";
	pr->attrs = attr;
	pr->nattrs = 1;
}

/* The request of the known profile, as JSON and as protobuf. */
static char *
known_request(size_t *lenp, char **pbp, size_t *pblenp)
{
	struct oe_otlpenc enc;
	struct oe_otlppb_defs defs;
	struct oe_profile pr;
	struct oe_profile_sample s[4];
	struct oe_kv attr;
	char *json, err[256];

	known_profile(&pr, s, &attr);
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	ATF_REQUIRE((json = oe_enc_profile(&enc, &pr, lenp)) != NULL);
	oe_enc_fini(&enc);
	if (pbp != NULL) {
		ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&defs));
		ATF_REQUIRE_EQ_MSG(0, oe_otlppb_encode(&defs,
		    OE_SIGNAL_PROFILES, json, *lenp, pbp, pblenp, err,
		    sizeof(err)), "%s", err);
		oe_otlppb_defs_fini(&defs);
	}
	return (json);
}

/* ---------------------------------------------------------------- */
/* The dictionary builder						*/

ATF_TC_WITHOUT_HEAD(profdict_tables);
ATF_TC_BODY(profdict_tables, tc)
{
	struct oe_profdict d;
	struct oe_profile_sample s[4];
	struct oe_kv kv;
	size_t i;

	known_samples(s);
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 0));
	ATF_CHECK_EQ(OE_PROFDICT_DEFAULT_MAX, d.max);
	/* Every table starts with its zero value. */
	ATF_CHECK_EQ(1, d.nstrings);
	ATF_CHECK_STREQ("", d.strings[0]);
	ATF_CHECK_EQ(1, d.nmappings);
	ATF_CHECK_EQ(1, d.nlocations);
	ATF_CHECK_EQ(1, d.nfunctions);
	ATF_CHECK_EQ(1, d.nstacks);
	ATF_CHECK_EQ(1, d.nlinks);
	ATF_CHECK_EQ(1, d.nattrs);
	ATF_CHECK_EQ(0, oe_profdict_string(&d, ""));
	ATF_CHECK_EQ(1, oe_profdict_string(&d, "x"));
	ATF_CHECK_EQ(1, oe_profdict_string(&d, "x"));
	for (i = 0; i < 4; i++)
		ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s[i]));
	/* s[0] and s[1] differ only in offsets: one merged sample. */
	ATF_CHECK_EQ(3, d.nsamples);
	ATF_CHECK_EQ(2, d.samples[0].ntimestamps);
	ATF_CHECK_EQ(0, d.samples[0].nvalues);
	ATF_CHECK_EQ(1700000000000000001ULL, d.samples[0].timestamps[0]);
	ATF_CHECK_EQ(1700000000000000002ULL, d.samples[0].timestamps[1]);
	/* kernel, a.out, libc.so.7, guest[3]. */
	ATF_CHECK_EQ(5, d.nmappings);
	/* spin_loop, main_loop, busy, nomodule. */
	ATF_CHECK_EQ(5, d.nfunctions);
	/* Four of s[0], the address, two of s[3]. */
	ATF_CHECK_EQ(8, d.nlocations);
	ATF_CHECK_EQ(4, d.nstacks);
	ATF_CHECK_EQ(2, d.nlinks);
	ATF_CHECK_EQ(1, d.samples[1].link);
	/* The libc frame is an address under its mapping, without a line. */
	for (i = 1; i < d.nlocations; i++)
		if (d.locations[i].address == 0x1234)
			break;
	ATF_REQUIRE(i < d.nlocations);
	ATF_CHECK_EQ(0, d.locations[i].function);
	ATF_CHECK_STREQ("libc.so.7",
	    d.strings[d.mappings[d.locations[i].mapping].filename]);
	/* A profile attribute of each type. */
	kv.key = "b";
	kv.type = OE_VAL_BOOL;
	kv.i = 7;
	ATF_CHECK(oe_profdict_attr(&d, &kv) > 0);
	ATF_CHECK_EQ(1, d.attrs[d.nattrs - 1].i);
	kv.type = OE_VAL_DOUBLE;
	kv.d = 1.5;
	ATF_CHECK(oe_profdict_attr(&d, &kv) > 0);
	kv.type = OE_VAL_STRING;
	kv.s = NULL;
	ATF_CHECK(oe_profdict_attr(&d, &kv) > 0);
	ATF_CHECK_STREQ("", d.attrs[d.nattrs - 1].s);
	/* A string value is no string table entry (none is orphaned). */
	kv.s = "only-a-value";
	ATF_CHECK(oe_profdict_attr(&d, &kv) > 0);
	for (i = 0; i < d.nstrings; i++)
		ATF_CHECK(strcmp(d.strings[i], "only-a-value") != 0);
	ATF_CHECK_EQ(0, d.error);
	ATF_CHECK_EQ(0, d.dropped);
	oe_profdict_fini(&d);
}

ATF_TC_WITHOUT_HEAD(profdict_shapes);
ATF_TC_BODY(profdict_shapes, tc)
{
	struct oe_profdict d;
	struct oe_profile_sample s;
	struct oe_kv kv[3];
	struct timespec ts[2] = { { 5, 0 }, { 6, 0 } };

	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 0));
	memset(&s, 0, sizeof(s));
	s.stack = kframes;
	s.nstack = 1;
	/* Neither value nor timestamps: one observation. */
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	s.has_value = 1;
	s.value = 9;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(1, d.nsamples);
	ATF_CHECK_EQ(1, d.samples[0].nvalues);
	ATF_CHECK_EQ(10, d.samples[0].values[0]);
	/* A value per timestamp: its own shape, never merged with those. */
	s.timestamps = ts;
	s.ntimestamps = 2;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(2, d.nsamples);
	ATF_CHECK_EQ(4, d.samples[1].nvalues);
	ATF_CHECK_EQ(4, d.samples[1].ntimestamps);
	ATF_CHECK_EQ(9, d.samples[1].values[3]);
	/* Timestamps only: a third shape. */
	s.has_value = 0;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(3, d.nsamples);
	ATF_CHECK_EQ(0, d.samples[2].nvalues);
	/*
	 * Attributes: keys unique (the later wins, so the sample's own
	 * process.pid replaces the context's), the set sorted, so the same
	 * attributes in another order are the same sample.
	 */
	s.timestamps = NULL;
	s.ntimestamps = 0;
	s.pid = 1;
	kv[0].key = "process.pid";
	kv[0].type = OE_VAL_INT;
	kv[0].i = 2;
	kv[1].key = "z";
	kv[1].type = OE_VAL_STRING;
	kv[1].s = "zz";
	kv[2].key = "a";
	kv[2].type = OE_VAL_STRING;
	kv[2].s = "aa";
	s.attrs = kv;
	s.nattrs = 3;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(4, d.nsamples);
	ATF_CHECK_EQ(3, d.samples[3].nattrs);
	ATF_CHECK(d.samples[3].attrs[0] < d.samples[3].attrs[1]);
	ATF_CHECK(d.samples[3].attrs[1] < d.samples[3].attrs[2]);
	kv[0] = kv[2];
	kv[2].key = "process.pid";
	kv[2].type = OE_VAL_INT;
	kv[2].i = 2;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(4, d.nsamples);
	ATF_CHECK_EQ(2, d.samples[3].values[0]);
	/* An empty stack is stack 0. */
	memset(&s, 0, sizeof(s));
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(0, d.samples[4].stack);
	oe_profdict_fini(&d);
}

/* A table bound drops samples and counts them; memory stays fine. */
ATF_TC_WITHOUT_HEAD(profdict_bounds);
ATF_TC_BODY(profdict_bounds, tc)
{
	struct oe_profdict d;
	struct oe_profile_sample s[4];
	struct oe_frame f;
	struct oe_kv kv;
	char sym[32];
	int i, ok;

	known_samples(s);
	/* Strings "", kernel, spin_loop, main_loop: the fifth refuses. */
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 4));
	ATF_CHECK_EQ(-1, oe_profdict_sample(&d, &s[0]));
	ATF_CHECK_EQ(1, d.dropped);
	ATF_CHECK_EQ(0, d.error);
	ATF_CHECK_EQ(0, d.nsamples);
	oe_profdict_fini(&d);
	/* Many distinct functions against a larger bound. */
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 64));
	memset(&s[0], 0, sizeof(s[0]));
	memset(&f, 0, sizeof(f));
	f.symbol = sym;
	s[0].stack = &f;
	s[0].nstack = 1;
	ok = 0;
	for (i = 0; i < 200; i++) {
		snprintf(sym, sizeof(sym), "f%d", i);
		if (oe_profdict_sample(&d, &s[0]) == 0)
			ok++;
	}
	ATF_CHECK(ok > 0 && ok < 64);
	ATF_CHECK_EQ((uint64_t)(200 - ok), d.dropped);
	ATF_CHECK(d.nstrings <= 64 && d.nfunctions <= 64 &&
	    d.nlocations <= 64 && d.nstacks <= 64 && d.nsamples <= 64);
	ATF_CHECK_EQ(0, d.error);
	/* Links and attributes have bounds too. */
	oe_profdict_fini(&d);
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 2));
	known_samples(s);
	s[2].stack = NULL;
	s[2].nstack = 0;
	s[2].ctx.flags = 0;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s[2]));
	s[2].trace_id[0] = 9;
	ATF_CHECK_EQ(-1, oe_profdict_sample(&d, &s[2]));
	ATF_CHECK_EQ(1, d.dropped);
	oe_profdict_fini(&d);
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 3));
	kv.key = "k";
	kv.type = OE_VAL_INT;
	kv.i = 1;
	ATF_CHECK_EQ(1, oe_profdict_attr(&d, &kv));
	kv.i = 2;
	ATF_CHECK_EQ(2, oe_profdict_attr(&d, &kv));
	kv.i = 3;
	ATF_CHECK_EQ(-1, oe_profdict_attr(&d, &kv));
	ATF_CHECK_EQ(0, d.error);
	memset(&s[0], 0, sizeof(s[0]));
	s[0].pid = 5;
	ATF_CHECK_EQ(-1, oe_profdict_sample(&d, &s[0]));
	ATF_CHECK_EQ(1, d.dropped);
	oe_profdict_fini(&d);
	/* A mapping beyond the bound. */
	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 1));
	memset(&s[0], 0, sizeof(s[0]));
	s[0].stack = addrframe;
	s[0].nstack = 1;
	ATF_CHECK_EQ(-1, oe_profdict_sample(&d, &s[0]));
	oe_profdict_fini(&d);
}

/* Every allocation of the builder and the encoder may fail. */
ATF_TC_WITHOUT_HEAD(profdict_oom);
ATF_TC_BODY(profdict_oom, tc)
{
	struct oe_profdict d;
	struct oe_profile_sample s[4];
	struct oe_otlpenc enc;
	struct oe_profile pr;
	struct oe_kv attr;
	char *json;
	size_t len;
	int n, i, r, fails, hit, ok;

	fails = 0;
	for (n = 1; n < 2000; n++) {
		known_samples(s);
		failalloc_arm(n);
		r = oe_profdict_init(&d, 0);
		for (i = 0; r == 0 && i < 4; i++)
			if (oe_profdict_sample(&d, &s[i]) != 0)
				break;
		hit = failalloc_hit();
		failalloc_arm(0);
		if (r == 0) {
			if (i < 4)
				ATF_CHECK(d.error);
			oe_profdict_fini(&d);
		}
		if (!hit)
			break;
		fails++;
	}
	ATF_CHECK(fails > 20);
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	fails = 0;
	for (n = 1; n < 4000; n++) {
		known_profile(&pr, s, &attr);
		failalloc_arm(n);
		json = oe_enc_profile(&enc, &pr, &len);
		hit = failalloc_hit();
		failalloc_arm(0);
		ok = json != NULL;
		free(json);
		if (!hit) {
			ATF_CHECK(ok);
			break;
		}
		fails++;
	}
	ATF_CHECK(fails > 20);
	oe_enc_fini(&enc);
}

/* ---------------------------------------------------------------- */
/* The request								*/

ATF_TC_WITHOUT_HEAD(profile_request);
ATF_TC_BODY(profile_request, tc)
{
	struct otlp_counts c;
	char *json, *pb, *got;
	size_t len, pblen;

	json = known_request(&len, &pb, &pblen);
	/* The independent JSON validator, dictionary rules included. */
	validate_json(json, len, &c);
	ATF_CHECK_EQ(1, c.profiles);
	ATF_CHECK_EQ(3, c.samples);
	ATF_CHECK(strncmp(json, "{\"resourceProfiles\":", 20) == 0);
	ATF_CHECK_EQ(OE_SIGNAL_PROFILES, oe_enc_classify(json));
	ATF_CHECK(strstr(json, "\"otlp.profiles.package\",\"value\":"
	    "{\"stringValue\":\"opentelemetry.proto.profiles.v1development\"}")
	    != NULL);
	ATF_CHECK(strstr(json, "\"period\":\"1003009\"") != NULL);
	ATF_CHECK(strstr(json, "\"durationNano\":\"9999999999\"") != NULL);
	/* The C++ runtime parses the JSON to the same message... */
	write_file("req.json", json, len);
	write_file("req.pb", pb, pblen);
	ATF_CHECK_EQ_MSG(0, run_oracle(tc, "compare req.json req.pb",
	    "cmp.txt"), "%s", read_file("cmp.txt"));
	/* ...which resolves, through the dictionary, to the samples. */
	got = oracle_profile(tc, pb, pblen);
	ATF_CHECK_STREQ(known_resolved, got);
	free(got);
	ATF_CHECK_EQ(0, run_oracle(tc, "decode profiles req.pb", "dec.txt"));
	got = read_file("dec.txt");
	ATF_CHECK(strstr(got, "\"profile:::profile-997\"") != NULL);
	free(got);
	free(json);
	free(pb);
}

/*
 * The request of the known profile, structurally equal to the golden
 * file an independent generator wrote from profiles.proto (key order
 * aside; table, sample and array order significant).
 */
ATF_TC_WITHOUT_HEAD(profile_golden);
ATF_TC_BODY(profile_golden, tc)
{
	struct jv *got, *want;
	char path[PATH_MAX], err[512], *json, *golden;
	size_t len;

	json = known_request(&len, NULL, NULL);
	snprintf(path, sizeof(path), "%s/golden/otlpjson-profiles.jsonl",
	    atf_tc_get_config_var(tc, "srcdir"));
	golden = read_file(path);
	ATF_REQUIRE((want = jv_parse(golden, strlen(golden), err,
	    sizeof(err))) != NULL);
	ATF_REQUIRE((got = jv_parse(json, len, err, sizeof(err))) != NULL);
	ATF_CHECK_EQ_MSG(0, jv_match(want, got, err, sizeof(err)), "%s", err);
	jv_free(want);
	jv_free(got);
	free(golden);
	free(json);
}

/* Value samples (aggregations), no period, attributes of each type. */
ATF_TC_WITHOUT_HEAD(profile_values);
ATF_TC_BODY(profile_values, tc)
{
	struct oe_otlpenc enc;
	struct oe_otlppb_defs defs;
	struct oe_profile pr;
	struct oe_profile_sample s[2];
	struct oe_kv kv[5];
	struct otlp_counts c;
	char *json, *pb, *got, err[256];
	size_t len, pblen;

	memset(s, 0, sizeof(s));
	s[0].stack = kframes;
	s[0].nstack = 2;
	s[0].has_value = 1;
	s[0].value = 7;
	kv[0].key = "process.executable.name";
	kv[0].type = OE_VAL_STRING;
	kv[0].s = "sh";
	s[0].attrs = kv;
	s[0].nattrs = 1;
	s[1] = s[0];
	s[1].value = 5;
	memset(&pr, 0, sizeof(pr));
	pr.profile = "p";
	pr.sample_type = "bytes";
	pr.sample_unit = "By";
	pr.samples = s;
	pr.nsamples = 2;
	/* A profile attribute that would repeat the profile name is not. */
	kv[1].key = "tool.profile";
	kv[1].type = OE_VAL_STRING;
	kv[1].s = "other";
	kv[2].key = "i";
	kv[2].type = OE_VAL_INT;
	kv[2].i = -3;
	kv[3].key = "d";
	kv[3].type = OE_VAL_DOUBLE;
	kv[3].d = 0.25;
	kv[4].key = "b";
	kv[4].type = OE_VAL_BOOL;
	kv[4].i = 1;
	pr.attrs = kv + 1;
	pr.nattrs = 4;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	ATF_REQUIRE((json = oe_enc_profile(&enc, &pr, &len)) != NULL);
	oe_enc_fini(&enc);
	validate_json(json, len, &c);
	ATF_CHECK_EQ(1, c.samples);
	ATF_CHECK(strstr(json, "periodType") == NULL);
	ATF_CHECK(strstr(json, "\"values\":[\"12\"]") != NULL);
	ATF_CHECK(strstr(json, "\"intValue\":\"-3\"") != NULL);
	ATF_CHECK(strstr(json, "\"doubleValue\":0.25") != NULL);
	ATF_CHECK(strstr(json, "\"boolValue\":true") != NULL);
	ATF_CHECK(strstr(json, "\"other\"") == NULL);
	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&defs));
	ATF_REQUIRE_EQ_MSG(0, oe_otlppb_encode(&defs, OE_SIGNAL_PROFILES,
	    json, len, &pb, &pblen, err, sizeof(err)), "%s", err);
	oe_otlppb_defs_fini(&defs);
	got = oracle_profile(tc, pb, pblen);
	ATF_CHECK_STREQ("svc|bytes/By|process.executable.name=sh|"
	    "kernel`spin_loop;kernel`main_loop|12\n", got);
	free(got);
	free(json);
	free(pb);
}

/*
 * Keys longer than the builder's inline buffer (deep stacks, many
 * attributes), under allocation failure too; doubles that JSON cannot
 * spell; an unset sample type; times before the epoch.
 */
ATF_TC_WITHOUT_HEAD(profile_large_keys);
ATF_TC_BODY(profile_large_keys, tc)
{
	struct oe_profdict d;
	struct oe_otlpenc enc;
	struct oe_profile pr;
	struct oe_profile_sample s;
	struct oe_frame f[40];
	struct oe_kv kv[24];
	struct otlp_counts c;
	char names[40][80], keys[24][8], vals[24][80], *json;
	size_t len;
	int i, n, hit, fails;

	for (i = 0; i < 40; i++) {
		/* Longer than the inline key buffer. */
		snprintf(names[i], sizeof(names[i]), "g%d_%s", i,
		    "a_function_name_longer_than_the_inline_key_buffer_xxxxx");
		memset(&f[i], 0, sizeof(f[i]));
		f[i].module = s_kernel;
		f[i].symbol = names[i];
	}
	for (i = 0; i < 24; i++) {
		snprintf(keys[i], sizeof(keys[i]), "k%d", i);
		kv[i].key = keys[i];
		kv[i].type = OE_VAL_DOUBLE;
		kv[i].d = i;
	}
	/* String values longer than the inline key buffer. */
	for (i = 3; i < 24; i += 2) {
		snprintf(vals[i], sizeof(vals[i]), "v%d_%s", i,
		    "a_string_value_longer_than_the_inline_key_buffer_xxxxxxx");
		kv[i].type = OE_VAL_STRING;
		kv[i].s = vals[i];
	}
	kv[0].d = 0.0 / 0.0;
	kv[1].d = 1.0 / 0.0;
	kv[2].d = -1.0 / 0.0;
	memset(&s, 0, sizeof(s));
	s.stack = f;
	s.nstack = 40;
	s.attrs = kv;
	s.nattrs = 24;
	fails = 0;
	for (n = 1; n < 3000; n++) {
		ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 0));
		failalloc_arm(n);
		(void)oe_profdict_sample(&d, &s);
		(void)oe_profdict_sample(&d, &s);
		hit = failalloc_hit();
		failalloc_arm(0);
		if (hit)
			ATF_CHECK(d.error);
		else {
			ATF_CHECK_EQ(1, d.nsamples);
			ATF_CHECK_EQ(2, d.samples[0].values[0]);
		}
		oe_profdict_fini(&d);
		if (!hit)
			break;
		fails++;
	}
	ATF_CHECK(fails > 10);
	memset(&pr, 0, sizeof(pr));
	pr.start.tv_sec = -5;
	pr.end.tv_sec = -1;
	pr.samples = &s;
	pr.nsamples = 1;
	pr.attrs = kv;
	pr.nattrs = 3;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	ATF_REQUIRE((json = oe_enc_profile(&enc, &pr, &len)) != NULL);
	oe_enc_fini(&enc);
	validate_json(json, len, &c);
	ATF_CHECK(strstr(json, "\"doubleValue\":\"NaN\"") != NULL);
	ATF_CHECK(strstr(json, "\"doubleValue\":\"Infinity\"") != NULL);
	ATF_CHECK(strstr(json, "\"doubleValue\":\"-Infinity\"") != NULL);
	ATF_CHECK(strstr(json, "\"sampleType\":{\"typeStrindex\":0,"
	    "\"unitStrindex\":0}") != NULL);
	ATF_CHECK(strstr(json, "\"timeUnixNano\":\"0\",\"durationNano\":"
	    "\"0\"") != NULL);
	free(json);
}

/*
 * Frame and value forms: empty module or symbol, malformed and
 * overflowing hex addresses, a long symbol, a value per timestamp that
 * grows past the first allocation, a time before the epoch.
 */
ATF_TC_WITHOUT_HEAD(profdict_forms);
ATF_TC_BODY(profdict_forms, tc)
{
	static char e[] = "", m[] = "m", hx[] = "0x", hz[] = "0xzz",
	    h0[] = "0abc",
	    hbig[] = "0x123456789abcdef0123", lng[] =
	    "a_symbol_name_that_is_longer_than_the_inline_key_buffer_of_the_"
	    "dictionary_builder";
	struct oe_frame f[] = {
		{ 0x10, e, hx, 0, 0 },
		{ 0x20, m, e, 0, 0 },
		{ 0x30, m, hz, 0, 0 },
		{ 0x40, m, hbig, 0, 0 },
		{ 0, m, lng, 0, 0 },
		{ 0, m, h0, 0, 0 },
	};
	struct timespec ts[6] = { { -1, 0 }, { 1, 0 }, { 2, 0 }, { 3, 0 },
	    { 4, 0 }, { 5, 0 } };
	struct oe_profdict d;
	struct oe_profile_sample s;
	struct oe_otlpenc enc;
	struct oe_profile pr;
	struct oe_kv kv;
	struct otlp_counts c;
	char *json;
	size_t len;

	ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 0));
	memset(&s, 0, sizeof(s));
	s.stack = f;
	s.nstack = nitems(f);
	s.has_value = 1;
	s.value = 2;
	s.timestamps = ts;
	s.ntimestamps = 6;
	ATF_CHECK_EQ(0, oe_profdict_sample(&d, &s));
	ATF_CHECK_EQ(1, d.nsamples);
	ATF_CHECK_EQ(6, d.samples[0].nvalues);
	ATF_CHECK_EQ(6, d.samples[0].ntimestamps);
	ATF_CHECK_EQ(0, d.samples[0].timestamps[0]);
	/* "" module: no mapping; "0x": no address, its own function. */
	ATF_CHECK_EQ(0, d.locations[1].mapping);
	ATF_CHECK(d.locations[1].function != 0);
	/* "" symbol: the frame's address. */
	ATF_CHECK_EQ(0x20, d.locations[2].address);
	ATF_CHECK_EQ(0, d.locations[2].function);
	/* Malformed and overflowing hex: names, not addresses. */
	ATF_CHECK(d.locations[3].function != 0);
	ATF_CHECK(d.locations[4].function != 0);
	ATF_CHECK(d.locations[5].function != 0);
	oe_profdict_fini(&d);
	/* fini of a released dictionary is harmless. */
	oe_profdict_fini(&d);
	/* Encoded: several values, a false boolean attribute. */
	memset(&pr, 0, sizeof(pr));
	pr.sample_type = "samples";
	pr.sample_unit = "count";
	pr.samples = &s;
	pr.nsamples = 1;
	kv.key = "flag";
	kv.type = OE_VAL_BOOL;
	kv.i = 0;
	pr.attrs = &kv;
	pr.nattrs = 1;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	ATF_REQUIRE((json = oe_enc_profile(&enc, &pr, &len)) != NULL);
	oe_enc_fini(&enc);
	validate_json(json, len, &c);
	ATF_CHECK(strstr(json, "\"values\":[\"2\",\"2\",\"2\"") != NULL);
	ATF_CHECK(strstr(json, "\"boolValue\":false") != NULL);
	free(json);
}

/*
 * Tables past their first allocation, merges and per-timestamp values,
 * all under allocation failure.
 */
ATF_TC_WITHOUT_HEAD(profdict_growth_oom);
ATF_TC_BODY(profdict_growth_oom, tc)
{
	static char mods[80][8], syms[80][8];
	struct oe_frame f[80];
	struct oe_profile_sample s;
	struct oe_profdict d;
	struct timespec ts[2] = { { 1, 0 }, { 2, 0 } };
	int i, n, hit, fails, r;

	for (i = 0; i < 80; i++) {
		snprintf(mods[i], sizeof(mods[i]), "m%d", i);
		snprintf(syms[i], sizeof(syms[i]), "s%d", i);
		memset(&f[i], 0, sizeof(f[i]));
		f[i].module = mods[i];
		f[i].symbol = syms[i];
	}
	fails = 0;
	for (n = 1; n < 20000; n++) {
		ATF_REQUIRE_EQ(0, oe_profdict_init(&d, 0));
		failalloc_arm(n);
		r = 0;
		memset(&s, 0, sizeof(s));
		/* 80 stacks of growing depth: every table grows. */
		for (i = 1; i <= 80 && r == 0; i++) {
			s.stack = f;
			s.nstack = (size_t)i;
			r = oe_profdict_sample(&d, &s);
		}
		/* A merge that appends values and timestamps. */
		s.has_value = 1;
		s.value = 3;
		s.timestamps = ts;
		s.ntimestamps = 2;
		for (i = 0; i < 4 && r == 0; i++)
			r = oe_profdict_sample(&d, &s);
		hit = failalloc_hit();
		failalloc_arm(0);
		if (hit)
			ATF_CHECK(d.error);
		else {
			ATF_CHECK_EQ(0, r);
			ATF_CHECK_EQ(81, d.nsamples);
			ATF_CHECK_EQ(8, d.samples[80].nvalues);
		}
		oe_profdict_fini(&d);
		if (!hit)
			break;
		fails++;
	}
	ATF_CHECK(fails > 100);
}

/* The exporters survive an allocation failure while encoding. */
ATF_TC_WITHOUT_HEAD(export_oom);
ATF_TC_BODY(export_oom, tc)
{
	struct oe_sink_config sc;
	struct oe_otlpjson_config jc;
	struct oe_profile pr;
	struct oe_profile_sample s[4];
	struct oe_kv attr;
	struct oe_exporter *e, *f;
	struct oe_sink *sink;
	char ep[64];
	int n, hit, r1, r2, fails;

	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", closed_port());
	ATF_REQUIRE((e = otlp_exporter("http/protobuf", ep, NULL, 1)) !=
	    NULL);
	memset(&sc, 0, sizeof(sc));
	sc.path = "oom.jsonl";
	ATF_REQUIRE((sink = oe_sink_open(&sc)) != NULL);
	memset(&jc, 0, sizeof(jc));
	jc.sink = sink;
	jc.profile = "p";
	jc.resource = resource();
	jc.scope_name = "tool";
	ATF_REQUIRE((f = oe_otlpjson_new(&jc)) != NULL);
	fails = 0;
	capture_start();
	for (n = 1; n < 2000; n++) {
		known_profile(&pr, s, &attr);
		failalloc_arm(n);
		r1 = oe_profile(e, &pr);
		r2 = oe_profile(f, &pr);
		hit = failalloc_hit();
		failalloc_arm(0);
		if (!hit) {
			ATF_CHECK_EQ(0, r1);
			ATF_CHECK_EQ(0, r2);
			break;
		}
		fails++;
	}
	free(capture_end());
	ATF_CHECK(fails > 20);
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(0, oe_shutdown(f));
	oe_exporter_free(f);
	ATF_REQUIRE_EQ(0, oe_sink_close(sink));
}

/* A full dictionary drops samples with a warning; the rest go out. */
ATF_TC_WITHOUT_HEAD(profile_dropped);
ATF_TC_BODY(profile_dropped, tc)
{
	struct oe_otlpenc enc;
	struct oe_profile pr;
	struct oe_profile_sample *s;
	struct oe_frame *f;
	char (*names)[16], *json, *err;
	size_t len, i, n;

	/* More distinct functions than OE_PROFDICT_DEFAULT_MAX. */
	n = OE_PROFDICT_DEFAULT_MAX + 10;
	ATF_REQUIRE((s = calloc(n, sizeof(*s))) != NULL);
	ATF_REQUIRE((f = calloc(n, sizeof(*f))) != NULL);
	ATF_REQUIRE((names = calloc(n, sizeof(*names))) != NULL);
	for (i = 0; i < n; i++) {
		snprintf(names[i], sizeof(names[i]), "f%zu", i);
		f[i].symbol = names[i];
		s[i].stack = &f[i];
		s[i].nstack = 1;
	}
	memset(&pr, 0, sizeof(pr));
	pr.profile = "p";
	pr.sample_type = "samples";
	pr.sample_unit = "count";
	pr.samples = s;
	pr.nsamples = n;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	capture_start();
	json = oe_enc_profile(&enc, &pr, &len);
	err = capture_end();
	ATF_REQUIRE(json != NULL);
	ATF_CHECK(strstr(err, "samples dropped (the profile dictionary is "
	    "full)") != NULL);
	free(err);
	free(json);
	oe_enc_fini(&enc);
	free(s);
	free(f);
	free(names);
}

/* ---------------------------------------------------------------- */
/* Through the exporters						*/

static struct oe_exporter *
otlp_exporter(const char *protocol, const char *endpoint, const char *spool,
    int profiles)
{
	struct oe_otlp_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = endpoint;
	cfg.profile = "p";
	cfg.resource = resource();
	cfg.flush_interval = 30;
	cfg.max_retries = 0;
	cfg.timeout = 5;
	cfg.protocol = protocol;
	cfg.scope_name = "tool";
	cfg.spool_path = spool;
	cfg.profiles = profiles;
	return (oe_otlp_new(&cfg));
}

static void
emit_known(struct oe_exporter *e)
{
	struct oe_profile pr;
	struct oe_profile_sample s[4];
	struct oe_kv attr;

	known_profile(&pr, s, &attr);
	ATF_REQUIRE_EQ(0, oe_profile(e, &pr));
	/* An empty profile is not sent. */
	pr.nsamples = 0;
	ATF_REQUIRE_EQ(0, oe_profile(e, &pr));
}

ATF_TC_WITHOUT_HEAD(export_http_protobuf);
ATF_TC_BODY(export_http_protobuf, tc)
{
	struct collector co;
	struct oe_exporter *e;
	char ep[64], *got;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d/base", co.port);
	ATF_REQUIRE((e = otlp_exporter("http/protobuf", ep, NULL, 1)) !=
	    NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_known(e);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(1, coll_nreqs(&co));
	ATF_CHECK_STREQ("/base/v1development/profiles", co.reqs[0].path);
	ATF_CHECK(strstr(co.reqs[0].headers, "application/x-protobuf") !=
	    NULL);
	got = oracle_profile(tc, co.reqs[0].body, co.reqs[0].bodylen);
	ATF_CHECK_STREQ(known_resolved, got);
	free(got);
	coll_stop(&co);
}

ATF_TC_WITHOUT_HEAD(export_grpc);
ATF_TC_BODY(export_grpc, tc)
{
	struct gsrv s;
	struct oe_exporter *e;
	char ep[64], *got;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	ATF_REQUIRE((e = otlp_exporter("grpc", ep, NULL, 1)) != NULL);
	/* Not started: flush delivers queued requests itself. */
	emit_known(e);
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(1, gsrv_nreqs(&s));
	ATF_CHECK_STREQ("/opentelemetry.proto.collector.profiles."
	    "v1development.ProfilesService/Export", s.reqs[0].path);
	got = oracle_profile(tc, s.reqs[0].msg, s.reqs[0].msglen);
	ATF_CHECK_STREQ(known_resolved, got);
	free(got);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	gsrv_stop(&s);
}

/* Profiles are protobuf only: refused, or dropped, over http/json. */
ATF_TC_WITHOUT_HEAD(export_http_json);
ATF_TC_BODY(export_http_json, tc)
{
	struct collector co;
	struct oe_exporter *e;
	char ep[64], *err;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", co.port);
	capture_start();
	e = otlp_exporter("http/json", ep, NULL, 1);
	err = capture_end();
	ATF_CHECK(e == NULL);
	ATF_CHECK(strstr(err, "profiles are sent with the http/protobuf or "
	    "grpc protocol only") != NULL);
	free(err);
	/* A library caller that did not ask: dropped with one warning. */
	ATF_REQUIRE((e = otlp_exporter(NULL, ep, NULL, 0)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	capture_start();
	emit_known(e);
	emit_known(e);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	oe_exporter_free(e);
	ATF_CHECK_EQ(0, coll_nreqs(&co));
	ATF_CHECK(strstr(err, "dropped over http/json") != NULL);
	ATF_CHECK(strstr(strstr(err, "dropped over") + 1, "dropped over") ==
	    NULL);
	free(err);
	coll_stop(&co);
}

/* A profile that cannot be sent is spooled and replayed as profiles. */
ATF_TC_WITHOUT_HEAD(export_spool);
ATF_TC_BODY(export_spool, tc)
{
	struct collector co;
	struct oe_exporter *e;
	char ep[64], *spool, *got;

	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", closed_port());
	ATF_REQUIRE((e = otlp_exporter("http/protobuf", ep, "p.spool", 1)) !=
	    NULL);
	capture_start();
	emit_known(e);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	free(capture_end());
	oe_exporter_free(e);
	spool = read_file("p.spool");
	ATF_CHECK_EQ(OE_SIGNAL_PROFILES, oe_enc_classify(spool));
	free(spool);
	/* Replayed to a collector that answers, after the next request. */
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", co.port);
	ATF_REQUIRE((e = otlp_exporter("http/protobuf", ep, "p.spool", 1)) !=
	    NULL);
	emit_known(e);
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	free(capture_end());
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(2, coll_nreqs(&co));
	ATF_CHECK_STREQ("/v1development/profiles", co.reqs[1].path);
	got = oracle_profile(tc, co.reqs[1].body, co.reqs[1].bodylen);
	ATF_CHECK_STREQ(known_resolved, got);
	free(got);
	coll_stop(&co);
}

/* The OTLP JSON Lines file exporter: one line per profile. */
ATF_TC_WITHOUT_HEAD(otlpjson_line);
ATF_TC_BODY(otlpjson_line, tc)
{
	struct oe_sink_config sc;
	struct oe_otlpjson_config jc;
	struct oe_exporter *e;
	struct oe_sink *sink;
	struct otlp_counts c;
	char *text, *nl;

	memset(&sc, 0, sizeof(sc));
	sc.path = "out.jsonl";
	ATF_REQUIRE((sink = oe_sink_open(&sc)) != NULL);
	memset(&jc, 0, sizeof(jc));
	jc.sink = sink;
	jc.profile = "p";
	jc.resource = resource();
	jc.scope_name = "tool";
	ATF_REQUIRE((e = oe_otlpjson_new(&jc)) != NULL);
	emit_known(e);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(0, oe_sink_close(sink));
	text = read_file("out.jsonl");
	ATF_REQUIRE((nl = strchr(text, '\n')) != NULL);
	ATF_CHECK_EQ('\0', nl[1]);
	validate_json(text, (size_t)(nl - text), &c);
	ATF_CHECK_EQ(3, c.samples);
	free(text);
	/* Exporters without profile support accept and ignore profiles. */
	ATF_REQUIRE((e = oe_text_new(stdout)) != NULL);
	emit_known(e);
	oe_exporter_free(e);
}

/* ---------------------------------------------------------------- */
/* Exemplars								*/

static const uint8_t ex_trace[OE_TRACE_ID_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t ex_span[OE_SPAN_ID_LEN] = { 17, 18, 19, 20, 21, 22,
    23, 24 };

static void
exemplars(struct oe_exemplar ex[3], struct oe_kv *kv)
{

	memset(ex, 0, 3 * sizeof(*ex));
	ex[0].ts.tv_sec = 1700000000;
	ex[0].ivalue = 42;
	memcpy(ex[0].trace_id, ex_trace, OE_TRACE_ID_LEN);
	memcpy(ex[0].span_id, ex_span, OE_SPAN_ID_LEN);
	kv[0].key = "http.route";
	kv[0].type = OE_VAL_STRING;
	kv[0].s = "/a";
	ex[0].attrs = kv;
	ex[0].nattrs = 1;
	/* A trace without a span, and a double without any trace. */
	ex[1].ts.tv_sec = 1700000001;
	ex[1].ivalue = -1;
	memcpy(ex[1].trace_id, ex_trace, OE_TRACE_ID_LEN);
	ex[2].ts.tv_sec = 1700000002;
	ex[2].is_double = 1;
	ex[2].dvalue = 0.5;
}

ATF_TC_WITHOUT_HEAD(exemplar_points);
ATF_TC_BODY(exemplar_points, tc)
{
	static const enum oe_agg_kind kinds[] = { OE_AGG_COUNT, OE_AGG_MAX,
	    OE_AGG_AVG, OE_AGG_LQUANTIZE, OE_AGG_QUANTIZE };
	struct oe_otlpenc enc;
	struct oe_otlppb_defs defs;
	struct oe_snapshot sn;
	struct oe_datapoint dp;
	struct oe_exemplar ex[3];
	struct oe_bucket b[2] = { { 10, 1 }, { INT64_MAX, 2 } };
	uint64_t pos[1] = { 3 };
	struct oe_exphist eh;
	struct oe_kv kv;
	struct otlp_counts c;
	char *frag, *req, *pb, *dec, err[256], *frags[1], name[8];
	size_t len, pblen, i;

	exemplars(ex, &kv);
	memset(&eh, 0, sizeof(eh));
	eh.positive.counts = pos;
	eh.positive.n = 1;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, resource(), "tool"));
	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&defs));
	for (i = 0; i < nitems(kinds); i++) {
		memset(&dp, 0, sizeof(dp));
		dp.scalar = 3;
		dp.exemplars = ex;
		dp.nexemplars = 3;
		if (kinds[i] == OE_AGG_AVG) {
			dp.has_stats = 1;
			dp.count = 2;
			dp.sum = 4;
		} else if (kinds[i] == OE_AGG_LQUANTIZE) {
			dp.is_histogram = 1;
			dp.buckets = b;
			dp.nbuckets = 2;
		} else if (kinds[i] == OE_AGG_QUANTIZE) {
			dp.is_histogram = 1;
			dp.exp = &eh;
		}
		memset(&sn, 0, sizeof(sn));
		sn.ts.tv_sec = 1700000010;
		sn.profile = "p";
		snprintf(name, sizeof(name), "m%zu", i);
		sn.name = name;
		sn.kind = kinds[i];
		sn.points = &dp;
		sn.npoints = 1;
		ATF_REQUIRE((frag = oe_enc_metric(&enc, &sn)) != NULL);
		frags[0] = frag;
		ATF_REQUIRE((req = oe_enc_request(&enc, OE_SIGNAL_METRICS,
		    frags, 1, &len)) != NULL);
		/* The independent validator knows Exemplar everywhere. */
		validate_json(req, len, &c);
		ATF_CHECK(strstr(req, "\"exemplars\":[{\"timeUnixNano\":"
		    "\"1700000000000000000\",\"asInt\":\"42\",\"traceId\":"
		    "\"0102030405060708090a0b0c0d0e0f10\",\"spanId\":"
		    "\"1112131415161718\",\"filteredAttributes\":[{\"key\":"
		    "\"http.route\",\"value\":{\"stringValue\":\"/a\"}}]},"
		    "{\"timeUnixNano\":\"1700000001000000000\",\"asInt\":"
		    "\"-1\",\"traceId\":\"0102030405060708090a0b0c0d0e0f10\"},"
		    "{\"timeUnixNano\":\"1700000002000000000\",\"asDouble\":"
		    "0.5}]") != NULL);
		ATF_REQUIRE_EQ_MSG(0, oe_otlppb_encode(&defs,
		    OE_SIGNAL_METRICS, req, len, &pb, &pblen, err,
		    sizeof(err)), "%s", err);
		write_file("m.json", req, len);
		write_file("m.pb", pb, pblen);
		ATF_CHECK_EQ_MSG(0, run_oracle(tc, "compare m.json m.pb",
		    "cmp.txt"), "%s", read_file("cmp.txt"));
		/* The C++ runtime sees the trace ids as bytes (base64). */
		ATF_CHECK_EQ(0, run_oracle(tc, "decode metrics m.pb",
		    "dec.txt"));
		dec = read_file("dec.txt");
		ATF_CHECK(strstr(dec, "\"traceId\":\"AQIDBAUGBwgJCgsMDQ4PEA==\"")
		    != NULL);
		ATF_CHECK(strstr(dec, "\"spanId\":\"ERITFBUWFxg=\"") != NULL);
		free(dec);
		free(pb);
		free(req);
		free(frag);
	}
	oe_otlppb_defs_fini(&defs);
	oe_enc_fini(&enc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, profdict_tables);
	ATF_TP_ADD_TC(tp, profdict_shapes);
	ATF_TP_ADD_TC(tp, profdict_bounds);
	ATF_TP_ADD_TC(tp, profdict_oom);
	ATF_TP_ADD_TC(tp, profile_request);
	ATF_TP_ADD_TC(tp, profile_golden);
	ATF_TP_ADD_TC(tp, profile_values);
	ATF_TP_ADD_TC(tp, profile_dropped);
	ATF_TP_ADD_TC(tp, profile_large_keys);
	ATF_TP_ADD_TC(tp, profdict_forms);
	ATF_TP_ADD_TC(tp, profdict_growth_oom);
	ATF_TP_ADD_TC(tp, export_oom);
	ATF_TP_ADD_TC(tp, export_http_protobuf);
	ATF_TP_ADD_TC(tp, export_grpc);
	ATF_TP_ADD_TC(tp, export_http_json);
	ATF_TP_ADD_TC(tp, export_spool);
	ATF_TP_ADD_TC(tp, otlpjson_line);
	ATF_TP_ADD_TC(tp, exemplar_points);
	return (atf_no_error());
}
