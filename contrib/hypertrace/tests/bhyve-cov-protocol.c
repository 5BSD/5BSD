/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Protocol-level tests of the migration session core in migration_session.c
 * (production compile configuration, linked into the bhyve-cov-adapter
 * binary and run with the "protocol" argument).
 *
 * Real migration_source_run() and migration_dest_run() talk through real
 * descriptors (migration_transport_fd_init) with a man-in-the-middle thread
 * that forwards frames and, in mutation runs, alters exactly one frame.  The
 * endpoints use small in-memory VM models.  Oracles are independent of the
 * implementation and checked for every run:
 *
 *   O1  a source that reports success is retired and defunct, the destination
 *       resumed exactly once, and its RAM and device state equal the source's
 *       state at quiesce;
 *   O2  a destination that resumed did so only after the source retired, with
 *       exactly the source's RAM and device state (integrity);
 *   O3  a source reported runnable is not quiesced and was never retired;
 *       a source not reported runnable is retired or wedged in quiesce;
 *   O4  so_resume is never called after so_retire (no resume after
 *       retirement began);
 *   O5  a frame whose bytes were corrupted without recomputing its CRC is
 *       never accepted (at least one endpoint fails, nothing resumes on
 *       altered data).
 *
 * Mutation kinds cover integrity (byte flips), framing (truncation, close,
 * duplicate, sequence, version, type, flags, length) and semantic fields of
 * each structured payload (re-encoded with a valid CRC).  Callback failures
 * of every source and destination operation are injected separately.
 */
#include <sys/param.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha256.h>
#include <zlib.h>

#include "migration_session.h"
#include "migration_commit.h"
#include "migration_recovery_phase.h"

/* Harness allocations bypass a malloc wrapper that faults session code. */
extern void *__real_malloc(size_t) __attribute__((weak));
extern void *__real_calloc(size_t, size_t) __attribute__((weak));
static __attribute__((unused)) void *hmalloc(size_t n) { return (__real_malloc != NULL ? __real_malloc(n) : malloc(n)); }
static __attribute__((unused)) void *hcalloc(size_t n, size_t m)
{ return (__real_calloc != NULL ? __real_calloc(n, m) : calloc(n, m)); }
static __attribute__((unused)) void *hrealloc(void *p, size_t n) { return (realloc(p, n)); }

#define PCHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: PCHECK(%s) failed [%s]\n", \
	__FILE__, __LINE__, #x, current_label); abort(); } } while (0)

static char current_label[160];

/* -------------------------------------------------------------- models */
#define PAGE 4096U
enum op {
	OP_NONE, S_HELLO, S_TOPOLOGY, S_ENABLE, S_ROUND, S_DISABLE, S_QUIESCE,
	S_QUIESCE_WEDGE, S_RESUME, S_DEV_STATE, S_RETIRE, S_RECORD_INTENT,
	S_RECORD_RETIRED, S_RECORD_RELEASED, S_RECORD_CONFIRMED, S_ACCEPT,
	S_ROUND_BADLEN, S_ROUND_STALL, S_DEV_NULL, S_DEV_HUGE,
	S_HELLO_BADCAPS, S_TOPOLOGY_HUGE, S_TOPOLOGY_BADMEM, S_ROUND_OVERFLOW,
	S_DEV_EMPTY,
	D_HELLO, D_TOPOLOGY, D_STAGE_MEM, D_STAGE_DEV, D_COMMIT, D_RESUME,
	D_PREPARE, D_PREPARE_CHALLENGE, D_PRESERVE, D_RECORD_STAGED,
	D_RECORD_RELEASED, D_RECORD_RUNNING, OP_LAST,
};
static const char *op_names[] = {
	"none", "so_local_hello", "so_local_topology", "so_precopy_enable",
	"so_precopy_round", "so_precopy_disable", "so_quiesce",
	"so_quiesce(wedged)", "so_resume", "so_dev_state", "so_retire",
	"so_record(INTENT)", "so_record(RETIRED)", "so_record(RELEASED)",
	"so_record(CONFIRMED)", "so_accept_commit", "so_precopy_round(bad length)",
	"so_precopy_round(no progress)", "so_dev_state(NULL)", "so_dev_state(huge)",
	"so_local_hello(unknown capability)", "so_local_topology(too many devices)",
	"so_local_topology(inconsistent memory)", "so_precopy_round(dirty count overflow)",
	"so_dev_state(empty)",
	"do_local_hello", "do_local_topology", "do_stage_mem", "do_stage_dev",
	"do_commit", "do_resume", "do_prepare_commit",
	"do_prepare_commit(challenge)", "do_preserve", "do_record(STAGED)",
	"do_record(RELEASED)", "do_record(RUNNING)",
};

struct config_model {
	size_t pages;		/* guest RAM pages */
	size_t dev_len;		/* device state bytes */
	bool fresh;
	bool preserve;
	int fail;		/* enum op to fail */
	int fail_error;
	uint32_t ncpus_dest;	/* topology mismatch knob */
	uint64_t hello_caps_dest;
	uint64_t converge_pages;	/* session convergence ceiling */
	bool cancel_on_converge;	/* operator cancels as pre-copy converges */
};
static volatile int run_cancel;

struct source_model {
	const struct config_model *cfg;
	uint8_t *ram, *dirty, *bitmap;
	size_t cursor;
	bool gen_active;
	uint64_t gen_total;
	int generations;
	int round_calls;
	bool enabled, quiesced, retired, defunct, resumed_after_retire;
	int resumes, records[8], nrecords;
	uint8_t challenge[32];
	uint8_t ram_at_quiesce_digest[32];
	uint8_t *dev;
};

struct dest_model {
	const struct config_model *cfg;
	uint8_t *ram;
	uint8_t *dev;
	size_t dev_len;
	bool committed, discarded, retained;
	int resumes, records[8], nrecords;
	bool resumed_before_source_retired;
	struct source_model *peer;	/* observes the source for O2 only */
};

static int
fail_if(const struct config_model *cfg, enum op op)
{
	return (cfg->fail == (int)op ? (cfg->fail_error != 0 ? cfg->fail_error : EIO) : 0);
}

static void
fill_hello(struct migration_hello *h, bool fresh)
{
	memset(h, 0, sizeof(*h));
	h->version_max = MIGRATION_PROTO_VERSION;
	h->version_min = MIGRATION_PROTO_VERSION_MIN;
	h->arch_id = 0x8664;
	h->page_size = PAGE;
	h->cpu_family = 6;
	h->cpu_model = 0x55;
	h->cpu_stepping = 4;
	h->cpu_feature_hash = 0x1122334455667788ULL;
	h->intr_controller = 1;
	h->capability_flags = MIGRATION_CAP_PRECOPY | MIGRATION_CAP_DEVICE_DIRTY |
	    (fresh ? MIGRATION_CAP_HYPERTRACE_FRESH : 0);
	strlcpy(h->machine_abi, "bhyve-protocol-test", sizeof(h->machine_abi));
}

static void
fill_topology(struct migration_topology *t, size_t pages, uint32_t ncpus)
{
	memset(t, 0, sizeof(*t));
	t->lowmem = (uint64_t)pages * PAGE;
	t->mem_size = t->lowmem;
	t->ncpus = ncpus;
	t->sockets = 1;
	t->cores = ncpus;
	t->threads = 1;
	t->device_count = 2;
	for (int i = 0; i < 2; i++) {
		snprintf(t->devices[i].name, sizeof(t->devices[i].name), "dev%d", i);
		t->devices[i].migration_flags = MIGRATION_DEVF_STATE_CODEC |
		    (i == 0 ? MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_NONE |
		    MIGRATION_DEVF_QUIESCE_NONE : MIGRATION_DEVF_COMPAT_CALLBACK |
		    MIGRATION_DEVF_DMA_TRACKED | MIGRATION_DEVF_QUIESCE_CALLBACK);
		t->devices[i].compat_schema = 1;
		t->devices[i].compat_crc32 = 0x1000 + i;
		t->devices[i].bar_hash = 0x2000 + i;
	}
}

static void
digest(const uint8_t *p, size_t n, uint8_t out[32])
{
	SHA256_CTX c;

	SHA256_Init(&c);
	SHA256_Update(&c, p, n);
	SHA256_Final(out, &c);
}

/* ---- source ops ---- */
static int
s_hello(void *arg, struct migration_hello *h)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_HELLO);

	if (e == 0)
		fill_hello(h, s->cfg->fresh);
	if (e == 0 && s->cfg->fail == S_HELLO_BADCAPS)
		h->capability_flags |= 1ULL << 40;	/* unknown to the protocol */
	return (e);
}

static int
s_topology(void *arg, struct migration_topology *t)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_TOPOLOGY);

	if (e == 0)
		fill_topology(t, s->cfg->pages, 2);
	if (e == 0 && s->cfg->fail == S_TOPOLOGY_HUGE)
		t->device_count = MIGRATION_MAX_DEVICES + 1;
	if (e == 0 && s->cfg->fail == S_TOPOLOGY_BADMEM)
		t->mem_size += PAGE;	/* lowmem + highmem no longer sum to it */
	return (e);
}

static int
s_enable(void *arg)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_ENABLE);

	if (e != 0)
		return (e);
	s->enabled = true;
	memset(s->dirty, 0xff, (s->cfg->pages + 7) / 8);	/* first generation: all */
	return (0);
}

static void
guest_dirty(struct source_model *s)
{
	/* The running guest dirties fewer pages each generation. */
	int n = 4 - s->generations;

	for (int i = 0; i < n; i++) {
		size_t page = (size_t)(s->generations * 7 + i * 3) % s->cfg->pages;
		s->ram[page * PAGE + (size_t)s->generations] ^= 0x5a;
		s->dirty[page / 8] |= (uint8_t)(1U << (page % 8));
	}
}

static int
s_round(void *arg, bool final, struct migration_memgen *gen, uint8_t *buf,
    size_t cap, size_t *written, uint64_t *dirty_pages, bool *converged, bool *more)
{
	struct source_model *s = arg;
	size_t off = 0, count = 0, bytes = (s->cfg->pages + 7) / 8;
	int e = fail_if(s->cfg, S_ROUND);

	(void)final;
	s->round_calls++;
	if (e != 0)
		return (e);
	if (s->cfg->fail == S_ROUND_BADLEN) {
		*written = cap + 1;
		return (0);
	}
	if (s->cfg->fail == S_ROUND_STALL) {
		*written = 0;
		*more = true;
		return (0);
	}
	if (!s->gen_active) {
		memcpy(s->bitmap, s->dirty, bytes);
		memset(s->dirty, 0, bytes);
		s->cursor = 0;
		s->gen_total = 0;
		s->gen_active = true;
	}
	*more = false;
	while (s->cursor < s->cfg->pages) {
		size_t p = s->cursor;
		if ((s->bitmap[p / 8] & (1U << (p % 8))) == 0) {
			s->cursor++;
			continue;
		}
		if (off + 12 + PAGE > cap) {
			*more = true;
			break;
		}
		le64enc(buf + off, (uint64_t)p * PAGE);
		le32enc(buf + off + 8, PAGE);
		memcpy(buf + off + 12, s->ram + p * PAGE, PAGE);
		off += 12 + PAGE;
		count++;
		s->cursor++;
	}
	s->gen_total += count;
	memset(gen, 0, sizeof(*gen));
	gen->mode = 2;	/* CLEAR */
	gen->gpa = 0;
	gen->length = (uint64_t)s->cfg->pages * PAGE;
	gen->page_count = (uint32_t)count;
	gen->cpu_identity = 1;
	gen->cpu_map_generation = 1;
	gen->cpu_dirty_generation = (uint64_t)s->generations + 1;
	*written = off;
	*dirty_pages = count;
	/* A generation whose continuation reports more dirty pages than can be
	 * counted: the first chunk stops early, the second overflows. */
	if (s->cfg->fail == S_ROUND_OVERFLOW && s->round_calls == 1) {
		*more = true;
		s->gen_active = true;
	}
	if (s->cfg->fail == S_ROUND_OVERFLOW && s->round_calls == 2)
		*dirty_pages = UINT64_MAX;
	*converged = !*more && s->gen_total == 0;
	if (s->cfg->cancel_on_converge && !*more &&
	    (*converged || (s->cfg->converge_pages != 0 && count <= s->cfg->converge_pages)))
		run_cancel = 1;
	if (!*more) {
		s->gen_active = false;
		s->generations++;
		if (!s->quiesced)
			guest_dirty(s);
	}
	return (0);
}

static int
s_disable(void *arg)
{
	struct source_model *s = arg;

	s->enabled = false;
	return (fail_if(s->cfg, S_DISABLE));
}

static int
s_quiesce(void *arg, bool *runnable)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_QUIESCE);

	if (e != 0) {
		*runnable = true;
		return (e);
	}
	if (s->cfg->fail == S_QUIESCE_WEDGE) {
		*runnable = false;
		s->quiesced = true;
		return (EIO);
	}
	s->quiesced = true;
	return (0);
}

static int
s_resume(void *arg)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_RESUME);

	if (s->retired)
		s->resumed_after_retire = true;
	if (e != 0)
		return (e);
	s->quiesced = false;
	s->resumes++;
	return (0);
}

static int
s_dev_state(void *arg, uint8_t **buf, size_t *len)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_DEV_STATE);

	if (e != 0)
		return (e);
	digest(s->ram, s->cfg->pages * PAGE, s->ram_at_quiesce_digest);
	if (s->cfg->fail == S_DEV_NULL) {
		*buf = NULL;
		*len = 1;
		return (0);
	}
	if (s->cfg->fail == S_DEV_EMPTY) {
		*buf = NULL;	/* a legitimately empty state */
		*len = 0;
		return (0);
	}
	if (s->cfg->fail == S_DEV_HUGE) {
		*buf = hmalloc(1);
		*len = (size_t)MIGRATION_MAX_DEV_STATE + 1;
		return (0);
	}
	*buf = hmalloc(s->cfg->dev_len != 0 ? s->cfg->dev_len : 1);
	memcpy(*buf, s->dev, s->cfg->dev_len);
	*len = s->cfg->dev_len;
	return (0);
}

static void
s_defunct(void *arg)
{
	struct source_model *s = arg;

	PCHECK(s->retired);
	s->defunct = true;
}

static int
s_retire(void *arg)
{
	struct source_model *s = arg;
	int e = fail_if(s->cfg, S_RETIRE);

	PCHECK(s->quiesced);
	s->retired = true;	/* even a failed retirement may have begun */
	return (e);
}

static int
s_record(void *arg, enum migration_recovery_phase phase, const uint8_t challenge[32])
{
	struct source_model *s = arg;
	static const enum op ops[] = { [MIGRATION_REC_SOURCE_INTENT] = S_RECORD_INTENT,
	    [MIGRATION_REC_SOURCE_RETIRED] = S_RECORD_RETIRED,
	    [MIGRATION_REC_SOURCE_RELEASED] = S_RECORD_RELEASED,
	    [MIGRATION_REC_SOURCE_CONFIRMED] = S_RECORD_CONFIRMED };

	PCHECK(phase >= MIGRATION_REC_SOURCE_INTENT && phase <= MIGRATION_REC_SOURCE_CONFIRMED);
	PCHECK(memcmp(challenge, s->challenge, 32) == 0);
	PCHECK(s->nrecords < 8);
	s->records[s->nrecords++] = phase;
	return (fail_if(s->cfg, ops[phase]));
}

static int
s_accept(void *arg, const struct migration_commit_binding *b)
{
	struct source_model *s = arg;
	uint8_t d[32];
	int e = fail_if(s->cfg, S_ACCEPT);

	if (e != 0)
		return (e);
	/* Independent integrity check of the transferred device state. */
	digest(s->dev, s->cfg->dev_len, d);
	if (b->destination_vmid != 5 || b->destination_epoch != 50 ||
	    memcmp(b->state_digest, d, 32) != 0)
		return (EPROTO);
	memcpy(s->challenge, b->challenge, 32);
	return (0);
}

static const struct migration_source_ops source_ops = {
	.so_local_hello = s_hello, .so_local_topology = s_topology,
	.so_precopy_enable = s_enable, .so_precopy_round = s_round,
	.so_precopy_disable = s_disable, .so_quiesce = s_quiesce,
	.so_resume = s_resume, .so_dev_state = s_dev_state,
	.so_defunct = s_defunct, .so_retire = s_retire, .so_record = s_record,
	.so_accept_commit = s_accept,
};

/* ---- destination ops ---- */
static int
d_hello(void *arg, struct migration_hello *h)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_HELLO);

	if (e == 0) {
		fill_hello(h, d->cfg->fresh);
		if (d->cfg->hello_caps_dest != 0)
			h->capability_flags = d->cfg->hello_caps_dest;
	}
	return (e);
}

static int
d_topology(void *arg, struct migration_topology *t)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_TOPOLOGY);

	if (e == 0)
		fill_topology(t, d->cfg->pages, d->cfg->ncpus_dest ? d->cfg->ncpus_dest : 2);
	return (e);
}

static int
d_stage_mem(void *arg, const struct migration_memgen *gen, const uint8_t *buf, size_t len)
{
	struct dest_model *d = arg;
	size_t off = 0;
	int e = fail_if(d->cfg, D_STAGE_MEM);

	PCHECK(!d->committed);
	if (e != 0)
		return (e);
	if (gen->length != (uint64_t)d->cfg->pages * PAGE || gen->gpa != 0)
		return (EBADMSG);
	while (off + 12 <= len) {
		uint64_t gpa = le64dec(buf + off);
		uint32_t plen = le32dec(buf + off + 8);
		if (plen != PAGE || gpa % PAGE != 0 || gpa >= gen->length ||
		    off + 12 + plen > len)
			return (EBADMSG);
		memcpy(d->ram + gpa, buf + off + 12, PAGE);
		off += 12 + plen;
	}
	return (off == len ? 0 : EBADMSG);
}

static int
d_stage_dev(void *arg, const uint8_t *buf, size_t len)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_STAGE_DEV);

	if (e != 0)
		return (e);
	free(d->dev);
	d->dev = hmalloc(len != 0 ? len : 1);
	memcpy(d->dev, buf, len);
	d->dev_len = len;
	return (0);
}

static int
d_commit(void *arg)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_COMMIT);

	if (e == 0)
		d->committed = true;
	return (e);
}

static int
d_resume(void *arg)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_RESUME);

	PCHECK(d->committed);
	if (e != 0)
		return (e);
	if (!d->peer->retired)
		d->resumed_before_source_retired = true;
	d->resumes++;
	return (0);
}

static void
d_discard(void *arg)
{
	struct dest_model *d = arg;

	d->discarded = true;
}

static int
d_record(void *arg, enum migration_recovery_phase phase, const uint8_t challenge[32])
{
	struct dest_model *d = arg;
	int e = 0;

	(void)challenge;
	PCHECK(d->nrecords < 8);
	d->records[d->nrecords++] = phase;
	if (phase == MIGRATION_REC_DEST_STAGED)
		e = fail_if(d->cfg, D_RECORD_STAGED);
	else if (phase == MIGRATION_REC_DEST_RELEASED)
		e = fail_if(d->cfg, D_RECORD_RELEASED);
	else if (phase == MIGRATION_REC_DEST_RUNNING)
		e = fail_if(d->cfg, D_RECORD_RUNNING);
	return (e);
}

static int
d_prepare(void *arg, struct migration_commit_binding *b)
{
	struct dest_model *d = arg;
	int e = fail_if(d->cfg, D_PREPARE);

	if (e != 0)
		return (e);
	b->destination_vmid = 5;
	b->destination_epoch = 50;
	digest(d->dev, d->dev_len, b->state_digest);
	if (d->cfg->fail == D_PREPARE_CHALLENGE)
		b->challenge[0] ^= 1;
	return (0);
}

static void
d_retain(void *arg, const struct migration_commit_binding *b)
{
	struct dest_model *d = arg;

	(void)b;
	PCHECK(d->committed);
	d->retained = true;
}

static int
d_preserve(void *arg, const struct migration_commit_binding *b)
{
	struct dest_model *d = arg;

	(void)b;
	PCHECK(d->committed);
	return (fail_if(d->cfg, D_PRESERVE));
}

/* ------------------------------------------------- man in the middle */
enum mutation {
	MUT_NONE, MUT_FLIP_PAYLOAD, MUT_FLIP_HEADER_MAGIC, MUT_FLIP_HEADER_CRC,
	MUT_TRUNCATE, MUT_DROP_CLOSE, MUT_DUPLICATE, MUT_SEQ, MUT_VERSION,
	MUT_TYPE, MUT_FLAGS, MUT_SHORTER, MUT_LONGER, MUT_ABORT, MUT_FIELD,
	MUT_LAST,
};
static const char *mutation_names[] = {
	"none", "flip-payload", "flip-magic", "flip-crc", "truncate", "drop-close",
	"duplicate", "sequence", "version", "type", "flags", "shorter", "longer",
	"abort", "field",
};

struct mitm {
	int in, out;		/* read from in, write to out */
	int direction;		/* 0: source->destination, 1: reverse */
	int target_index, mutation, variant;
	int frames;
	uint16_t types[256];
	bool mutated;
};

static bool
read_full(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;

	while (n > 0) {
		ssize_t r = read(fd, p, n);
		if (r <= 0)
			return (false);
		p += r;
		n -= (size_t)r;
	}
	return (true);
}

static bool
write_full(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;

	while (n > 0) {
		ssize_t r = write(fd, p, n);
		if (r <= 0)
			return (false);
		p += r;
		n -= (size_t)r;
	}
	return (true);
}

/* Independent frame writer (wire layout from the protocol definition), so
 * deliberately invalid headers can be produced. */
static bool
send_frame(int fd, uint16_t version, uint16_t type, uint32_t seq, uint32_t flags,
    const uint8_t *payload, size_t len)
{
	size_t total = MIGRATION_FRAME_HDR_SIZE + len;
	uint8_t *frame = hmalloc(total);
	bool ok;

	PCHECK(frame != NULL);
	le32enc(frame, MIGRATION_PROTO_MAGIC);
	le16enc(frame + 4, version);
	le16enc(frame + 6, type);
	le32enc(frame + 8, flags);
	le32enc(frame + 12, seq);
	le32enc(frame + 16, (uint32_t)len);
	le32enc(frame + 20, len == 0 ? 0 : (uint32_t)crc32(crc32(0, Z_NULL, 0), payload,
	    (uInt)len));
	if (len != 0)
		memcpy(frame + MIGRATION_FRAME_HDR_SIZE, payload, len);
	ok = write_full(fd, frame, total);
	free(frame);
	return (ok);
}

/* Semantic field mutation of a structured payload; variant selects a field.
 * Returns false when the variant does not apply to this frame type. */
static bool
mutate_field(uint16_t type, uint32_t flags, uint8_t **payload, size_t *len, int variant)
{
	uint8_t *p = *payload;

	switch (type) {
	case MIGRATION_MSG_HELLO: {
		struct migration_hello h;
		if (migration_hello_decode(p, *len, &h) != 0)
			return (false);
		switch (variant) {
		case 0: h.role = MIGRATION_ROLE_DEST; break;
		case 1: h.version_min = 9; h.version_max = 9; break;
		case 2: h.arch_id ^= 1; break;
		case 3: h.page_size = 8192; break;
		case 4: h.intr_controller = 9; break;
		case 5: strlcpy(h.machine_abi, "other-abi", sizeof(h.machine_abi)); break;
		case 6: h.cpu_feature_hash ^= 1; break;
		case 7: h.capability_flags &= ~MIGRATION_CAP_PRECOPY; break;
		case 8: h.capability_flags ^= MIGRATION_CAP_HYPERTRACE_FRESH; break;
		case 9: h.version_min = MIGRATION_PROTO_VERSION + 1;
			h.version_max = MIGRATION_PROTO_VERSION; break;	/* inverted window */
		default: return (false);
		}
		return (migration_hello_encode(&h, p, *len) == 0);
	}
	case MIGRATION_MSG_CAPS_ACCEPT: {
		struct migration_caps_accept c;
		if (migration_caps_accept_decode(p, *len, &c) != 0)
			return (false);
		switch (variant) {
		case 0: c.negotiated_version = 7; break;
		case 1: c.capability_flags |= 1ULL << 40; break;
		case 2: c.capability_flags ^= MIGRATION_CAP_HYPERTRACE_FRESH; break;
		case 3: c.capability_flags &= ~MIGRATION_CAP_PRECOPY; break;
		case 4: c.negotiated_version = 0; break;	/* below version_min */
		default: return (false);
		}
		return (migration_caps_accept_encode(&c, p, *len) == 0);
	}
	case MIGRATION_MSG_TOPOLOGY: {
		struct migration_topology *t = hcalloc(1, sizeof(*t));
		size_t wrote;
		bool ok = migration_topology_decode(p, *len, t) == 0;
		if (ok) {
			switch (variant) {
			case 0: t->mem_size += PAGE; break;
			case 1: t->ncpus = 3; break;
			case 2: t->devices[1].migration_flags |= MIGRATION_DEVF_DMA_NONE; break;
			case 3: t->devices[0].compat_crc32 ^= 1; break;
			case 4: t->devices[1].bar_hash ^= 1; break;
			case 5: t->device_count = 1; break;
			case 6: t->devices[0].name[0] = 'X'; break;
			case 7: t->lowmem = 0; t->mem_size = 0; break;
			case 8: t->sockets = 2; break;
			case 9: t->devices[0].compat_schema = 9; break;
			case 10: t->devices[0].migration_flags = 0; break;
			default: ok = false;
			}
		}
		if (ok) {
			size_t size = migration_topology_wire_size(t);
			uint8_t *wire = hmalloc(size != 0 ? size : 1);
			ok = size != 0 && migration_topology_encode(t, wire, size, &wrote) == 0;
			if (ok) {
				free(*payload);
				*payload = wire;
				*len = wrote;
			} else
				free(wire);
		}
		free(t);
		return (ok);
	}
	case MIGRATION_MSG_MEM_GEN: {
		struct migration_memgen g;
		if (*len < MIGRATION_MEMGEN_HDR_SIZE ||
		    migration_memgen_decode(p, *len, &g) != 0)
			return (false);
		if ((flags & MIGRATION_FFLAG_CHUNK) != 0 && variant >= 6) {
			struct migration_chunk c;
			if (*len < MIGRATION_MEMGEN_HDR_SIZE + MIGRATION_CHUNK_HDR_SIZE ||
			    migration_chunk_decode(p + MIGRATION_MEMGEN_HDR_SIZE,
			    MIGRATION_CHUNK_HDR_SIZE, &c) != 0)
				return (false);
			switch (variant) {
			case 6: c.offset += PAGE; break;
			case 7: c.total_length = 1; break;
			case 8: c.chunk_length += 1; break;
			case 9: c.final = 2; break;
			/* A continuation naming another generation. */
			case 10: g.cpu_map_generation ^= 1; break;
			case 11: g.cpu_dirty_generation ^= 1; break;
			case 12: g.device_identity ^= 1; break;
			case 13: g.device_dirty_generation ^= 1; break;
			case 14:
				/* An empty chunk that does not end the stream. */
				c.chunk_length = 0;
				c.final = 0;
				*len = MIGRATION_MEMGEN_HDR_SIZE + MIGRATION_CHUNK_HDR_SIZE;
				break;
			default: return (false);
			}
			if (variant >= 10 && variant <= 13 &&
			    migration_memgen_encode(&g, p, MIGRATION_MEMGEN_HDR_SIZE) != 0)
				return (false);
			return (migration_chunk_encode(&c, p + MIGRATION_MEMGEN_HDR_SIZE,
			    MIGRATION_CHUNK_HDR_SIZE) == 0);
		}
		switch (variant) {
		case 0: g.gpa = PAGE; break;
		case 1: g.length += PAGE; break;
		case 2: g.mode = 1; break;
		case 3: g.page_count += 1; break;
		case 4: g.final = 3; break;
		case 5: g.round = 0; break;
		default: return (false);
		}
		return (migration_memgen_encode(&g, p, MIGRATION_MEMGEN_HDR_SIZE) == 0);
	}
	case MIGRATION_MSG_DEV_STATE: {
		struct migration_chunk c;
		if ((flags & MIGRATION_FFLAG_CHUNK) == 0 || *len < MIGRATION_CHUNK_HDR_SIZE ||
		    migration_chunk_decode(p, MIGRATION_CHUNK_HDR_SIZE, &c) != 0)
			return (false);
		switch (variant) {
		case 0: c.total_length = 0; break;
		case 1: c.offset += 1; break;
		case 2: c.chunk_length -= 1; break;
		case 3: c.total_length += 1; break;
		case 4: c.final = c.final ? 0 : 1; break;
		case 5:
			/* A chunked frame shorter than its chunk header. */
			*len = MIGRATION_CHUNK_HDR_SIZE - 14;
			return (true);
		default: return (false);
		}
		return (migration_chunk_encode(&c, p, MIGRATION_CHUNK_HDR_SIZE) == 0);
	}
	case MIGRATION_MSG_RELEASE: {
		struct migration_reason_msg rm;
		if (*len < MIGRATION_REASON_SIZE ||
		    migration_reason_decode(p, MIGRATION_REASON_SIZE, &rm) != 0)
			return (false);
		switch (variant) {
		case 0: rm.detail = 7; break;		/* a success with detail */
		case 1: rm.reason_code = MIGRATION_REASON_STATE; break;
		case 2: p[*len - 1] ^= 1; return (true);	/* the challenge */
		default: return (false);
		}
		return (migration_reason_encode(&rm, p, MIGRATION_REASON_SIZE) == 0);
	}
	case MIGRATION_MSG_COMMIT: {
		if (*len != MIGRATION_FRESH_COMMIT_SIZE || variant > 3)
			return (false);
		p[variant == 0 ? 0 : variant == 1 ? 4 : variant == 2 ? 16 : 79] ^= 1;
		return (true);
	}
	case MIGRATION_MSG_FINAL:
	case MIGRATION_MSG_RELEASE_ACK:
	case MIGRATION_MSG_CAPS_REJECT:
	case MIGRATION_MSG_TOPO_REJECT:
		if (*len == 0 || variant > 1)
			return (false);
		p[variant == 0 ? 0 : *len - 1] ^= 1;
		return (true);
	default:
		return (false);
	}
}

static void *
mitm_main(void *arg)
{
	struct mitm *m = arg;
	uint8_t header[MIGRATION_FRAME_HDR_SIZE];

	for (;;) {
		struct migration_frame_header h;
		uint8_t *payload;
		size_t len;
		int index = m->frames;

		if (!read_full(m->in, header, sizeof(header)))
			break;
		if (migration_frame_decode_header(header, sizeof(header), &h) != 0)
			break;
		len = h.length;
		payload = hmalloc(len != 0 ? len : 1);
		PCHECK(payload != NULL);
		if (len != 0 && !read_full(m->in, payload, len)) {
			free(payload);
			break;
		}
		if (m->frames < 256)
			m->types[m->frames] = h.type;
		m->frames++;
		if (index != m->target_index || m->mutation == MUT_NONE) {
			bool ok = write_full(m->out, header, sizeof(header)) &&
			    (len == 0 || write_full(m->out, payload, len));
			free(payload);
			if (!ok)
				break;
			continue;
		}
		m->mutated = true;
		bool stop = false;
		switch (m->mutation) {
		case MUT_FLIP_PAYLOAD:
			if (len == 0)
				header[MIGRATION_FRAME_HDR_SIZE - 1] ^= 0x10;	/* CRC */
			else
				payload[(size_t)m->variant % len] ^= 0x01;
			stop = !write_full(m->out, header, sizeof(header)) ||
			    (len != 0 && !write_full(m->out, payload, len));
			break;
		case MUT_FLIP_HEADER_MAGIC:
			header[(size_t)m->variant % 20] ^= 0x40;
			stop = !write_full(m->out, header, sizeof(header)) ||
			    (len != 0 && !write_full(m->out, payload, len));
			break;
		case MUT_FLIP_HEADER_CRC:
			header[20] ^= 0x01;
			stop = !write_full(m->out, header, sizeof(header)) ||
			    (len != 0 && !write_full(m->out, payload, len));
			break;
		case MUT_TRUNCATE:
			(void)write_full(m->out, header, m->variant == 0 ? 10 : sizeof(header));
			if (m->variant == 1 && len > 1)
				(void)write_full(m->out, payload, len / 2);
			stop = true;
			break;
		case MUT_DROP_CLOSE:
			stop = true;
			break;
		case MUT_DUPLICATE:
			stop = !write_full(m->out, header, sizeof(header)) ||
			    (len != 0 && !write_full(m->out, payload, len)) ||
			    !write_full(m->out, header, sizeof(header)) ||
			    (len != 0 && !write_full(m->out, payload, len));
			break;
		case MUT_SEQ:
			stop = !send_frame(m->out, h.version, h.type,
			    m->variant == 0 ? h.seq + 1 : h.seq - 1, h.flags, payload, len);
			break;
		case MUT_VERSION:
			stop = !send_frame(m->out, (uint16_t)(h.version + 1), h.type, h.seq,
			    h.flags, payload, len);
			break;
		case MUT_TYPE: {
			uint16_t type = (uint16_t)(1 + (h.type + m->variant) % MIGRATION_MSG_RELEASE_ACK);
			if (type == h.type)
				type = (uint16_t)(type % MIGRATION_MSG_RELEASE_ACK + 1);
			stop = !send_frame(m->out, h.version, type, h.seq, h.flags, payload, len);
			break;
		}
		case MUT_FLAGS:
			stop = !send_frame(m->out, h.version, h.type, h.seq,
			    h.flags ^ MIGRATION_FFLAG_CHUNK, payload, len);
			break;
		case MUT_SHORTER:
			stop = !send_frame(m->out, h.version, h.type, h.seq, h.flags, payload,
			    len != 0 ? len - 1 : 0);
			break;
		case MUT_LONGER: {
			uint8_t *longer = hcalloc(1, len + 1);
			memcpy(longer, payload, len);
			stop = !send_frame(m->out, h.version, h.type, h.seq, h.flags, longer,
			    len + 1);
			free(longer);
			break;
		}
		case MUT_ABORT: {
			struct migration_reason_msg r = { .reason_code = MIGRATION_REASON_DEVICE,
			    .detail = 7 };
			uint8_t wire[MIGRATION_REASON_SIZE];
			PCHECK(migration_reason_encode(&r, wire, sizeof(wire)) == 0);
			stop = !send_frame(m->out, h.version, MIGRATION_MSG_ABORT, h.seq, 0,
			    m->variant == 0 ? wire : NULL, m->variant == 0 ? sizeof(wire) : 0);
			break;
		}
		case MUT_FIELD:
			if (!mutate_field(h.type, h.flags, &payload, &len, m->variant))
				m->mutated = false;
			stop = !send_frame(m->out, h.version, h.type, h.seq, h.flags, payload, len);
			break;
		}
		free(payload);
		if (stop)
			break;
	}
	shutdown(m->out, SHUT_WR);
	/* Drain so the writer never blocks on a full socket after we stop. */
	{
		uint8_t sink[4096];
		while (read(m->in, sink, sizeof(sink)) > 0)
			;
	}
	return (NULL);
}

/* ------------------------------------------------------------- run */
struct run_result {
	int source_error, dest_error;
	struct migration_source_result source;
	struct migration_dest_result dest;
	struct source_model s;
	struct dest_model d;
	bool mutated;
	int frames[2];
	uint16_t types[2][256];
};

struct endpoint_args {
	const struct migration_transport *xp;
	struct migration_session_config config;
	void *model;
	struct migration_dest_ops dops;
	int error;
	struct migration_source_result sresult;
	struct migration_dest_result dresult;
	int fd;
};

static void *
dest_thread(void *arg)
{
	struct endpoint_args *a = arg;

	a->error = migration_dest_run(a->xp, &a->dops, a->model, &a->config, &a->dresult);
	shutdown(a->fd, SHUT_RDWR);
	return (NULL);
}

/*
 * Transport faults: wrap an endpoint's transport so its n-th send or receive
 * fails with EIO without touching the descriptor (the peer sees silence or
 * a later close).  xp_fault_side 'S'/'D', xp_fault_recv, xp_fault_at; counts
 * of a baseline run are kept to enumerate every call.
 */
struct fault_xp {
	struct migration_transport inner;
	char side;
	int sends, recvs;
};
static char xp_fault_side;
static bool xp_fault_recv;
static int xp_fault_at, xp_counts[2][2];	/* [side][recv] */

static int
fault_xp_send(void *cookie, const void *buf, size_t len)
{
	struct fault_xp *f = cookie;
	int n = ++f->sends;
	if (xp_fault_side == f->side && !xp_fault_recv && n == xp_fault_at)
		return (EIO);
	return (f->inner.xp_send(f->inner.xp_cookie, buf, len));
}

static int
fault_xp_recv(void *cookie, void *buf, size_t len)
{
	struct fault_xp *f = cookie;
	int n = ++f->recvs;
	if (xp_fault_side == f->side && xp_fault_recv && n == xp_fault_at)
		return (EIO);
	return (f->inner.xp_recv(f->inner.xp_cookie, buf, len));
}

static void
run_once(const struct config_model *cfg, int direction, int index, int mutation,
    int variant, struct run_result *r)
{
	struct fault_xp sfx, dfx;
	struct migration_transport swrap, dwrap;
	int sd[2], dd[2];
	struct migration_transport sxp, dxp;
	struct migration_transport_fd sfd, dfd;
	struct mitm forward, backward;
	pthread_t f, b, dt;
	struct endpoint_args sa, da;
	size_t bytes = (cfg->pages + 7) / 8;

	memset(r, 0, sizeof(*r));
	r->s.cfg = cfg;
	r->s.ram = hmalloc(cfg->pages * PAGE);
	r->s.dirty = hcalloc(1, bytes);
	r->s.bitmap = hcalloc(1, bytes);
	r->s.dev = hmalloc(cfg->dev_len != 0 ? cfg->dev_len : 1);
	for (size_t i = 0; i < cfg->pages * PAGE; i++)
		r->s.ram[i] = (uint8_t)(i * 13 + i / PAGE);
	for (size_t i = 0; i < cfg->dev_len; i++)
		r->s.dev[i] = (uint8_t)(i * 7 + 3);
	r->d.cfg = cfg;
	r->d.ram = hcalloc(1, cfg->pages * PAGE);
	r->d.peer = &r->s;
	PCHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sd) == 0);
	PCHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, dd) == 0);
	memset(&forward, 0, sizeof(forward));
	memset(&backward, 0, sizeof(backward));
	forward.in = sd[1];
	forward.out = dd[1];
	backward.in = dd[1];
	backward.out = sd[1];
	forward.direction = 0;
	backward.direction = 1;
	forward.target_index = direction == 0 ? index : -1;
	backward.target_index = direction == 1 ? index : -1;
	forward.mutation = backward.mutation = mutation;
	forward.variant = backward.variant = variant;
	/* Two MITM threads share descriptors: each reads its own direction. */
	backward.in = dd[1];
	backward.out = sd[1];
	{
		int fdup = dup(sd[1]), bdup = dup(dd[1]);
		PCHECK(fdup >= 0 && bdup >= 0);
		forward.in = sd[1];
		forward.out = bdup;
		backward.in = dd[1];
		backward.out = fdup;
	}
	migration_transport_fd_init(&sxp, &sfd, sd[0], 5000);
	migration_transport_fd_init(&dxp, &dfd, dd[0], 5000);
	sfx = (struct fault_xp){ .inner = sxp, .side = 'S' };
	dfx = (struct fault_xp){ .inner = dxp, .side = 'D' };
	swrap = (struct migration_transport){ fault_xp_send, fault_xp_recv, &sfx };
	dwrap = (struct migration_transport){ fault_xp_send, fault_xp_recv, &dfx };
	memset(&sa, 0, sizeof(sa));
	memset(&da, 0, sizeof(da));
	sa.config.max_rounds = 6;
	sa.config.converge_pages = cfg->converge_pages;
	run_cancel = 0;
	sa.config.cancel = &run_cancel;
	da.xp = &dwrap;
	da.model = &r->d;
	da.fd = dd[0];
	da.dops = (struct migration_dest_ops){
		.do_local_hello = d_hello, .do_local_topology = d_topology,
		.do_stage_mem = d_stage_mem, .do_stage_dev = d_stage_dev,
		.do_commit = d_commit, .do_resume = d_resume, .do_discard = d_discard,
		.do_record = d_record, .do_prepare_commit = d_prepare,
		.do_retain = d_retain,
		.do_preserve = cfg->preserve ? d_preserve : NULL,
	};
	PCHECK(pthread_create(&f, NULL, mitm_main, &forward) == 0);
	PCHECK(pthread_create(&b, NULL, mitm_main, &backward) == 0);
	PCHECK(pthread_create(&dt, NULL, dest_thread, &da) == 0);
	r->source_error = migration_source_run(&swrap, &source_ops, &r->s, &sa.config,
	    &r->source);
	shutdown(sd[0], SHUT_RDWR);
	PCHECK(pthread_join(dt, NULL) == 0);
	r->dest_error = da.error;
	r->dest = da.dresult;
	xp_counts[0][0] = sfx.sends;
	xp_counts[0][1] = sfx.recvs;
	xp_counts[1][0] = dfx.sends;
	xp_counts[1][1] = dfx.recvs;
	shutdown(sd[1], SHUT_RDWR);
	shutdown(dd[1], SHUT_RDWR);
	PCHECK(pthread_join(f, NULL) == 0);
	PCHECK(pthread_join(b, NULL) == 0);
	close(sd[0]);
	close(sd[1]);
	close(dd[0]);
	close(dd[1]);
	close(forward.out);
	close(backward.out);
	r->mutated = forward.mutated || backward.mutated;
	r->frames[0] = forward.frames;
	r->frames[1] = backward.frames;
	memcpy(r->types[0], forward.types, sizeof(forward.types));
	memcpy(r->types[1], backward.types, sizeof(backward.types));
}

static void
free_run(struct run_result *r)
{
	free(r->s.ram);
	free(r->s.dirty);
	free(r->s.bitmap);
	free(r->s.dev);
	free(r->d.ram);
	free(r->d.dev);
}

static bool
dest_ram_matches(const struct run_result *r)
{
	uint8_t d[32];

	digest(r->d.ram, r->s.cfg->pages * PAGE, d);
	return (memcmp(d, r->s.ram_at_quiesce_digest, 32) == 0);
}

static bool
dest_dev_matches(const struct run_result *r)
{
	return (r->d.dev_len == r->s.cfg->dev_len &&
	    memcmp(r->d.dev, r->s.dev, r->s.cfg->dev_len) == 0);
}

/* A re-encoded frame with a valid CRC models an active network attacker.
 * The frame CRC detects accidental corruption only; without TLS such an
 * alteration of an ordinary migration can go undetected.  Fresh migration
 * binds the device state to COMMIT by digest, so altered device state must
 * never be resumed there; RAM is protected only by the TLS channel. */
static bool active_alteration;
static int undetected_alterations;

static bool
dest_matches_source(const struct run_result *r)
{
	bool ram = dest_ram_matches(r), dev = dest_dev_matches(r);

	if (!active_alteration)
		return (ram && dev);
	if (r->s.cfg->fresh && !dev)
		return (false);
	if (!ram || !dev)
		undetected_alterations++;
	return (true);
}

/* Ordinary (non-fresh) mode has no RELEASE acknowledgment: the source
 * becomes defunct after sending RELEASE, so a destination failure after
 * that point loses both copies.  Counted, reported, and allowed only when the
 * failure is at RELEASE or later. */
static int ordinary_losses;
static bool loss_allowed;

/* Oracles O1-O5. */
static void
check_run(const struct run_result *r, bool integrity_mutation)
{
	PCHECK(!r->s.resumed_after_retire);			/* O4 */
	PCHECK(r->d.resumes <= 1 && !r->d.resumed_before_source_retired);
	if (r->source_error == 0) {				/* O1 */
		PCHECK(r->s.retired && r->s.defunct && !r->source.source_runnable);
		PCHECK(r->source.phase == MIGRATION_PHASE_COMPLETED);
		/* Protocol 2: the source completes only on RELEASE_ACK from a
		 * resumed destination, in every mode.  An ordinary loss (source
		 * defunct, destination not running) was possible with protocol 1
		 * and is counted so the summary shows it is now always 0. */
		if (r->d.resumes != 1)
			ordinary_losses++;
		PCHECK(r->d.resumes == 1 && dest_matches_source(r));
	} else {
		PCHECK(!r->s.defunct);
		if (r->source.source_runnable)			/* O3 */
			PCHECK(!r->s.quiesced && !r->s.retired);
		else
			PCHECK(r->s.retired || r->s.quiesced);
	}
	if (r->d.resumes == 1)					/* O2 */
		PCHECK(r->s.retired && dest_matches_source(r));
	if (r->dest_error == 0)
		PCHECK(r->d.resumes == 1 && r->dest.resumed);
	else {
		PCHECK(!r->dest.resumed || r->d.resumes == 1);
		/* Any committed destination may be retained (protocol 2). */
		if (r->dest.retained)
			PCHECK(r->d.retained && r->d.committed);
	}
	if (integrity_mutation && r->mutated)			/* O5 */
		PCHECK(r->source_error != 0 || r->dest_error != 0);
}

/* ------------------------------------------------------------- tests */
static void
test_codecs(void)
{
	struct migration_hello h, h2;
	struct migration_caps_accept c;
	struct migration_reason_msg rm;
	struct migration_memgen g;
	struct migration_chunk ch;
	struct migration_frame_header fh;
	uint8_t wire[512], frame[64];
	size_t written;
	uint16_t negotiated;
	uint32_t reason;
	int checks = 0;

#define EXPECT(expr, value) do { int _v = (expr); if (_v != (value)) { \
	fprintf(stderr, "%s:%d: %s = %d, expected %d\n", __FILE__, __LINE__, #expr, _v, \
	    (int)(value)); abort(); } checks++; } while (0)
	strlcpy(current_label, "codecs", sizeof(current_label));
	/* Frames. */
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0, NULL, 0, NULL, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0, NULL, 0, frame, 64, NULL), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0, NULL, 4, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, 0, 1, 0, NULL, 0, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, 99, 1, 0, NULL, 0, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0x80, NULL, 0, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0, wire, 41, frame, 64, &written), EMSGSIZE);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0, wire,
	    (size_t)MIGRATION_MAX_PAYLOAD + 1, frame, 64, &written), EMSGSIZE);
	EXPECT(migration_frame_encode(0, MIGRATION_MSG_HELLO, 1, 0, NULL, 0, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(1, MIGRATION_MSG_CAPS_REJECT, 1, 0, NULL, 0, frame, 64,
	    &written), 0);	/* a reply in a protocol 1 peer's framing */
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION + 1, MIGRATION_MSG_HELLO, 1, 0, NULL,
	    0, frame, 64, &written), EINVAL);
	EXPECT(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_MEM_ACK, 2, 0, NULL, 0, frame, 64, &written), 0);
	EXPECT((int)written, MIGRATION_FRAME_HDR_SIZE);
	EXPECT(migration_frame_decode_header(NULL, 24, &fh), EINVAL);
	EXPECT(migration_frame_decode_header(frame, 24, NULL), EINVAL);
	EXPECT(migration_frame_decode_header(frame, 23, &fh), EINVAL);
	EXPECT(migration_frame_decode_header(frame, 24, &fh), 0);
	{
		/* Frame versions 1..MIGRATION_PROTO_VERSION decode; 0 and
		 * MIGRATION_PROTO_VERSION + 1 do not. */
		uint8_t v0[24];
		memcpy(v0, frame, 24);
		le16enc(v0 + 4, 0);
		EXPECT(migration_frame_decode_header(v0, 24, &fh), EPROTO);
		le16enc(v0 + 4, MIGRATION_PROTO_VERSION + 1);
		EXPECT(migration_frame_decode_header(v0, 24, &fh), EPROTO);
		le16enc(v0 + 4, 1);
		EXPECT(migration_frame_decode_header(v0, 24, &fh), 0);
		EXPECT(fh.version, 1);
		EXPECT(migration_frame_decode_header(frame, 24, &fh), 0);
	}
	EXPECT(migration_frame_verify_payload(NULL, NULL, 0), EINVAL);
	EXPECT(migration_frame_verify_payload(&fh, NULL, 1), EINVAL);
	EXPECT(migration_frame_verify_payload(&fh, wire, 1), EBADMSG);
	EXPECT(migration_frame_verify_payload(&fh, NULL, 0), 0);
	fh.crc32 ^= 1;
	EXPECT(migration_frame_verify_payload(&fh, NULL, 0), EBADMSG);
	for (size_t i = 0; i < 24; i++) {
		uint8_t bad[64];
		memcpy(bad, frame, 24);
		bad[i] ^= 0x80;
		int e = migration_frame_decode_header(bad, 24, &fh);
		/* Magic: EINVAL; version/type/flags: EPROTO; the top length byte
		 * exceeds the payload limit (EMSGSIZE).  Sequence, low length
		 * bytes and CRC are checked by the session, not the decoder. */
		if (i < 4)
			EXPECT(e, EINVAL);
		else if (i < 12)
			EXPECT(e, EPROTO);
		else if (i == 19)
			EXPECT(e, EMSGSIZE);
		else
			EXPECT(e, 0);
	}
	/* HELLO. */
	fill_hello(&h, true);
	EXPECT(migration_hello_encode(NULL, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_hello_encode(&h, NULL, sizeof(wire)), EINVAL);
	EXPECT(migration_hello_encode(&h, wire, MIGRATION_HELLO_SIZE - 1), EINVAL);
	h2 = h;
	memset(h2.machine_abi, 'a', sizeof(h2.machine_abi));
	EXPECT(migration_hello_encode(&h2, wire, sizeof(wire)), EINVAL);
	h2 = h;
	h2.role = 9;
	EXPECT(migration_hello_encode(&h2, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_hello_encode(&h, wire, sizeof(wire)), 0);
	wire[4] = 9;	/* role byte */
	EXPECT(migration_hello_decode(wire, MIGRATION_HELLO_SIZE, &h2), EBADMSG);
	EXPECT(migration_hello_encode(&h, wire, sizeof(wire)), 0);
	EXPECT(migration_hello_decode(NULL, MIGRATION_HELLO_SIZE, &h2), EINVAL);
	EXPECT(migration_hello_decode(wire, MIGRATION_HELLO_SIZE, NULL), EINVAL);
	EXPECT(migration_hello_decode(wire, MIGRATION_HELLO_SIZE - 1, &h2), EINVAL);
	EXPECT(migration_hello_decode(wire, MIGRATION_HELLO_SIZE + 1, &h2), EINVAL);
	EXPECT(migration_hello_decode(wire, MIGRATION_HELLO_SIZE, &h2), 0);
	EXPECT(memcmp(&h, &h2, sizeof(h)), 0);
	/* Every reserved/padding byte of HELLO is validated: flip each byte and
	 * require that a decoded value either changes or the decode fails. */
	for (size_t i = 0; i < MIGRATION_HELLO_SIZE; i++) {
		uint8_t bad[MIGRATION_HELLO_SIZE];
		memcpy(bad, wire, sizeof(bad));
		bad[i] ^= 0x01;
		if (migration_hello_decode(bad, sizeof(bad), &h2) == 0)
			EXPECT(memcmp(&h, &h2, sizeof(h)) != 0, 1);
		else
			checks++;
	}
	/* CAPS_ACCEPT. */
	c.negotiated_version = MIGRATION_PROTO_VERSION;
	c.capability_flags = MIGRATION_CAP_PRECOPY;
	EXPECT(migration_caps_accept_encode(NULL, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_caps_accept_encode(&c, NULL, sizeof(wire)), EINVAL);
	EXPECT(migration_caps_accept_encode(&c, wire, MIGRATION_CAPS_ACCEPT_SIZE - 1), EINVAL);
	EXPECT(migration_caps_accept_encode(&c, wire, sizeof(wire)), 0);
	EXPECT(migration_caps_accept_decode(NULL, MIGRATION_CAPS_ACCEPT_SIZE, &c), EINVAL);
	EXPECT(migration_caps_accept_decode(wire, MIGRATION_CAPS_ACCEPT_SIZE, NULL), EINVAL);
	EXPECT(migration_caps_accept_decode(wire, MIGRATION_CAPS_ACCEPT_SIZE + 1, &c), EINVAL);
	c.capability_flags = 1ULL << 9;
	EXPECT(migration_caps_accept_encode(&c, wire, sizeof(wire)), EINVAL);
	c.capability_flags = MIGRATION_CAP_PRECOPY;
	EXPECT(migration_caps_accept_encode(&c, wire, sizeof(wire)), 0);
	wire[2] = 0xff;		/* reserved */
	EXPECT(migration_caps_accept_decode(wire, MIGRATION_CAPS_ACCEPT_SIZE, &c), EBADMSG);
	wire[2] = 0;
	wire[11] = 0x80;	/* undefined capability */
	EXPECT(migration_caps_accept_decode(wire, MIGRATION_CAPS_ACCEPT_SIZE, &c), EBADMSG);
	wire[11] = 0;
	EXPECT(migration_caps_accept_decode(wire, MIGRATION_CAPS_ACCEPT_SIZE, &c), 0);
	/* Reasons. */
	rm.reason_code = MIGRATION_REASON_DEVICE;
	rm.detail = 9;
	EXPECT(migration_reason_encode(NULL, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_reason_encode(&rm, NULL, sizeof(wire)), EINVAL);
	EXPECT(migration_reason_encode(&rm, wire, MIGRATION_REASON_SIZE - 1), EINVAL);
	EXPECT(migration_reason_encode(&rm, wire, sizeof(wire)), 0);
	EXPECT(migration_reason_decode(NULL, MIGRATION_REASON_SIZE, &rm), EINVAL);
	EXPECT(migration_reason_decode(wire, MIGRATION_REASON_SIZE, NULL), EINVAL);
	EXPECT(migration_reason_decode(wire, MIGRATION_REASON_SIZE - 1, &rm), EINVAL);
	EXPECT(migration_reason_decode(wire, MIGRATION_REASON_SIZE, &rm), 0);
	EXPECT((int)rm.reason_code, MIGRATION_REASON_DEVICE);
	/* Memory generations and chunks. */
	memset(&g, 0, sizeof(g));
	g.mode = 2;
	g.length = PAGE;
	EXPECT(migration_memgen_encode(NULL, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_memgen_encode(&g, NULL, sizeof(wire)), EINVAL);
	EXPECT(migration_memgen_encode(&g, wire, MIGRATION_MEMGEN_HDR_SIZE - 1), EINVAL);
	EXPECT(migration_memgen_encode(&g, wire, sizeof(wire)), 0);
	EXPECT(migration_memgen_decode(NULL, MIGRATION_MEMGEN_HDR_SIZE, &g), EINVAL);
	EXPECT(migration_memgen_decode(wire, MIGRATION_MEMGEN_HDR_SIZE, NULL), EINVAL);
	EXPECT(migration_memgen_decode(wire, MIGRATION_MEMGEN_HDR_SIZE - 1, &g), EINVAL);
	memset(&ch, 0, sizeof(ch));
	ch.chunk_length = 4;
	EXPECT(migration_chunk_encode(NULL, wire, sizeof(wire)), EINVAL);
	EXPECT(migration_chunk_encode(&ch, NULL, sizeof(wire)), EINVAL);
	EXPECT(migration_chunk_encode(&ch, wire, MIGRATION_CHUNK_HDR_SIZE - 1), EINVAL);
	EXPECT(migration_chunk_encode(&ch, wire, sizeof(wire)), 0);
	EXPECT(migration_chunk_decode(NULL, MIGRATION_CHUNK_HDR_SIZE, &ch), EINVAL);
	EXPECT(migration_chunk_decode(wire, MIGRATION_CHUNK_HDR_SIZE, NULL), EINVAL);
	EXPECT(migration_chunk_decode(wire, MIGRATION_CHUNK_HDR_SIZE - 1, &ch), EINVAL);
	/* chunk_validate(expect_offset, total_or_zero, chunk, chunkmax, totalmax) */
	EXPECT(migration_chunk_validate(0, 0, NULL, 16, 64), EINVAL);
	ch = (struct migration_chunk){ .total_length = 8, .offset = 0, .chunk_length = 8, .final = 1 };
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), 0);
	ch.chunk_length = 17;
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), EMSGSIZE);
	ch = (struct migration_chunk){ .total_length = 65, .offset = 0, .chunk_length = 8, .final = 0 };
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), EMSGSIZE);
	ch = (struct migration_chunk){ .total_length = 16, .offset = 8, .chunk_length = 8, .final = 1 };
	EXPECT(migration_chunk_validate(8, 16, &ch, 16, 64), 0);
	EXPECT(migration_chunk_validate(0, 16, &ch, 16, 64), EBADMSG);	/* gap/reorder */
	EXPECT(migration_chunk_validate(8, 24, &ch, 16, 64), EBADMSG);	/* total changed */
	ch.final = 0;
	EXPECT(migration_chunk_validate(8, 16, &ch, 16, 64), EBADMSG);	/* final missing */
	ch = (struct migration_chunk){ .total_length = 16, .offset = 0, .chunk_length = 8, .final = 1 };
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), EBADMSG);	/* final too early */
	{
		/* Streaming: an empty final chunk terminates at any offset. */
		struct migration_chunk end = { .offset = 8, .chunk_length = 0,
		    .total_length = 0, .final = 1 };
		EXPECT(migration_chunk_validate(8, 0, &end, 16, 64), 0);
		end.offset = 0;
		EXPECT(migration_chunk_validate(0, 0, &end, 16, 64), 0);
	}
	ch = (struct migration_chunk){ .total_length = 16, .offset = 12, .chunk_length = 8, .final = 1 };
	EXPECT(migration_chunk_validate(12, 16, &ch, 16, 64), EBADMSG);	/* past total */
	ch = (struct migration_chunk){ .total_length = 16, .offset = 20, .chunk_length = 0, .final = 1 };
	EXPECT(migration_chunk_validate(20, 16, &ch, 16, 64), EBADMSG);	/* offset past total */
	ch = (struct migration_chunk){ .total_length = 0, .offset = 0, .chunk_length = 8, .final = 0 };
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), 0);
	ch = (struct migration_chunk){ .total_length = 0, .offset = 0, .chunk_length = 0, .final = 1 };
	EXPECT(migration_chunk_validate(0, 0, &ch, 16, 64), 0);		/* empty stream end */
	/* Version negotiation. */
	EXPECT(migration_negotiate_version(1, 2, 1, 1, &negotiated), EINVAL);
	EXPECT(migration_negotiate_version(1, 1, 1, 2, &negotiated), EINVAL);
	EXPECT(migration_negotiate_version(1, 1, 1, 1, NULL), EINVAL);
	EXPECT(migration_negotiate_version(3, 2, 1, 1, &negotiated), EPROTONOSUPPORT);
	EXPECT(migration_negotiate_version(3, 1, 5, 2, &negotiated), 0);
	EXPECT(negotiated, 3);
	/* Device flags. */
	EXPECT(migration_device_flags_eligible(0), false);
	EXPECT(migration_device_flags_eligible(1U << 20), false);
	EXPECT(migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_COMPAT_CALLBACK |
	    MIGRATION_DEVF_DMA_NONE | MIGRATION_DEVF_QUIESCE_NONE), false);
	EXPECT(migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_DMA_NONE | MIGRATION_DEVF_QUIESCE_NONE), false);
	EXPECT(migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_NONE), false);
	EXPECT(migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_NONE |
	    MIGRATION_DEVF_QUIESCE_NONE), true);
	/* HELLO validation reasons. */
	{
		struct migration_hello local, remote;
		struct { void (*mutate)(struct migration_hello *); uint32_t reason; } cases[] = {
			{ NULL, MIGRATION_REASON_NONE },
		};
		(void)cases;
		fill_hello(&local, false);
		local.role = MIGRATION_ROLE_DEST;
		fill_hello(&remote, false);
		EXPECT(migration_hello_validate(NULL, &remote, &negotiated, &reason), EINVAL);
		EXPECT(migration_hello_validate(&local, NULL, &negotiated, &reason), EINVAL);
		EXPECT(migration_hello_validate(&local, &remote, NULL, &reason), EINVAL);
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), 0);
		remote.arch_id ^= 1;
		reason = 0;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_ARCH);
		fill_hello(&remote, false);
		remote.page_size = 2 * PAGE;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_PAGESIZE);
		fill_hello(&remote, false);
		remote.intr_controller = 2;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_INTR);
		fill_hello(&remote, false);
		strlcpy(remote.machine_abi, "other", sizeof(remote.machine_abi));
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_MACHINE_ABI);
		fill_hello(&remote, false);
		remote.cpu_feature_hash ^= 1;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_CPU);
		fill_hello(&remote, false);
		remote.version_min = remote.version_max = 4;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), EPROTONOSUPPORT);
		EXPECT((int)reason, MIGRATION_REASON_VERSION);
		fill_hello(&remote, false);
		remote.capability_flags = MIGRATION_CAP_DEVICE_DIRTY;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_CAPS);
		fill_hello(&remote, false);
		remote.capability_flags |= 1ULL << 50;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_CAPS);
		fill_hello(&remote, true);
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), EPROTONOSUPPORT);
		EXPECT((int)reason, MIGRATION_REASON_CAPS);
		fill_hello(&remote, false);
		remote.cpu_model ^= 1;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_CPU);
		fill_hello(&remote, false);
		remote.cpu_family ^= 1;
		EXPECT(migration_hello_validate(&local, &remote, &negotiated, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_CPU);
	}
	/* Topology encode/decode/validate. */
	{
		struct migration_topology *a = hcalloc(1, sizeof(*a)), *b = hcalloc(1, sizeof(*b));
		uint8_t *tw;
		size_t size, wrote;

		fill_topology(a, 16, 2);
		size = migration_topology_wire_size(a);
		EXPECT(size == MIGRATION_TOPOLOGY_HDR_SIZE + 2 * MIGRATION_DEVREC_SIZE, 1);
		EXPECT((int)migration_topology_wire_size(NULL), 0);
		a->device_count = MIGRATION_MAX_DEVICES + 1;
		EXPECT((int)migration_topology_wire_size(a), 0);
		a->device_count = 2;
		tw = hmalloc(size + 8);
		EXPECT(migration_topology_encode(NULL, tw, size, &wrote), EINVAL);
		EXPECT(migration_topology_encode(a, NULL, size, &wrote), EINVAL);
		EXPECT(migration_topology_encode(a, tw, size, NULL), EINVAL);
		EXPECT(migration_topology_encode(a, tw, size - 1, &wrote), EMSGSIZE);
		a->device_count = MIGRATION_MAX_DEVICES + 1;
		EXPECT(migration_topology_encode(a, tw, size, &wrote), EINVAL);
		a->device_count = 2;
		a->mem_size += 1;	/* geometry must sum */
		EXPECT(migration_topology_encode(a, tw, size, &wrote), EINVAL);
		a->mem_size -= 1;
		memset(a->devices[0].name, 'n', sizeof(a->devices[0].name));
		EXPECT(migration_topology_encode(a, tw, size, &wrote), EINVAL);
		fill_topology(a, 16, 2);
		EXPECT(migration_topology_encode(a, tw, size, &wrote), 0);
		EXPECT(migration_topology_decode(NULL, size, b), EINVAL);
		EXPECT(migration_topology_decode(tw, size, NULL), EINVAL);
		EXPECT(migration_topology_decode(tw, MIGRATION_TOPOLOGY_HDR_SIZE - 1, b), EINVAL);
		EXPECT(migration_topology_decode(tw, size - 1, b), EBADMSG);
		EXPECT(migration_topology_decode(tw, size, b), 0);
		tw[MIGRATION_TOPOLOGY_HDR_SIZE + 39] = 'z';	/* name not terminated */
		EXPECT(migration_topology_decode(tw, size, b), EBADMSG);
		tw[MIGRATION_TOPOLOGY_HDR_SIZE + 39] = 0;
		le64enc(tw, 1);		/* mem_size != lowmem + highmem */
		EXPECT(migration_topology_decode(tw, size, b), EBADMSG);
		le32enc(tw + 36, MIGRATION_MAX_DEVICES + 1);
		EXPECT(migration_topology_decode(tw, size, b), EBADMSG);
		/* validate: every mismatch class reports its reason */
		fill_topology(a, 16, 2);
		fill_topology(b, 16, 2);
		EXPECT(migration_topology_validate(NULL, b, &reason), EINVAL);
		EXPECT(migration_topology_validate(a, NULL, &reason), EINVAL);
		EXPECT(migration_topology_validate(a, b, &reason), 0);
		b->mem_size += PAGE;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_MEMSIZE);
		fill_topology(b, 16, 3);
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_CPUCOUNT);
		fill_topology(b, 16, 2);
		b->sockets = 2;	/* same vCPU count, different shape */
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_TOPOLOGY);
		/* Each CPU-shape and memory-geometry field is compared on its own. */
		fill_topology(b, 16, 2);
		b->cores = 1;
		b->threads = 2;
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_TOPOLOGY);
		fill_topology(b, 16, 2);
		b->threads = 2;
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_TOPOLOGY);
		fill_topology(b, 16, 2);
		b->lowmem -= PAGE;
		b->highmem += PAGE;	/* same total, different split */
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_MEMSIZE);
		fill_topology(a, 16, 2);
		fill_topology(b, 16, 2);
		memcpy(b->devices[1].name, "devX", 5);
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_DEVICE);
		fill_topology(b, 16, 2);
		b->devices[0].migration_flags = MIGRATION_DEVF_STATE_CODEC |
		    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_TRACKED |
		    MIGRATION_DEVF_QUIESCE_NONE;	/* eligible, but not the local contract */
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_DEVICE);
		fill_topology(b, 16, 2);
		b->device_count = MIGRATION_MAX_DEVICES + 1;
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_TOPOLOGY);
		/* The reason output is optional. */
		EXPECT(migration_topology_validate(a, b, NULL), EINVAL);
		fill_topology(b, 16, 2);
		b->device_count = 1;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		EXPECT((int)reason, MIGRATION_REASON_DEVICE);
		fill_topology(b, 16, 2);
		b->devices[1].migration_flags = MIGRATION_DEVF_STATE_CODEC;
		EXPECT(migration_topology_validate(a, b, &reason), EOPNOTSUPP);
		EXPECT((int)reason, MIGRATION_REASON_DEVICE);
		fill_topology(b, 16, 2);
		b->devices[0].compat_crc32 ^= 1;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		fill_topology(b, 16, 2);
		b->devices[1].bar_hash ^= 1;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		fill_topology(b, 16, 2);
		b->devices[0].compat_schema ^= 1;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		fill_topology(b, 16, 2);
		b->devices[0].name[0] = 'Y';
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		fill_topology(b, 16, 2);
		b->highmem = PAGE;
		b->mem_size += PAGE;
		EXPECT(migration_topology_validate(a, b, &reason) != 0, 1);
		fill_topology(b, 16, 2);
		b->lowmem = 0;
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		EXPECT((int)reason, MIGRATION_REASON_MEMSIZE);
		fill_topology(b, 16, 2);
		a->mem_size += PAGE;	/* the local geometry must be valid too */
		EXPECT(migration_topology_validate(a, b, &reason), EINVAL);
		a->mem_size -= PAGE;
		free(a);
		free(b);
		free(tw);
	}
	/* Memory record validation: (gpa, length, lowmem, highbase, highmem, prev_end). */
	EXPECT(migration_memory_record_validate(0, PAGE, 16 * PAGE, 0, 0, 0), 0);
	EXPECT(migration_memory_record_validate(1, PAGE, 16 * PAGE, 0, 0, 0) != 0, 1);
	EXPECT(migration_memory_record_validate(0, 2 * PAGE, 16 * PAGE, 0, 0, 0) != 0, 1);
	EXPECT(migration_memory_record_validate(16 * PAGE, PAGE, 16 * PAGE, 0, 0, 0) != 0, 1);
	EXPECT(migration_memory_record_validate(0, PAGE, 16 * PAGE, 0, 0, PAGE) != 0, 1);
	EXPECT(migration_memory_record_validate(1ULL << 32, PAGE, 16 * PAGE, 1ULL << 32, PAGE, 0), 0);
	EXPECT(migration_memory_record_validate((1ULL << 32) + PAGE, PAGE, 16 * PAGE,
	    1ULL << 32, PAGE, 0) != 0, 1);
	EXPECT(migration_memory_record_validate(UINT64_MAX - PAGE + 1, PAGE, 16 * PAGE,
	    1ULL << 32, PAGE, 0) != 0, 1);
	printf("protocol codecs: %d checks\n", checks);
#undef EXPECT
}

static struct config_model
base_config(bool fresh)
{
	return ((struct config_model){ .pages = 48, .dev_len = 3000, .fresh = fresh });
}

static void
test_baseline(bool fresh, struct run_result *baseline)
{
	struct config_model cfg = base_config(fresh);

	snprintf(current_label, sizeof(current_label), "baseline fresh=%d", fresh);
	run_once(&cfg, -1, -1, MUT_NONE, 0, baseline);
	check_run(baseline, false);
	PCHECK(baseline->source_error == 0 && baseline->dest_error == 0);
	if (fresh) {
		PCHECK(baseline->s.nrecords == 4 && baseline->s.records[0] == MIGRATION_REC_SOURCE_INTENT &&
		    baseline->s.records[3] == MIGRATION_REC_SOURCE_CONFIRMED);
		PCHECK(baseline->d.nrecords == 3 && baseline->d.records[2] == MIGRATION_REC_DEST_RUNNING);
		PCHECK(baseline->dest.release_ack_sent);
	}
	printf("protocol baseline fresh=%d: %d+%d frames, %u rounds\n", fresh,
	    baseline->frames[0], baseline->frames[1], baseline->source.rounds);
}

static void
test_mutations(bool fresh, const struct run_result *baseline)
{
	int runs = 0, rejected = 0, accepted = 0, final_index = 0;
	struct config_model cfg = base_config(fresh);

	for (int i = 0; i < baseline->frames[0]; i++)
		if (baseline->types[0][i] == MIGRATION_MSG_FINAL)
			final_index = i;

	for (int direction = 0; direction < 2; direction++)
	for (int index = 0; index < baseline->frames[direction]; index++)
	for (int mutation = MUT_FLIP_PAYLOAD; mutation < MUT_LAST; mutation++) {
		int variants = mutation == MUT_FIELD ? 11 : mutation == MUT_TYPE ? 13 :
		    mutation == MUT_FLIP_PAYLOAD || mutation == MUT_FLIP_HEADER_MAGIC ? 3 :
		    mutation == MUT_TRUNCATE || mutation == MUT_SEQ || mutation == MUT_ABORT ? 2 : 1;
		for (int variant = 0; variant < variants; variant++) {
			struct run_result r;
			bool integrity = mutation == MUT_FLIP_PAYLOAD ||
			    mutation == MUT_FLIP_HEADER_CRC;

			snprintf(current_label, sizeof(current_label),
			    "fresh=%d dir=%d frame=%d(type %u) %s/%d", fresh, direction,
			    index, baseline->types[direction][index], mutation_names[mutation],
			    variant);
			/* Ordinary mode: anything injected at or after FINAL can hit
			 * the destination after it sent COMMIT. */
			loss_allowed = direction == 0 && index >= final_index;
			active_alteration = mutation >= MUT_SEQ && mutation != MUT_ABORT;
			run_once(&cfg, direction, index, mutation, variant, &r);
			check_run(&r, integrity);
			runs++;
			if (r.mutated && (r.source_error != 0 || r.dest_error != 0))
				rejected++;
			else if (r.mutated)
				accepted++;
			free_run(&r);
		}
	}
	loss_allowed = false;
	active_alteration = false;
	printf("protocol mutations fresh=%d: %d runs, %d rejected, %d accepted; all oracles "
	    "held; ordinary losses after RELEASE so far %d; undetected active alterations "
	    "without TLS so far %d\n", fresh, runs, rejected, accepted, ordinary_losses,
	    undetected_alterations);
}

static void
test_operation_failures(bool fresh)
{
	int runs = 0;

	for (int op = S_HELLO; op < OP_LAST; op++) {
		struct config_model cfg = base_config(fresh);
		struct run_result r;

		cfg.fail = op;
		cfg.preserve = op == D_PRESERVE;
		snprintf(current_label, sizeof(current_label), "fresh=%d fail %s", fresh,
		    op_names[op]);
		loss_allowed = op == D_RESUME;
		run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
		check_run(&r, false);
		if (fresh && op == D_RESUME)
			PCHECK(r.dest.retained && r.source_error != 0 && !r.source.source_runnable);
		runs++;
		free_run(&r);
	}
	loss_allowed = false;
	printf("protocol operation failures fresh=%d: %d injected, all oracles held "
	    "(ordinary-mode losses after RELEASE so far: %d)\n", fresh, runs, ordinary_losses);
}

/*
 * Every transport send and receive of a successful run fails in turn, on
 * each side.  Oracles O1-O4 hold in every run; a source that sent RELEASE
 * may lose its copy only in ordinary mode (no acknowledgment, counted).
 */
static void
test_transport_faults(bool fresh)
{
	struct config_model cfg = base_config(fresh);
	struct run_result r;
	int totals[2][2], runs = 0;

	strlcpy(current_label, "transport baseline", sizeof(current_label));
	xp_fault_side = 0;
	run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
	check_run(&r, false);
	PCHECK(r.source_error == 0 && r.dest_error == 0);
	memcpy(totals, xp_counts, sizeof(totals));
	free_run(&r);
	for (int side = 0; side < 2; side++)
	for (int recv = 0; recv < 2; recv++)
	for (int at = 1; at <= totals[side][recv]; at++) {
		snprintf(current_label, sizeof(current_label),
		    "fresh=%d %s %s #%d", fresh, side ? "dest" : "source",
		    recv ? "recv" : "send", at);
		xp_fault_side = side ? 'D' : 'S';
		xp_fault_recv = recv;
		xp_fault_at = at;
		loss_allowed = !fresh;
		run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
		xp_fault_side = 0;
		check_run(&r, false);
		PCHECK(r.source_error != 0 || r.dest_error != 0);
		runs++;
		free_run(&r);
	}
	loss_allowed = false;
	printf("protocol transport faults fresh=%d: %d runs over %d+%d source and %d+%d "
	    "destination calls, all oracles held\n", fresh, runs, totals[0][0], totals[0][1],
	    totals[1][0], totals[1][1]);
}

static void
test_shapes(void)
{
	struct config_model cfg;
	struct run_result r;

	/* Generations and device state larger than one frame are chunked. */
	cfg = base_config(true);
	cfg.pages = 4200;
	cfg.dev_len = (size_t)MIGRATION_MAX_PAYLOAD + 5000;
	strlcpy(current_label, "chunked", sizeof(current_label));
	run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
	check_run(&r, false);
	PCHECK(r.source_error == 0 && r.dest_error == 0);
	printf("protocol chunked: %d+%d frames for %zu pages and %zu device bytes\n",
	    r.frames[0], r.frames[1], cfg.pages, cfg.dev_len);
	/* Mutate the chunk headers of the chunked streams. */
	{
		struct run_result base = r;
		int runs = 0;
		for (int index = 0; index < base.frames[0]; index++) {
			for (int variant = 0; variant < 15; variant++) {
				struct run_result m;
				snprintf(current_label, sizeof(current_label),
				    "chunked frame %d field %d", index, variant);
				active_alteration = true;
				run_once(&cfg, 0, index, MUT_FIELD, variant, &m);
				check_run(&m, false);
				runs++;
				free_run(&m);
			}
			struct run_result m;
			active_alteration = true;
			run_once(&cfg, 0, index, MUT_FLAGS, 0, &m);
			check_run(&m, false);
			free_run(&m);
			runs++;
		}
		active_alteration = false;
		printf("protocol chunk mutations: %d runs\n", runs);
	}
	free_run(&r);
	/* A reassembled (chunked) device state that the destination refuses. */
	cfg.fail = D_STAGE_DEV;
	strlcpy(current_label, "chunked stage_dev failure", sizeof(current_label));
	run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
	check_run(&r, false);
	PCHECK(r.dest_error != 0 && !r.d.committed && r.dest.reason == MIGRATION_REASON_STATE);
	free_run(&r);
	cfg.fail = OP_NONE;
	/*
	 * Convergence policy.  A ceiling above the per-round dirty count cuts
	 * over after the first round; the migration completes with one
	 * pre-copy round.  An operator cancellation that arrives as pre-copy
	 * converges is honoured at the stop-and-copy fence: the source stays
	 * runnable with reason CANCELLED and nothing was quiesced.
	 */
	for (int fresh = 0; fresh < 2; fresh++) {
		cfg = base_config(fresh);
		cfg.converge_pages = 1000;
		snprintf(current_label, sizeof(current_label), "converge ceiling fresh=%d", fresh);
		run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
		check_run(&r, false);
		PCHECK(r.source_error == 0 && r.dest_error == 0 && r.source.rounds == 1);
		free_run(&r);
		cfg.cancel_on_converge = true;
		snprintf(current_label, sizeof(current_label), "cancel at stop-copy fresh=%d", fresh);
		run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
		check_run(&r, false);
		PCHECK(r.source_error == ECANCELED && r.source.source_runnable &&
		    r.source.reason == MIGRATION_REASON_CANCELLED && !r.s.quiesced &&
		    r.dest_error != 0 && !r.dest.resumed && !r.d.committed);
		free_run(&r);
	}
	printf("protocol convergence ceiling and stop-copy cancellation: 4 runs\n");
	/* Destination with a different topology rejects before quiesce. */
	cfg = base_config(false);
	cfg.ncpus_dest = 4;
	strlcpy(current_label, "topology mismatch", sizeof(current_label));
	run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
	check_run(&r, false);
	PCHECK(r.source_error == ECONNREFUSED && r.source.reason == MIGRATION_REASON_CPUCOUNT &&
	    r.source.source_runnable && r.s.resumes == 0 && !r.s.quiesced);
	free_run(&r);
	/* A fresh source cannot pair with a destination that does not trace. */
	cfg = base_config(true);
	cfg.hello_caps_dest = MIGRATION_CAP_PRECOPY | MIGRATION_CAP_DEVICE_DIRTY;
	strlcpy(current_label, "fresh mismatch", sizeof(current_label));
	run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
	check_run(&r, false);
	PCHECK(r.source_error != 0 && r.source.source_runnable);
	free_run(&r);
	printf("protocol shapes: topology and capability rejections before quiesce\n");
}

/*
 * Protocol 1 peers (item 2).  A destination is offered a HELLO whose
 * window is 1..1, either inside protocol 2 framing (a peer that can frame
 * protocol 2 but not speak it) or with protocol 1 framing (an unmodified
 * protocol 1 peer).  Oracle: the destination never stages or commits, reports
 * REASON_VERSION and answers one CAPS_REJECT(REASON_VERSION) in the peer's
 * frame version (regression: a protocol 1 framed HELLO used to be refused by
 * the frame decoder as a transport failure with no reply).  A source that receives CAPS_ACCEPT naming version 1
 * refuses with REASON_VERSION and stays runnable.
 */
static void
test_protocol1_peers(void)
{
	struct migration_session_config config = {0};
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_dest_result dr;
	int checks = 0;

	strlcpy(current_label, "protocol 1 peers", sizeof(current_label));
	for (int framing = 2; framing >= 1; framing--) {
		struct config_model cfg = base_config(false);
		struct dest_model d = { .cfg = &cfg };
		struct migration_dest_ops ops = {
			.do_local_hello = d_hello, .do_local_topology = d_topology,
			.do_stage_mem = d_stage_mem, .do_stage_dev = d_stage_dev,
			.do_commit = d_commit, .do_resume = d_resume, .do_discard = d_discard,
			.do_record = d_record, .do_prepare_commit = d_prepare,
			.do_retain = d_retain,
		};
		struct migration_hello h;
		uint8_t hw[MIGRATION_HELLO_SIZE];
		int pair[2], pending = -1;

		fill_hello(&h, false);
		h.role = MIGRATION_ROLE_SOURCE;
		h.version_min = h.version_max = 1;
		PCHECK(migration_hello_encode(&h, hw, sizeof(hw)) == 0);
		PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
		PCHECK(send_frame(pair[1], (uint16_t)framing, MIGRATION_MSG_HELLO, 1, 0,
		    hw, sizeof(hw)));
		migration_transport_fd_init(&xp, &fdx, pair[0], 1000);
		PCHECK(migration_dest_run(&xp, &ops, &d, &config, &dr) != 0);
		PCHECK(!d.committed && d.resumes == 0 && dr.phase == MIGRATION_PHASE_FAILED);
		/* Either framing: CAPS_REJECT(REASON_VERSION), in the peer's own
		 * frame version (the frame layout is unchanged since protocol 1;
		 * negotiation, not framing, refuses protocol 1). */
		{
			struct migration_frame_header fh;
			struct migration_reason_msg rm;
			uint8_t hdr[MIGRATION_FRAME_HDR_SIZE], body[MIGRATION_REASON_SIZE];
			PCHECK(dr.reason == MIGRATION_REASON_VERSION);
			PCHECK(read_full(pair[1], hdr, sizeof(hdr)) &&
			    migration_frame_decode_header(hdr, sizeof(hdr), &fh) == 0 &&
			    fh.type == MIGRATION_MSG_CAPS_REJECT && fh.version == framing);
			PCHECK(read_full(pair[1], body, sizeof(body)) &&
			    migration_reason_decode(body, sizeof(body), &rm) == 0 &&
			    rm.reason_code == MIGRATION_REASON_VERSION);
			PCHECK(ioctl(pair[1], FIONREAD, &pending) == 0 && pending == 0);
		}
		close(pair[0]);
		close(pair[1]);
		checks += 4;
	}
	/* A destination answering with version 1. */
	{
		struct config_model cfg = base_config(false);
		struct source_model s = { .cfg = &cfg };
		struct migration_source_result sr;
		struct migration_caps_accept c = { .negotiated_version = 1,
		    .capability_flags = MIGRATION_CAP_PRECOPY | MIGRATION_CAP_DEVICE_DIRTY };
		uint8_t cw[MIGRATION_CAPS_ACCEPT_SIZE], hdr[MIGRATION_FRAME_HDR_SIZE];
		struct migration_frame_header fh;
		int pair[2];

		PCHECK(migration_caps_accept_encode(&c, cw, sizeof(cw)) == 0);
		PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
		/* Queue the reply; the source reads it after sending HELLO. */
		PCHECK(send_frame(pair[1], MIGRATION_PROTO_VERSION, MIGRATION_MSG_CAPS_ACCEPT,
		    1, 0, cw, sizeof(cw)));
		migration_transport_fd_init(&xp, &fdx, pair[0], 1000);
		PCHECK(migration_source_run(&xp, &source_ops, &s, &config, &sr) ==
		    EPROTONOSUPPORT);
		PCHECK(sr.reason == MIGRATION_REASON_VERSION && sr.source_runnable &&
		    !s.quiesced && !s.retired);
		PCHECK(read_full(pair[1], hdr, sizeof(hdr)) &&
		    migration_frame_decode_header(hdr, sizeof(hdr), &fh) == 0 &&
		    fh.type == MIGRATION_MSG_HELLO);
		close(pair[0]);
		close(pair[1]);
		checks += 3;
	}
	printf("protocol 1 peers: %d checks\n", checks);
}

static int
xp_send_dummy(void *cookie __unused, const void *buf __unused, size_t len __unused)
{
	abort();
}

static int
xp_recv_dummy(void *cookie __unused, void *buf __unused, size_t len __unused)
{
	abort();
}

static void
test_arguments(void)
{
	struct migration_source_result sr;
	struct migration_dest_result dr;
	struct migration_session_config config = {0};
	struct migration_transport xp = {0};
	struct migration_transport_fd fdx;
	struct migration_dest_ops dops = {0};
	struct source_model s = {0};

	strlcpy(current_label, "arguments", sizeof(current_label));
	PCHECK(migration_source_run(NULL, &source_ops, &s, &config, &sr) == EINVAL);
	PCHECK(migration_source_run(&xp, &source_ops, &s, &config, &sr) == EINVAL);
	{
		/* A transport with a send but no receive operation. */
		struct migration_transport half = { .xp_send = xp_send_dummy };
		PCHECK(migration_source_run(&half, &source_ops, &s, &config, &sr) == EINVAL);
		PCHECK(migration_dest_run(&half, &dops, NULL, &config, &dr) == EINVAL);
		half = (struct migration_transport){ .xp_recv = xp_recv_dummy };
		PCHECK(migration_dest_run(&half, &dops, NULL, &config, &dr) == EINVAL);
	}
	migration_transport_fd_init(&xp, &fdx, -1, 10);
	PCHECK(migration_source_run(&xp, NULL, &s, &config, &sr) == EINVAL);
	PCHECK(migration_source_run(&xp, &source_ops, &s, NULL, &sr) == EINVAL);
	PCHECK(migration_source_run(&xp, &source_ops, &s, &config, NULL) == EINVAL);
	config.max_rounds = UINT32_MAX;
	PCHECK(migration_source_run(&xp, &source_ops, &s, &config, &sr) == EINVAL);
	PCHECK(sr.phase == MIGRATION_PHASE_FAILED && sr.reason == MIGRATION_REASON_STATE &&
	    sr.source_runnable);
	config.max_rounds = 0;
	PCHECK(migration_dest_run(NULL, &dops, NULL, &config, &dr) == EINVAL);
	PCHECK(migration_dest_run(&xp, NULL, NULL, &config, &dr) == EINVAL);
	PCHECK(migration_dest_run(&xp, &dops, NULL, NULL, &dr) == EINVAL);
	PCHECK(migration_dest_run(&xp, &dops, NULL, &config, NULL) == EINVAL);
	/* A fresh source without retirement hooks refuses before sending. */
	{
		struct migration_source_ops partial = source_ops;
		struct config_model cfg = base_config(true);
		int pair[2];
		s.cfg = &cfg;
		partial.so_retire = NULL;
		PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
		migration_transport_fd_init(&xp, &fdx, pair[0], 100);
		PCHECK(migration_source_run(&xp, &partial, &s, &config, &sr) == EOPNOTSUPP);
		PCHECK(sr.reason == MIGRATION_REASON_CAPS && sr.source_runnable);
		/* Each missing fresh hook alone is refused; the peer sees only
		 * ABORT(CAPS) frames, never a HELLO. */
		partial = source_ops;
		partial.so_record = NULL;
		PCHECK(migration_source_run(&xp, &partial, &s, &config, &sr) == EOPNOTSUPP);
		partial = source_ops;
		partial.so_accept_commit = NULL;
		PCHECK(migration_source_run(&xp, &partial, &s, &config, &sr) == EOPNOTSUPP);
		for (int i = 0; i < 3; i++) {
			struct migration_frame_header fh;
			struct migration_reason_msg rm;
			uint8_t hdr[MIGRATION_FRAME_HDR_SIZE], body[MIGRATION_REASON_SIZE];
			PCHECK(read_full(pair[1], hdr, sizeof(hdr)) &&
			    migration_frame_decode_header(hdr, sizeof(hdr), &fh) == 0 &&
			    fh.type == MIGRATION_MSG_ABORT && fh.length == sizeof(body));
			PCHECK(read_full(pair[1], body, sizeof(body)) &&
			    migration_reason_decode(body, sizeof(body), &rm) == 0 &&
			    rm.reason_code == MIGRATION_REASON_CAPS);
		}
		{
			int pending = -1;
			PCHECK(ioctl(pair[1], FIONREAD, &pending) == 0 && pending == 0);
		}
		close(pair[0]);
		close(pair[1]);
	}
	/* A fresh destination missing one fresh hook refuses with CAPS_REJECT. */
	for (int missing = 0; missing < 3; missing++) {
		struct config_model cfg = base_config(true);
		struct dest_model d = { .cfg = &cfg };
		struct migration_dest_ops partial = {
			.do_local_hello = d_hello, .do_local_topology = d_topology,
			.do_stage_mem = d_stage_mem, .do_stage_dev = d_stage_dev,
			.do_commit = d_commit, .do_resume = d_resume, .do_discard = d_discard,
			.do_record = d_record, .do_prepare_commit = d_prepare,
			.do_retain = d_retain,
		};
		struct migration_hello h;
		struct migration_frame_header fh;
		uint8_t hw[MIGRATION_HELLO_SIZE], hdr[MIGRATION_FRAME_HDR_SIZE];
		int pair[2];

		if (missing == 0)
			partial.do_record = NULL;
		else if (missing == 1)
			partial.do_prepare_commit = NULL;
		else
			partial.do_retain = NULL;
		fill_hello(&h, true);
		h.role = MIGRATION_ROLE_SOURCE;
		PCHECK(migration_hello_encode(&h, hw, sizeof(hw)) == 0);
		PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
		PCHECK(send_frame(pair[1], MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0,
		    hw, sizeof(hw)));
		migration_transport_fd_init(&xp, &fdx, pair[0], 1000);
		PCHECK(migration_dest_run(&xp, &partial, &d, &config, &dr) == EOPNOTSUPP);
		PCHECK(dr.reason == MIGRATION_REASON_CAPS);
		PCHECK(read_full(pair[1], hdr, sizeof(hdr)) &&
		    migration_frame_decode_header(hdr, sizeof(hdr), &fh) == 0 &&
		    fh.type == MIGRATION_MSG_CAPS_REJECT);
		close(pair[0]);
		close(pair[1]);
	}
	printf("protocol arguments: 24 checks\n");
}

/*
 * Allocation faults (driven by a harness whose malloc/calloc fail the n-th
 * large allocation): every large allocation of a successful run fails in
 * turn.  Oracles O1-O4 hold in every run, and the run fails.
 */
void protocol_allocation_faults(void (*arm)(int), int (*count)(void));
void
protocol_allocation_faults(void (*arm)(int), int (*count)(void))
{
	for (int fresh = 0; fresh < 2; fresh++) {
		struct config_model cfg = base_config(fresh);
		struct run_result r;
		int total, runs = 0;

		cfg.pages = 4200;
		cfg.dev_len = (size_t)MIGRATION_MAX_PAYLOAD + 5000;
		snprintf(current_label, sizeof(current_label), "allocation baseline fresh=%d", fresh);
		arm(INT_MAX);
		run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
		total = count();
		arm(0);
		check_run(&r, false);
		PCHECK(r.source_error == 0 && r.dest_error == 0);
		free_run(&r);
		for (int k = 1; k <= total; k++) {
			snprintf(current_label, sizeof(current_label),
			    "fresh=%d large allocation #%d", fresh, k);
			loss_allowed = !fresh;
			arm(k);
			run_once(&cfg, -1, -1, MUT_NONE, 0, &r);
			arm(0);
			check_run(&r, false);
			runs++;
			free_run(&r);
		}
		loss_allowed = false;
		printf("protocol allocation faults fresh=%d: %d runs over %d large allocations, "
		    "all oracles held\n", fresh, runs, total);
	}
}

int protocol_main(void);

int
protocol_main(void)
{
	struct run_result plain, fresh;

	signal(SIGPIPE, SIG_IGN);
	test_codecs();
	test_arguments();
	test_protocol1_peers();
	test_baseline(false, &plain);
	test_baseline(true, &fresh);
	test_operation_failures(false);
	test_operation_failures(true);
	test_transport_faults(false);
	test_transport_faults(true);
	test_mutations(false, &plain);
	test_mutations(true, &fresh);
	test_shapes();
	free_run(&plain);
	free_run(&fresh);
	printf("PASS: migration protocol core\n");
	return (0);
}
