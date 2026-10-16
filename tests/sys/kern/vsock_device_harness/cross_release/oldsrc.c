/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Rootless v0.1.0 migration producer.  The runner compiles this against
 * migration_session.c and headers extracted from that exact release tag.
 */
#include <sys/types.h>
#include <sys/endian.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "migration_session.c"
struct model {
	int rounds;
	bool quiesced;
	bool defunct;
};
static int
hello(void *arg, struct migration_hello *h)
{
	(void)arg;
	memset(h, 0, sizeof(*h));
	h->version_min = h->version_max = 1;
	h->arch_id = 0x8664;
	h->page_size = 4096;
	h->cpu_family = 6;
	h->cpu_model = 0x97;
	h->cpu_stepping = 2;
	h->cpu_feature_hash = 0x123456789abcdef0ULL;
	h->intr_controller = 1;
	h->capability_flags = MIGRATION_CAP_PRECOPY |
	    MIGRATION_CAP_DEVICE_DIRTY;
	strlcpy(h->machine_abi, "bhyve-virtio-v2", sizeof(h->machine_abi));
	return 0;
}
static int
topology(void *arg, struct migration_topology *t)
{
	(void)arg;
	memset(t, 0, sizeof(*t));
	t->mem_size = t->lowmem = 4096;
	t->ncpus = t->sockets = t->cores = t->threads = 1;
	return 0;
}
static int
enable(void *arg)
{
	(void)arg;
	return 0;
}
static int
round_cb(void *arg, bool final, struct migration_memgen *g, uint8_t *buf,
    size_t cap, size_t *written, uint64_t *dirty, bool *converged, bool *more)
{
	struct model *m = arg;
	(void) final;
	memset(g, 0, sizeof(*g));
	g->mode = MIGRATION_DIRTY_CLEAR;
	g->gpa = 0;
	g->length = 4096;
	g->cpu_identity = 1;
	g->cpu_map_generation = 1;
	g->cpu_dirty_generation = 1;
	g->device_identity = 2;
	g->device_dirty_generation = 1;
	*more = false;
	*converged = true;
	if (m->rounds++ == 0) {
		if (cap < 4104)
			return ENOSPC;
		le64enc(buf, 0);
		memset(buf + 8, 0x5a, 4096);
		g->page_count = 1;
		*written = 4104;
		*dirty = 1;
	} else {
		*written = 0;
		*dirty = 0;
	}
	return 0;
}
static int
disable(void *arg)
{
	(void)arg;
	return 0;
}
static int
quiesce(void *arg, bool *runnable)
{
	struct model *m = arg;
	(void)runnable;
	m->quiesced = true;
	return 0;
}
static int
resume(void *arg)
{
	struct model *m = arg;
	m->quiesced = false;
	return 0;
}
static int
dev(void *arg, uint8_t **buf, size_t *len)
{
	(void)arg;
	*buf = malloc(4);
	if (!*buf)
		return ENOMEM;
	memcpy(*buf, "V010", 4);
	*len = 4;
	return 0;
}
static void
defunct(void *arg)
{
	((struct model *)arg)->defunct = true;
}
int
main(int argc, char **argv)
{
	struct model m = { 0 };
	struct migration_source_ops ops = { .so_local_hello = hello,
		.so_local_topology = topology,
		.so_precopy_enable = enable,
		.so_precopy_round = round_cb,
		.so_precopy_disable = disable,
		.so_quiesce = quiesce,
		.so_resume = resume,
		.so_dev_state = dev,
		.so_defunct = defunct };
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_session_config cfg = { .version_min = 1,
		.version_max = 1,
		.max_rounds = 8 };
	struct migration_source_result result;
	int error;
	if (argc != 2)
		return 2;
	migration_transport_fd_init(&xp, &fdx, atoi(argv[1]), 5000);
	error = migration_source_run(&xp, &ops, &m, &cfg, &result);
	printf(
	    "old-source error=%d phase=%u version=%u runnable=%d defunct=%d rounds=%u\n",
	    error, result.phase, result.negotiated_version,
	    result.source_runnable, m.defunct, m.rounds);
	if (getenv("V010_DISABLE_OPTIN") != NULL)
		return error != 0 && result.source_runnable && !m.quiesced &&
		    !m.defunct ? 0 : 1;
	return error == 0 && m.defunct && !result.source_runnable &&
		result.negotiated_version == 1 ?
	    0 :
	    1;
}
