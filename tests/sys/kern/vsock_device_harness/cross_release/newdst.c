/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Rootless current migration destination for the v0.1.0 producer.
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
	bool saw_page;
	bool saw_dev;
	bool committed;
	bool resumed;
	bool discarded;
};
static int
hello(void *arg, struct migration_hello *h)
{
	(void)arg;
	memset(h, 0, sizeof(*h));
	h->version_min = 1;
	h->version_max = MIGRATION_PROTO_VERSION;
	h->arch_id = 0x8664;
	h->page_size = 4096;
	h->cpu_family = 6;
	h->cpu_model = 0x97;
	h->cpu_stepping = 2;
	h->cpu_feature_hash = 0x123456789abcdef0ULL;
	h->intr_controller = 1;
	h->capability_flags = MIGRATION_CAP_PRECOPY |
	    MIGRATION_CAP_DEVICE_DIRTY | MIGRATION_CAP_V2_RESTORE;
	if (getenv("V010_DISABLE_OPTIN") != NULL)
		h->capability_flags &= ~MIGRATION_CAP_V2_RESTORE;
	strlcpy(h->machine_abi, CHECKPOINT_MACHINE_ABI, sizeof(h->machine_abi));
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
stage_mem(void *arg, const struct migration_memgen *g, const uint8_t *buf,
    size_t len)
{
	struct model *m = arg;
	if (len == 0)
		return g->page_count == 0 ? 0 : EBADMSG;
	if (len != 4104 || g->page_count != 1 || le64dec(buf) != 0)
		return EBADMSG;
	for (size_t i = 8; i < len; i++)
		if (buf[i] != 0x5a)
			return EBADMSG;
	m->saw_page = true;
	return 0;
}
static int
stage_dev(void *arg, const uint8_t *buf, size_t len)
{
	struct model *m = arg;
	if (len != 4 || memcmp(buf, "V010", 4) != 0)
		return EBADMSG;
	m->saw_dev = true;
	return 0;
}
static int
commit(void *arg)
{
	struct model *m = arg;
	if (!m->saw_page || !m->saw_dev)
		return EPROTO;
	m->committed = true;
	return 0;
}
static int
resume(void *arg)
{
	struct model *m = arg;
	if (!m->committed)
		return EPROTO;
	m->resumed = true;
	return 0;
}
static void
discard(void *arg)
{
	((struct model *)arg)->discarded = true;
}
int
main(int argc, char **argv)
{
	struct model m = { 0 };
	struct migration_dest_ops ops = { .do_local_hello = hello,
		.do_local_topology = topology,
		.do_stage_mem = stage_mem,
		.do_stage_dev = stage_dev,
		.do_commit = commit,
		.do_resume = resume,
		.do_discard = discard };
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_session_config cfg = { .version_min = 1,
		.version_max = MIGRATION_PROTO_VERSION,
		.max_rounds = 8 };
	struct migration_dest_result result;
	int error;
	if (argc != 2)
		return 2;
	migration_transport_fd_init(&xp, &fdx, atoi(argv[1]), 5000);
	error = migration_dest_run(&xp, &ops, &m, &cfg, &result);
	printf(
	    "new-dest error=%d phase=%u version=%u resumed=%d committed=%d discarded=%d\n",
	    error, result.phase, result.negotiated_version, m.resumed,
	    m.committed, m.discarded);
	if (getenv("V010_DISABLE_OPTIN") != NULL)
		return error != 0 && !m.saw_page && !m.saw_dev &&
		    !m.committed && !m.resumed ? 0 : 1;
	return error == 0 && m.saw_page && m.saw_dev && m.committed &&
		m.resumed && !m.discarded && result.negotiated_version == 1 ?
	    0 :
	    1;
}
