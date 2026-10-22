/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stddef.h>
#include <sys/mbufid.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define M_NOWAIT 0

struct mbuf {
	mbufid_t id;
	mbufid_v2_t id_v2;
	bool has_id, has_v2;
	uint64_t local_epoch;
};
static hostid_t dtrace_node_id;
static uint64_t node_epoch = 7;
static unsigned generate_calls, ensure_calls;
static bool fail_ensure, drop_node_on_ensure;

static mbufid_t *
m_mbufid(struct mbuf *m)
{
	return (m->has_id ? &m->id : NULL);
}

static mbufid_t *
m_mbufid_ensure(struct mbuf *m, int flags)
{
	(void)flags;
	ensure_calls++;
	if (fail_ensure)
		return (NULL);
	if (drop_node_on_ensure)
		dtrace_node_id = 0;
	m->has_id = true;
	return (&m->id);
}

static mbufid_v2_t *
m_mbufid_v2(struct mbuf *m)
{
	return (m->has_v2 ? &m->id_v2 : NULL);
}

static uint64_t
mbufid_origin_epoch(void)
{
	return (node_epoch);
}

static uint64_t
m_mbufid_v2_local_epoch(struct mbuf *m)
{
	return (m->has_v2 ? m->local_epoch : 0);
}

static void
m_mbufid_v2_local_epoch_set(struct mbuf *m, uint64_t epoch)
{
	assert(m->has_v2);
	m->local_epoch = epoch;
}

static mbufid_v2_t *
m_mbufid_v2_ensure(struct mbuf *m, int flags)
{
	(void)flags;
	ensure_calls++;
	if (fail_ensure)
		return (NULL);
	if (drop_node_on_ensure)
		dtrace_node_id = 0;
	if (!m->has_v2) {
		memset(&m->id_v2, 0, sizeof(m->id_v2));
		m->local_epoch = node_epoch;
		if (m->has_id)
			m->id_v2.mv2_id = m->id;
		m->has_id = false;
		m->has_v2 = true;
	}
	return (&m->id_v2);
}

int
mbufid_origin_ready(void)
{
	return (dtrace_node_id != 0);
}

static void
msgid_generate(msgid_t *id)
{
	generate_calls++;
	*id = generate_calls;
}

#define SDT_PROBE1(provider, module, function, name, arg) ((void)(arg))
static void mbufid_assert_sanity(mbufid_t *id)
{
	assert(mbufid_iscanonical(id));
}

#include "mbufid-generate.inc"
#include "vtnet-packet-id-rx-v2.inc"
#include "vtnet-packet-id.inc"
#include "vtnet-packet-id-v2.inc"
#include "mbufid-valid.inc"

int
main(void)
{
	struct mbuf m = {};
	mbufid_t wire = {};
	assert(vtnet_tx_packet_id(&m, 0, &wire) == 0);
	assert(mbufid_isempty(&wire) && !m.has_id && ensure_calls == 0 &&
	    generate_calls == 0);

	dtrace_node_id = 42;
	assert(vtnet_tx_packet_id(&m, 0, &wire) == 0);
	assert(mbufid_iscanonical(&wire) && m.has_id);
	assert(memcmp(&wire, &m.id, sizeof(wire)) == 0 && ensure_calls == 1);
	assert(mbufid_isvalid(&wire));

	dtrace_node_id = 0;
	mbufid_t saved = wire;
	assert(vtnet_tx_packet_id(&m, 0, &wire) == 0);
	assert(memcmp(&wire, &saved, sizeof(wire)) == 0);
	assert(generate_calls == 1 && ensure_calls == 1);

	m.has_id = false;
	memset(&m.id, 0, sizeof(m.id));
	dtrace_node_id = 42;
	fail_ensure = true;
	assert(vtnet_tx_packet_id(&m, 0, &wire) == ENOBUFS);
	assert(!m.has_id && generate_calls == 1);
	fail_ensure = false;
	drop_node_on_ensure = true;
	assert(vtnet_tx_packet_id(&m, 0, &wire) == 0);
	assert(mbufid_isempty(&wire) && mbufid_isempty(&m.id));
	drop_node_on_ensure = false;

	m.has_id = true;
	m.id = saved;
	m.id.mid_magic = 0;
	assert(!mbufid_isvalid(&m.id));
	dtrace_node_id = 0;
	assert(vtnet_tx_packet_id(&m, 0, &wire) == 0);
	assert(mbufid_isempty(&wire) && mbufid_isempty(&m.id));
	m.id = saved;
	m.id.__mid_pad[0] = 1;
	assert(!mbufid_isvalid(&m.id));
	/* BPF and datagram sockets use this same generator before identity. */
	m.id = saved;
	mbufid_generate(&m.id);
	assert(mbufid_isempty(&m.id) && generate_calls == 1);
	dtrace_node_id = 42;
	mbufid_generate(&m.id);
	assert(mbufid_iscanonical(&m.id) && generate_calls == 2);

	/* A valid stamped record remains opaque across a guest relay. */
	mbufid_v2_t wire_v2 = {};
	m.has_v2 = true;
	m.local_epoch = node_epoch;
	m.id_v2.mv2_id = m.id;
	m.id_v2.mv2_id.mid_hostid = 77;
	m.id_v2.mv2_epoch = 7;
	m.id_v2.mv2_stamp = 9;
	unsigned before = generate_calls;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(memcmp(&wire_v2, &m.id_v2, sizeof(wire_v2)) == 0);
	assert(generate_calls == before);

	/* Identity clear cannot turn an epoch-zero tag into a valid relay. */
	node_epoch = 0;
	dtrace_node_id = 0;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(mbufid_v2_isempty(&wire_v2));
	assert(generate_calls == before);
	dtrace_node_id = 42;
	node_epoch = 7;

	/* A saved mbuf's old stamp is rebased after the guest rekeys. */
	node_epoch = 8;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(mbufid_v2_isfresh(&wire_v2));
	assert(m.local_epoch == node_epoch && generate_calls == before + 1);
	before = generate_calls;

	/* An unstamped V1 ID cannot become a foreign V2 claim. */
	m.has_v2 = false;
	m.has_id = true;
	m.id = wire_v2.mv2_id;
	m.id.mid_hostid = 77;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(m.has_v2 && !m.has_id && mbufid_v2_isfresh(&wire_v2));
	assert(wire_v2.mv2_id.mid_hostid == dtrace_node_id);
	assert(generate_calls == before + 1);

	m.has_v2 = false;
	dtrace_node_id = 0;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(mbufid_v2_isempty(&wire_v2) && !m.has_v2);
	dtrace_node_id = 42;
	fail_ensure = true;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == ENOBUFS);
	fail_ensure = false;
	drop_node_on_ensure = true;
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(mbufid_v2_isempty(&wire_v2));
	drop_node_on_ensure = false;

	/* An empty receive record remains unknown through a guest relay. */
	m.has_v2 = false;
	m.has_id = false;
	mbufid_v2_t empty = {};
	before = generate_calls;
	assert(vtnet_rx_packet_id_v2(&m, &empty) == 0);
	assert(m.has_v2 && mbufid_v2_isempty(&m.id_v2));
	assert(vtnet_tx_packet_id_v2(&m, 0, &wire_v2) == 0);
	assert(mbufid_v2_isempty(&wire_v2) && generate_calls == before);

	m.has_v2 = false;
	mbufid_v2_t malformed = { .mv2_id = {
		.mid_hostid = 77, .mid_msgid = 4,
		.mid_magic = MBUFID_MAGIC_NUMBER } };
	assert(vtnet_rx_packet_id_v2(&m, &malformed) == EINVAL);
	assert(!m.has_v2);
	fail_ensure = true;
	assert(vtnet_rx_packet_id_v2(&m, &empty) == ENOBUFS);
	assert(!m.has_v2);
	fail_ensure = false;
	malformed.mv2_epoch = 7;
	malformed.mv2_stamp = 9;
	assert(vtnet_rx_packet_id_v2(&m, &malformed) == 0);
	assert(memcmp(&m.id_v2, &malformed, sizeof(malformed)) == 0);
	puts("PASS: guest packet IDs preserve lineage and avoid unusable sidecars");
}
