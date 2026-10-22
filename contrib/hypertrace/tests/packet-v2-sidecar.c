/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/mbufid.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define M_PKTHDR 1
#define M_NOWAIT 0
#define MTAG_PERSISTENT 0x100
#define MTAG_MBUFID_COOKIE 0x68747263U
#define MTAG_MBUFID_TYPE (1 | MTAG_PERSISTENT)
#define SDT_PROBE2(...) ((void)0)
struct m_tag { struct m_tag *next; size_t m_tag_len; };
struct mbuf { int m_flags; struct m_tag *tag; };
static bool fail_alloc;
static int allocations, frees;
static uint64_t current_epoch = 7;

static uint64_t
mbufid_origin_epoch(void)
{
    return (current_epoch);
}

static struct m_tag *
m_tag_locate(struct mbuf *m, uint32_t cookie, uint16_t type,
    struct m_tag *after)
{
    assert(cookie == MTAG_MBUFID_COOKIE && type == MTAG_MBUFID_TYPE);
    assert(after == NULL);
    return (m->tag);
}

static struct m_tag *
m_tag_alloc(uint32_t cookie, uint16_t type, int len, int how)
{
    struct m_tag *tag;
    assert(cookie == MTAG_MBUFID_COOKIE && type == MTAG_MBUFID_TYPE);
    assert(how == M_NOWAIT);
    if (fail_alloc)
        return (NULL);
    tag = calloc(1, sizeof(*tag) + (size_t)len);
    assert(tag != NULL);
    tag->m_tag_len = (size_t)len;
    allocations++;
    return (tag);
}

static void
m_tag_prepend(struct mbuf *m, struct m_tag *tag)
{
    assert(m->tag == NULL);
    m->tag = tag;
}

static void
m_tag_delete(struct mbuf *m, struct m_tag *tag)
{
    assert(m->tag == tag);
    m->tag = NULL;
    free(tag);
    frees++;
}

#include "packet-v2-sidecar.inc"

int
main(void)
{
    struct mbuf packet = { .m_flags = M_PKTHDR };
    mbufid_t *v1;
    mbufid_v2_t *v2;

    assert(m_mbufid(&packet) == NULL);
    assert(m_mbufid_v2(&packet) == NULL);
    assert(m_mbufid_v2_local_epoch(&packet) == 0);
    v1 = m_mbufid_ensure(&packet, M_NOWAIT);
    assert(v1 != NULL && allocations == 1);
    v1->mid_hostid = 13;
    v1->mid_msgid = 89;
    v1->mid_magic = MBUFID_MAGIC_NUMBER;
    fail_alloc = true;
    assert(m_mbufid_v2_ensure(&packet, M_NOWAIT) == NULL);
    assert(m_mbufid(&packet) == v1 && frees == 0);
    fail_alloc = false;
    v2 = m_mbufid_v2_ensure(&packet, M_NOWAIT);
    assert(v2 != NULL && allocations == 2 && frees == 1);
    assert(v2->mv2_id.mid_hostid == 13 && v2->mv2_id.mid_msgid == 89);
    assert(v2->mv2_epoch == 0 && v2->mv2_stamp == 0);
    assert(packet.tag->m_tag_len == sizeof(struct mbufid_v2_tag));
    assert(m_mbufid_v2_local_epoch(&packet) == 7);
    assert(m_mbufid(&packet) == &v2->mv2_id);
    assert(m_mbufid_v2(&packet) == v2);
    assert(m_mbufid_v2_ensure(&packet, M_NOWAIT) == v2);
    current_epoch = 8;
    assert(m_mbufid_v2_local_epoch(&packet) == 7);
    m_mbufid_v2_local_epoch_set(&packet, current_epoch);
    assert(m_mbufid_v2_local_epoch(&packet) == 8);
    assert(m_mbufid_ensure(&packet, M_NOWAIT) == NULL);
    assert(allocations == 2 && frees == 1);
    m_tag_delete(&packet, packet.tag);
    assert(allocations == frees);
    puts("PASS: V2 sidecar upgrade preserves V1 on OOM, reuses persistent tag");
    return (0);
}
