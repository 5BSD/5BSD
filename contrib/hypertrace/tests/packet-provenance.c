/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/mbufid.h>
#include <sys/uio.h>
#include <crypto/siphash/siphash.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#define IFF_UP 1
#define TUN_PROPAGATE_TAG 2
#define TUN_PROPAGATE_TAG_V2 16
#define TUN_L2 4
#define TUN_IFHEAD 8
#define TAPMRU 1500
#define TUNMRU 1500
#define ETHER_ALIGN 2
#define M_PKTHDR 1
#define M_NOWAIT 0
#define IFCOUNTER_IERRORS 0
#define TUN2IFP(tp) (&(tp)->ifp)
#define TUNDEBUG(...) ((void)0)
#define TUN_LOCK(tp) ((void)0)
#define TUN_UNLOCK(tp) ((void)0)
#define cv_broadcast(cv) ((void)0)
#define SDT_PROBE1(...) ((void)0)
#define KASSERT(cond, msg) assert(cond)
#define TAPSTAGGING 1
#define TAPSTAGGINGV2 2
struct ifnet { int if_flags; };
struct tuntap_softc { unsigned tun_flags; int tun_vhdrlen; struct ifnet ifp;
    uint16_t tun_bound_vmid; uint64_t tun_bound_epoch; unsigned tun_tag_io; int tun_cv; };
struct cdev { struct tuntap_softc *si_drv1; };
struct uio { ssize_t uio_resid; unsigned char *data; };
struct virtio_net_hdr_mrg_rxbuf { unsigned char bytes[12]; };
struct mbuf { int m_flags; struct { struct ifnet *rcvif; mbufid_t mbufid;
    mbufid_v2_t v2id; } m_pkthdr;
    int m_len; struct mbuf *m_next; char *m_data; };
static int id_present = 1;
static mbufid_t *m_mbufid(struct mbuf *m) {
    return id_present ? &m->m_pkthdr.mbufid : NULL;
}
struct sglist_seg { const void *ss_paddr; size_t ss_len; };
struct sglist { unsigned short sg_nseg, sg_maxseg; struct sglist_seg sg_segs[4]; };
struct sgsave { unsigned short sg_nseg; size_t ss_len; };
#define SGLIST_SAVE(sg, save) do { (save).sg_nseg = (sg)->sg_nseg; \
    (save).ss_len = (save).sg_nseg ? (sg)->sg_segs[(save).sg_nseg - 1].ss_len : 0; } while (0)
#define SGLIST_RESTORE(sg, save) do { (sg)->sg_nseg = (save).sg_nseg; \
    if ((save).sg_nseg) (sg)->sg_segs[(save).sg_nseg - 1].ss_len = (save).ss_len; } while (0)
static int fail_sg_id, fail_sg_data;
static int sglist_append(struct sglist *sg, const void *data, size_t len) {
    if (fail_sg_id || sg->sg_nseg == sg->sg_maxseg) return EFBIG;
    sg->sg_segs[sg->sg_nseg++] = (struct sglist_seg){data, len}; return 0;
}
static int sglist_append_mbuf(struct sglist *sg, struct mbuf *m) {
    struct sgsave save; SGLIST_SAVE(sg, save);
    for (; m; m = m->m_next) if (m->m_len > 0) {
        if (sg->sg_nseg == sg->sg_maxseg) { SGLIST_RESTORE(sg, save); return EFBIG; }
        sg->sg_segs[sg->sg_nseg++] =
            (struct sglist_seg){m->m_data, (size_t)m->m_len};
    }
    if (fail_sg_data) { SGLIST_RESTORE(sg, save); return EFBIG; }
    return 0;
}
static int fail_id_ensure, id_ensure_calls, freed_packets;
static int fail_v2_ensure, v2_ensure_calls;
static mbufid_t *m_mbufid_ensure(struct mbuf *m, int how __unused) {
    id_ensure_calls++;
    return fail_id_ensure ? NULL : m_mbufid(m);
}
static mbufid_v2_t *m_mbufid_v2_ensure(struct mbuf *m, int how __unused) {
    v2_ensure_calls++;
    return fail_v2_ensure ? NULL : &m->m_pkthdr.v2id;
}
static uint16_t live_vmid = 12;
static uint64_t live_epoch = 0x83a7;
static uint64_t foreign_epoch = 0x777;
static int mbufid_v2_vm_epoch_current(uint16_t vmid, uint64_t epoch) {
    return ((vmid == live_vmid && epoch == live_epoch) ||
        (vmid == 12 && epoch == foreign_epoch));
}
static void m_freem(struct mbuf *m __unused) { freed_packets++; }
static struct mbuf packet;
static unsigned char received[1500], header[12];
static size_t received_length;
static int delivered;
static int uiomove(void *dst, size_t len, struct uio *u) {
    if (u->uio_resid < 0 || len > (size_t)u->uio_resid) return EINVAL;
    memcpy(dst, u->data, len); u->data += len; u->uio_resid -= len; return 0;
}
static struct mbuf *m_uiotombuf(struct uio *u, int a __unused, int b __unused,
    int c __unused, int d __unused) {
    assert(u->uio_resid >= 0 && (size_t)u->uio_resid <= sizeof(received));
    memset(&packet, 0, sizeof(packet)); packet.m_flags = M_PKTHDR;
    received_length = u->uio_resid; memcpy(received, u->data, received_length);
    return &packet;
}
static void if_inc_counter(struct ifnet *p __unused, int a __unused, int b __unused) {}
static int tunwrite_l2(struct tuntap_softc *t __unused, struct mbuf *m __unused,
    struct virtio_net_hdr_mrg_rxbuf *h) {
    delivered++; if (h) memcpy(header, h, sizeof(header)); return 0;
}
static int tunwrite_l3(struct tuntap_softc *t, struct mbuf *m) { return tunwrite_l2(t, m, NULL); }
struct tap_priv { unsigned char bbuf[1600]; size_t bbuflen; };
struct net_backend { int fd, tagging_enabled, tagging_v2_enabled;
    size_t be_vnet_hdr_len;
    int (*tagging_enable_v2)(struct net_backend *);
    int (*checkpoint_rx_quiescent)(struct net_backend *);
    int (*checkpoint_rx_freeze)(struct net_backend *, bool);
    int (*tagging_disable)(struct net_backend *); struct tap_priv priv; };
static int checkpoint_quiescent(struct net_backend *be __unused) { return 0; }
static int checkpoint_freeze(struct net_backend *be __unused,
    bool freeze __unused) { return 0; }
#define NET_BE_PRIV(be) (&(be)->priv)
static mbufid_t probe_id;
static int probe_seen;
static int v1_probe_enabled = 1;
static mbufid_v2_t probe_id_v2;
static int v2_probe_seen;
static int v2_probe_enabled = 1;
static void capture_probe(const char *name, const void *id) {
    if (strstr(name, "__v2") != NULL) {
        memcpy(&probe_id_v2, id, sizeof(probe_id_v2)); v2_probe_seen++;
    } else {
        memcpy(&probe_id, id, sizeof(probe_id)); probe_seen++;
    }
}
#define DTRACE_PROBE2(prov, name, arg1, arg2) capture_probe(#name, (arg2))
#define NETBE_TAP_RECV_ENABLED() v1_probe_enabled
#define NETBE_TAP_SEND_ENABLED() v1_probe_enabled
#define NETBE_TAP_RECV_V2_ENABLED() v2_probe_enabled
#define NETBE_TAP_SEND_V2_ENABLED() v2_probe_enabled
#define g_vmname "test-vm"
static size_t count_iov(const struct iovec *iov, size_t n) {
    size_t total = 0;
    for (size_t i = 0; i < n; i++) total += iov[i].iov_len;
    return total;
}
static size_t buf_to_iov(const void *buf, size_t len, const struct iovec *iov, size_t n) {
    size_t copied = 0;
    for (size_t i = 0; i < n && copied < len; i++) {
        size_t part = MIN(iov[i].iov_len, len - copied);
        memcpy(iov[i].iov_base, (const unsigned char *)buf + copied, part);
        copied += part;
    }
    return copied;
}
static int ioctl_result, ioctl_calls, ioctl_flag_seen, ioctl_op_seen;
static int ioctl(int fd __unused, int op, int *flag) {
    assert(*flag == 0 || *flag == 1);
    ioctl_calls++; ioctl_flag_seen = *flag; ioctl_op_seen = op;
    return ioctl_result;
}
static hostid_t dtrace_node_id = 0x12;
static void msgid_generate(msgid_t *id) { memset(id, 0x35, sizeof(*id)); }
int mbufid_isvalid(mbufid_t *);
static void mbufid_assert_sanity(mbufid_t *id) { assert(id->mid_magic == MBUFID_MAGIC_NUMBER); }
static uint8_t mbufid_v2_key[SIPHASH_KEY_LENGTH] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static bool mbufid_v2_key_ready = true;
#define HYPERTRACE_MAX_VMS 1024
static uint64_t mbufid_v2_host_epoch = UINT64_C(0x97538471625340ab);
static uint64_t mbufid_v2_hostid = UINT64_C(0xe7538471625340ab);
int timingsafe_bcmp(const void *, const void *, size_t);
#include "packet-v2-auth.inc"
#include "packet-provenance.inc"
int main(void) {
    assert(mbufid_isempty(NULL));
    assert(!mbufid_iscanonical(NULL));
    assert(!mbufid_isvalid(NULL));
    unsigned char wire[1600]; mbufid_t mid = {
        .mid_hostid = 0x12, .mid_msgid = 0x35,
        .mid_magic = MBUFID_MAGIC_NUMBER
    };
    struct tuntap_softc tap = {.tun_flags = TUN_L2, .ifp = {IFF_UP}};
    struct cdev dev = {&tap};
    for (int tagged = 0; tagged < 2; tagged++) for (int virtio = 0; virtio < 2; virtio++) {
        size_t n = 0;
        tap.tun_flags = TUN_L2 | (tagged ? TUN_PROPAGATE_TAG : 0);
        tap.tun_vhdrlen = virtio ? 12 : 0;
        if (virtio) { memset(wire, 0x27, 12); n += 12; }
        if (tagged) { memcpy(wire + n, &mid, sizeof(mid)); n += sizeof(mid); }
        memset(wire + n, 0x51, 1500); n += 1500;
        struct uio u = {(ssize_t)n, wire}; delivered = 0;
        assert(tunwrite(&dev, &u, 0) == 0 && delivered == 1);
        assert(received_length == 1500 && received[0] == 0x51 && received[1499] == 0x51);
        if (virtio) assert(header[0] == 0x27 && header[11] == 0x27);
        if (tagged) assert(memcmp(&packet.m_pkthdr.mbufid, &mid, sizeof(mid)) == 0);
        u = (struct uio){(ssize_t)n + 1, wire}; assert(tunwrite(&dev, &u, 0) == EIO);
    }
    for (size_t len = 1; len <= 12 + sizeof(mid); len++) {
        struct uio u = {(ssize_t)len, wire}; delivered = 0;
        assert(tunwrite(&dev, &u, 0) != 0 && delivered == 0);
    }
    tap.tun_flags = TUN_L2 | TUN_PROPAGATE_TAG; tap.tun_vhdrlen = 0;
    memset(wire, 0, sizeof(mid)); memset(wire + sizeof(mid), 0x51, 16);
    struct uio zero_id = {(ssize_t)sizeof(mid) + 16, wire};
    int old_ensures = id_ensure_calls;
    delivered = 0;
    assert(tunwrite(&dev, &zero_id, 0) == 0 && delivered == 1);
    assert(id_ensure_calls == old_ensures + 1);
    assert(mbufid_isempty(&packet.m_pkthdr.mbufid));
    old_ensures = id_ensure_calls;
    mbufid_t no_origin = mid; no_origin.mid_hostid = 0;
    memcpy(wire, &no_origin, sizeof(no_origin));
    struct uio missing_origin = {(ssize_t)sizeof(no_origin) + 16, wire};
    delivered = 0;
    assert(tunwrite(&dev, &missing_origin, 0) == EINVAL && delivered == 0);
    assert(id_ensure_calls == old_ensures);
    mbufid_t bad_magic = mid; bad_magic.mid_magic = 0;
    memcpy(wire, &bad_magic, sizeof(bad_magic));
    struct uio invalid_magic = {(ssize_t)sizeof(mid) + 16, wire};
    assert(tunwrite(&dev, &invalid_magic, 0) == EINVAL && delivered == 0);
    mbufid_t bad_padding = mid; bad_padding.__mid_pad[0] = 1;
    memcpy(wire, &bad_padding, sizeof(bad_padding));
    struct uio invalid_padding = {(ssize_t)sizeof(mid) + 16, wire};
    assert(tunwrite(&dev, &invalid_padding, 0) == EINVAL && delivered == 0);
    memcpy(wire, &mid, sizeof(mid));
    struct uio failed_id = {(ssize_t)sizeof(mid) + 16, wire};
    int old_frees = freed_packets;
    fail_id_ensure = 1; delivered = 0;
    assert(tunwrite(&dev, &failed_id, 0) == ENOBUFS && delivered == 0);
    assert(freed_packets == old_frees + 1);
    fail_id_ensure = 0;
    tap.tun_flags = TUN_L2 | TUN_PROPAGATE_TAG_V2;
    tap.tun_bound_vmid = live_vmid;
    tap.tun_bound_epoch = live_epoch;
    mbufid_v2_t v2 = { .mv2_id = {
        .mid_hostid = live_vmid, .mid_msgid = 97,
        .mid_magic = MBUFID_MAGIC_NUMBER } };
    memcpy(wire, &v2, sizeof(v2));
    memset(wire + sizeof(v2), 0x52, 16);
    struct uio v2_input = { (ssize_t)sizeof(v2) + 16, wire };
    delivered = 0;
    assert(tunwrite(&dev, &v2_input, 0) == 0 && delivered == 1);
    assert(tap.tun_tag_io == 0 && received_length == 16);
    assert(packet.m_pkthdr.v2id.mv2_id.mid_hostid == live_vmid);
    assert(le64toh(packet.m_pkthdr.v2id.mv2_epoch) == live_epoch);
    assert(mbufid_v2_verify(&packet.m_pkthdr.v2id) == 0);
    tap.tun_bound_vmid = 13; live_vmid = 13;
    v2_input = (struct uio){ (ssize_t)sizeof(v2) + 16, wire };
    delivered = 0;
    assert(tunwrite(&dev, &v2_input, 0) == EACCES && delivered == 0);
    assert(tap.tun_tag_io == 0);
    mbufid_v2_t relay = { .mv2_id = {
        .mid_hostid = 12, .mid_msgid = 97,
        .mid_magic = MBUFID_MAGIC_NUMBER } };
    assert(mbufid_v2_stamp(&relay, 0x777) == 0);
    memcpy(wire, &relay, sizeof(relay));
    v2_input = (struct uio){ (ssize_t)sizeof(relay) + 16, wire };
    delivered = 0;
    assert(tunwrite(&dev, &v2_input, 0) == 0 && delivered == 1);
    assert(memcmp(&packet.m_pkthdr.v2id, &relay, sizeof(relay)) == 0);
    foreign_epoch = 0;
    v2_input = (struct uio){ (ssize_t)sizeof(relay) + 16, wire };
    delivered = 0;
    assert(tunwrite(&dev, &v2_input, 0) == ESTALE && delivered == 0);
    foreign_epoch = 0x777;
    relay.mv2_stamp ^= 1;
    memcpy(wire, &relay, sizeof(relay));
    v2_input = (struct uio){ (ssize_t)sizeof(relay) + 16, wire };
    delivered = 0;
    assert(tunwrite(&dev, &v2_input, 0) == EACCES && delivered == 0);
    assert(tap.tun_tag_io == 0);
    live_epoch++;
    v2_input = (struct uio){ (ssize_t)sizeof(relay) + 16, wire };
    assert(tunwrite(&dev, &v2_input, 0) == ESTALE && delivered == 0);
    live_epoch--;
    memset(wire, 0, sizeof(v2));
    v2_input = (struct uio){ (ssize_t)sizeof(v2) + 16, wire };
    int old_v2_ensures = v2_ensure_calls;
    assert(tunwrite(&dev, &v2_input, 0) == 0);
    assert(v2_ensure_calls == old_v2_ensures + 1);
    assert(mbufid_v2_isempty(&packet.m_pkthdr.v2id));
    assert(packet.m_pkthdr.v2id.mv2_epoch == 0);
    memcpy(wire, &v2, sizeof(v2));
    fail_v2_ensure = 1;
    old_frees = freed_packets;
    v2.mv2_id.mid_hostid = live_vmid;
    memcpy(wire, &v2, sizeof(v2));
    v2_input = (struct uio){ (ssize_t)sizeof(v2) + 16, wire };
    assert(tunwrite(&dev, &v2_input, 0) == ENOBUFS);
    assert(freed_packets == old_frees + 1 && tap.tun_tag_io == 0);
    fail_v2_ensure = 0;
    struct net_backend be = {.tagging_disable = tap_tagging_disable}; ioctl_result = -1;
    assert(tap_tagging_enable(&be) == -1 && !be.tagging_enabled);
    ioctl_result = 0; assert(tap_tagging_enable(&be) == 0 && be.tagging_enabled);
    ioctl_result = -1;
    be.priv.bbuflen = 12 + sizeof(mid);
    assert(netbe_tagging_disable(&be) == -1 && be.tagging_enabled);
    assert(be.priv.bbuflen == 12 + sizeof(mid));
    ioctl_result = 0;
    assert(netbe_tagging_disable(&be) == 0 && !be.tagging_enabled);
    assert(be.priv.bbuflen == 0);
    assert(ioctl_flag_seen == 0);
    int old_ioctl_calls = ioctl_calls;
    assert(netbe_tagging_disable(&be) == 0 && ioctl_calls == old_ioctl_calls);
    be.tagging_enabled = 1; be.tagging_disable = NULL;
    assert(netbe_tagging_disable(&be) == EOPNOTSUPP && be.tagging_enabled);
    be.tagging_enabled = 0; be.tagging_disable = tap_tagging_disable;
    assert(tap_tagging_enable(&be) == 0 && be.tagging_enabled);
    assert(!netbe_tagging_v2_supported(&be));
    assert(netbe_tagging_enable_v2(&be) == -1 && errno == EOPNOTSUPP);
    assert(tap_tagging_disable(&be) == 0);
    be.tagging_enable_v2 = tap_tagging_enable_v2;
    be.checkpoint_rx_quiescent = checkpoint_quiescent;
    be.checkpoint_rx_freeze = checkpoint_freeze;
    assert(netbe_tagging_v2_supported(&be));
    assert(netbe_tagging_enable_v2(&be) == 0 && be.tagging_enabled &&
        be.tagging_v2_enabled && ioctl_op_seen == TAPSTAGGINGV2);
    assert(tap_tagging_disable(&be) == 0 && !be.tagging_v2_enabled &&
        ioctl_op_seen == TAPSTAGGINGV2);
    assert(tap_tagging_enable(&be) == 0 && be.tagging_enabled);
    memset(&mid, 0xa5, sizeof(mid)); mbufid_generate(&mid);
    for (size_t i = 0; i < sizeof(mid.__mid_pad); i++) assert(mid.__mid_pad[i] == 0);
    unsigned char tagged[12 + sizeof(mid)]; mbufid_t observed;
    memset(tagged, 0x27, 12); memcpy(tagged + 12, &mid, sizeof(mid));
    struct iovec one[] = {{tagged, sizeof(tagged)}};
    assert(tap_probe_mbufid(one, 1, sizeof(tagged), 12, &observed));
    assert(memcmp(&observed, &mid, sizeof(mid)) == 0);
    struct iovec split[] = {
        {tagged, 7}, {tagged + 7, 10},
        {tagged + 17, sizeof(tagged) - 17}
    };
    memset(&observed, 0, sizeof(observed));
    assert(tap_probe_mbufid(split, 3, sizeof(tagged), 12, &observed));
    assert(memcmp(&observed, &mid, sizeof(mid)) == 0);
    assert(!tap_probe_mbufid(split, 3, sizeof(tagged) - 1, 12, &observed));
    assert(!tap_probe_mbufid(split, 2, sizeof(tagged), 12, &observed));
    assert(!tap_probe_mbufid(split, 0, sizeof(tagged), 12, &observed));
    int fds[2]; assert(pipe(fds) == 0);
    be.fd = fds[1]; be.be_vnet_hdr_len = 12; probe_seen = 0;
    assert(tap_send(&be, split, 3) == (ssize_t)sizeof(tagged));
    assert(probe_seen == 1 && memcmp(&probe_id, &mid, sizeof(mid)) == 0);
    unsigned char roundtrip[sizeof(tagged)];
    assert(read(fds[0], roundtrip, sizeof(roundtrip)) == (ssize_t)sizeof(roundtrip));
    assert(memcmp(roundtrip, tagged, sizeof(tagged)) == 0);
    probe_seen = 0;
    assert(tap_send(&be, NULL, 0) == 0 && probe_seen == 0);
    assert(write(fds[1], tagged, sizeof(tagged)) == (ssize_t)sizeof(tagged));
    be.fd = fds[0]; struct iovec recv_one[] = {{roundtrip, sizeof(roundtrip)}};
    assert(tap_recv(&be, recv_one, 1) == (ssize_t)sizeof(tagged));
    assert(probe_seen == 1 && memcmp(&probe_id, &mid, sizeof(mid)) == 0);
    mbufid_v2_t trace_v2 = { .mv2_id = mid,
        .mv2_epoch = UINT64_C(0x123456789abcdef0),
        .mv2_stamp = UINT64_C(0xfedcba9876543210) };
    unsigned char tagged_v2[12 + sizeof(trace_v2)];
    memset(tagged_v2, 0x27, 12);
    memcpy(tagged_v2 + 12, &trace_v2, sizeof(trace_v2));
    struct iovec split_v2[] = {
        {tagged_v2, 17}, {tagged_v2 + 17, 23},
        {tagged_v2 + 40, sizeof(tagged_v2) - 40}
    };
    mbufid_v2_t observed_v2;
    assert(tap_probe_mbufid_v2(split_v2, 3, sizeof(tagged_v2), 12,
        &observed_v2));
    assert(memcmp(&observed_v2, &trace_v2, sizeof(trace_v2)) == 0);
    assert(!tap_probe_mbufid_v2(split_v2, 3, sizeof(tagged_v2) - 1, 12,
        &observed_v2));
    be.fd = fds[1]; be.tagging_v2_enabled = 1;
    probe_seen = v2_probe_seen = 0;
    assert(tap_send(&be, split_v2, 3) == (ssize_t)sizeof(tagged_v2));
    assert(probe_seen == 1 && v2_probe_seen == 1);
    assert(memcmp(&probe_id_v2, &trace_v2, sizeof(trace_v2)) == 0);
    unsigned char received_v2[sizeof(tagged_v2)];
    assert(read(fds[0], received_v2, sizeof(received_v2)) ==
        (ssize_t)sizeof(received_v2));
    assert(write(fds[1], tagged_v2, sizeof(tagged_v2)) ==
        (ssize_t)sizeof(tagged_v2));
    be.fd = fds[0];
    struct iovec recv_v2[] = {{received_v2, sizeof(received_v2)}};
    probe_seen = v2_probe_seen = 0;
    assert(tap_recv(&be, recv_v2, 1) == (ssize_t)sizeof(received_v2));
    assert(probe_seen == 1 && v2_probe_seen == 1);
    assert(memcmp(&probe_id_v2, &trace_v2, sizeof(trace_v2)) == 0);
    v2_probe_enabled = 0;
    be.fd = fds[1];
    probe_seen = v2_probe_seen = 0;
    assert(tap_send(&be, split_v2, 3) == (ssize_t)sizeof(tagged_v2));
    assert(probe_seen == 1 && v2_probe_seen == 0);
    assert(read(fds[0], received_v2, sizeof(received_v2)) ==
        (ssize_t)sizeof(received_v2));
    v1_probe_enabled = 0;
    probe_seen = v2_probe_seen = 0;
    assert(tap_send(&be, split_v2, 3) == (ssize_t)sizeof(tagged_v2));
    assert(probe_seen == 0 && v2_probe_seen == 0);
    assert(read(fds[0], received_v2, sizeof(received_v2)) ==
        (ssize_t)sizeof(received_v2));
    v1_probe_enabled = 1;
    v2_probe_enabled = 1;
    be.tagging_v2_enabled = 0;
    close(fds[0]); close(fds[1]);
    memcpy(be.priv.bbuf, tagged, sizeof(tagged));
    be.priv.bbuflen = sizeof(tagged); probe_seen = 0;
    recv_one[0].iov_len = sizeof(tagged) - 1;
    assert(tap_recv(&be, recv_one, 1) == (ssize_t)sizeof(tagged) - 1);
    assert(probe_seen == 0);
    be.priv.bbuflen = sizeof(tagged);
    recv_one[0].iov_len = sizeof(tagged);
    assert(tap_recv(&be, recv_one, 1) == (ssize_t)sizeof(tagged));
    assert(probe_seen == 1 && memcmp(&probe_id, &mid, sizeof(mid)) == 0);
    struct mbuf empty_head = {.m_flags = M_PKTHDR, .m_len = 0,
        .m_pkthdr = {.mbufid = mid}};
    struct mbuf payload = {.m_len = 16, .m_data = (char *)wire};
    empty_head.m_next = &payload;
    struct sglist sg = {.sg_maxseg = 4};
    int mbuf_fail = -1;
    assert(sglist_append_mbuf_with_id(&sg, &empty_head, &mbuf_fail) == 0);
    assert(sg.sg_nseg == 2 && sg.sg_segs[0].ss_paddr == m_mbufid(&empty_head) &&
        sg.sg_segs[0].ss_len == sizeof(mid) &&
        sg.sg_segs[1].ss_paddr == wire && sg.sg_segs[1].ss_len == 16);
    sg.sg_nseg = 1; sg.sg_segs[0] = (struct sglist_seg){wire, 7};
    fail_sg_data = 1; mbuf_fail = -1;
    assert(sglist_append_mbuf_with_id(&sg, &empty_head, &mbuf_fail) == EFBIG);
    assert(mbuf_fail == 1 && sg.sg_nseg == 1 && sg.sg_segs[0].ss_len == 7);
    fail_sg_data = 0; fail_sg_id = 1; mbuf_fail = -1;
    assert(sglist_append_mbuf_with_id(&sg, &empty_head, &mbuf_fail) == EFBIG);
    assert(mbuf_fail == 0 && sg.sg_nseg == 1 && sg.sg_segs[0].ss_len == 7);
    fail_sg_id = 0;
    id_present = 0; sg.sg_nseg = 0; mbuf_fail = -1;
    assert(sglist_append_mbuf_with_id(&sg, &empty_head, &mbuf_fail) == 0);
    assert(sg.sg_nseg == 2 && sg.sg_segs[0].ss_len == sizeof(mid) &&
        mbufid_isempty(sg.sg_segs[0].ss_paddr));
    id_present = 1;
    puts("PASS: TAP/VirtIO packet IDs, framing, probes and scatter/gather rollback");
}
