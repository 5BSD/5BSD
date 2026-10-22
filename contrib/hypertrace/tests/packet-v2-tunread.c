/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/mbufid.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define TUN_READY 1
#define TUN_PROPAGATE_TAG 2
#define TUN_PROPAGATE_TAG_V2 4
#define TUN_RWAIT 8
#define TUN2IFP(tp) (&(tp)->ifp)
#define TUNDEBUG(...) ((void)0)
#define TUN_LOCK(tp) ((void)0)
#define TUN_UNLOCK(tp) ((void)0)
#define SDT_PROBE1(...) ((void)0)
#define SDT_PROBE2(...) ((void)0)
#define KASSERT(condition, message) assert(condition)
#define IFQ_DEQUEUE(queue, result) do { \
    (result) = (queue)->head; (queue)->head = NULL; \
} while (0)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define PCATCH 0
#define PZERO 0

struct mbuf {
    bool has_v2;
    bool has_v1;
    mbufid_v2_t id;
    mbufid_t v1id;
    unsigned char data[3];
};
struct ifnet { struct { struct mbuf *head; } if_snd; };
struct tuntap_softc {
    struct ifnet ifp;
    unsigned tun_flags;
    unsigned tun_vhdrlen;
    uint16_t tun_bound_vmid;
    uint64_t tun_bound_epoch;
    unsigned tun_tag_io;
    int tun_mtx, tun_cv;
};
struct cdev { struct tuntap_softc *si_drv1; };
struct uio { ssize_t uio_resid; unsigned char *data; };
struct virtio_net_hdr_mrg_rxbuf {
    struct { unsigned flags, gso_type, hdr_len, gso_size;
        unsigned csum_start, csum_offset; } hdr;
};

static unsigned frees, verifies, host_makes;
static int verify_result, host_result;
static uint16_t current_vmid = 12;
static uint64_t current_epoch = 0x83a7;
static const mbufid_v2_t host_id = { .mv2_id = {
    .mid_hostid = UINT64_C(0xe7538471625340ab),
    .mid_msgid = 93, .mid_magic = MBUFID_MAGIC_NUMBER },
    .mv2_epoch = 5, .mv2_stamp = 7 };

static int mbufid_v2_vm_epoch_current(uint16_t vmid, uint64_t epoch) {
    return vmid == current_vmid && epoch == current_epoch;
}
static const mbufid_t *m_mbufid(struct mbuf *m) {
    return m->has_v1 ? &m->v1id : NULL;
}
int mbufid_origin_ready(void) { return 0; }
void mbufid_generate(mbufid_t *id __unused) { assert(0); }
static const mbufid_v2_t *m_mbufid_v2(struct mbuf *m) {
    return m->has_v2 ? &m->id : NULL;
}
static int mbufid_v2_verify(const mbufid_v2_t *id __unused) {
    verifies++;
    return verify_result;
}
static int mbufid_v2_make_host(mbufid_v2_t *id) {
    host_makes++;
    if (host_result == 0)
        *id = host_id;
    return host_result;
}
static int mtx_sleep(void *a __unused, void *b __unused, int c __unused,
    const char *d __unused, int e __unused) { return EIO; }
static void cv_broadcast(void *a __unused) {}
static int uiomove(const void *source, size_t length, struct uio *uio) {
    if (uio->uio_resid < 0 || length > (size_t)uio->uio_resid)
        return EMSGSIZE;
    memcpy(uio->data, source, length);
    uio->data += length;
    uio->uio_resid -= length;
    return 0;
}
static int m_mbuftouio(struct uio *uio, struct mbuf *m, int offset __unused) {
    return uiomove(m->data, sizeof(m->data), uio);
}
static void m_freem(struct mbuf *m __unused) { frees++; }

#include "packet-v2-tunread.inc"

static int
read_packet(struct cdev *dev, struct mbuf *packet, mbufid_v2_t *observed)
{
    unsigned char output[sizeof(*observed) + sizeof(packet->data)] = {};
    struct uio uio = { sizeof(output), output };
    struct tuntap_softc *tap = dev->si_drv1;
    int error;

    tap->ifp.if_snd.head = packet;
    error = tunread(dev, &uio, O_NONBLOCK);
    assert(tap->tun_tag_io == 0);
    if (error == 0) {
        assert(uio.uio_resid == 0);
        memcpy(observed, output, sizeof(*observed));
        assert(memcmp(output + sizeof(*observed), packet->data,
            sizeof(packet->data)) == 0);
    }
    return error;
}

int
main(void)
{
    struct tuntap_softc tap = {
        .tun_flags = TUN_READY | TUN_PROPAGATE_TAG_V2,
        .tun_bound_vmid = 12, .tun_bound_epoch = 0x83a7 };
    struct cdev dev = { &tap };
    struct mbuf packet = { .has_v2 = true, .data = {1, 2, 3} };
    mbufid_v2_t observed;

    assert(read_packet(&dev, &packet, &observed) == 0);
    assert(mbufid_v2_isempty(&observed));
    assert(host_makes == 0 && verifies == 0);

    packet.has_v2 = false;
    assert(read_packet(&dev, &packet, &observed) == 0);
    assert(host_makes == 1 && memcmp(&observed, &host_id,
        sizeof(observed)) == 0);

    packet.has_v1 = true;
    packet.v1id = host_id.mv2_id;
    assert(read_packet(&dev, &packet, &observed) == 0);
    assert(mbufid_v2_isempty(&observed) && host_makes == 1);
    packet.has_v1 = false;

    packet.has_v2 = true;
    packet.id = host_id;
    assert(read_packet(&dev, &packet, &observed) == 0);
    assert(verifies == 1 && host_makes == 1);
    assert(memcmp(&observed, &host_id, sizeof(observed)) == 0);

    verify_result = EACCES;
    assert(read_packet(&dev, &packet, &observed) == EACCES);
    assert(verifies == 2 && host_makes == 1);
    verify_result = 0;

    packet.id.mv2_epoch = 0;
    packet.id.mv2_stamp = 0;
    assert(read_packet(&dev, &packet, &observed) == EINVAL);
    assert(verifies == 2 && host_makes == 1);

    packet.has_v2 = false;
    host_result = EAGAIN;
    assert(read_packet(&dev, &packet, &observed) == EAGAIN);
    assert(host_makes == 2);

    current_epoch++;
    assert(read_packet(&dev, &packet, &observed) == ESTALE);
    assert(host_makes == 2);
    assert(frees == 8);
    puts("PASS: TAP V2 read preserves empty and stamped guests, marks host only when untagged");
    return 0;
}
