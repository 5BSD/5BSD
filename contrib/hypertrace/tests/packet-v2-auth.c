/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mbufid.h>
#include <crypto/siphash/siphash.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static uint8_t mbufid_v2_key[SIPHASH_KEY_LENGTH];
static uint64_t mbufid_v2_host_epoch = UINT64_C(0x97538471625340ab);
static uint64_t mbufid_v2_hostid = UINT64_C(0xe7538471625340ab);
static bool mbufid_v2_key_ready = true;
#define HYPERTRACE_MAX_VMS 1024
static uint64_t guest_current_epoch = UINT64_C(0x1122334455667788);

int
mbufid_v2_vm_epoch_current(uint16_t vmid, uint64_t epoch)
{
    return (vmid == 37 && epoch == guest_current_epoch);
}

void
msgid_generate(msgid_t *id)
{
    *id = UINT64_C(0xbca93421);
}

int timingsafe_bcmp(const void *, const void *, size_t);
#include "packet-v2-auth.inc"

int
main(void)
{
    mbufid_v2_t fresh = {}, signed_id, corrupt, host, colliding, wrong_host;

    for (size_t i = 0; i < sizeof(mbufid_v2_key); i++)
        mbufid_v2_key[i] = (uint8_t)i;
    assert(sizeof(mbufid_v2_t) == 48);
    assert(mbufid_v2_isempty(&fresh));
    assert(mbufid_v2_verify(&fresh) == EINVAL);
    fresh.mv2_id.mid_hostid = 37;
    fresh.mv2_id.mid_msgid = 101;
    fresh.mv2_id.mid_magic = MBUFID_MAGIC_NUMBER;
    assert(mbufid_v2_isfresh(&fresh));
    assert(mbufid_v2_stamp(&fresh, 0) == EINVAL);
    assert(mbufid_v2_stamp(&fresh, UINT64_C(0x1122334455667788)) == 0);
    assert(mbufid_v2_isstamped(&fresh));
    assert(le64toh(fresh.mv2_epoch) == UINT64_C(0x1122334455667788));
    assert(mbufid_v2_verify(&fresh) == 0);
    assert(mbufid_v2_stamp(&fresh, 6) == EINVAL);
    signed_id = fresh;
    corrupt = fresh; corrupt.mv2_id.mid_hostid++;
    assert(mbufid_v2_verify(&corrupt) == EACCES);
    corrupt = fresh; corrupt.mv2_id.mid_msgid++;
    assert(mbufid_v2_verify(&corrupt) == EACCES);
    corrupt = fresh; corrupt.mv2_epoch++;
    assert(mbufid_v2_verify(&corrupt) == EACCES);
    corrupt = fresh; corrupt.mv2_stamp++;
    assert(mbufid_v2_verify(&corrupt) == EACCES);
    corrupt = fresh; corrupt.mv2_id.__mid_pad[0] = 1;
    assert(mbufid_v2_verify(&corrupt) == EINVAL);
    corrupt = fresh; corrupt.mv2_id.mid_magic = 0;
    assert(mbufid_v2_verify(&corrupt) == EINVAL);
    mbufid_v2_key[0] ^= 1;
    assert(mbufid_v2_verify(&signed_id) == EACCES);
    mbufid_v2_key[0] ^= 1;
    assert(mbufid_v2_verify(&signed_id) == 0); /* relay keeps origin */
    guest_current_epoch = 0;
    assert(mbufid_v2_verify(&signed_id) == ESTALE);
    guest_current_epoch = UINT64_C(0xaabbccddeeff0011);
    assert(mbufid_v2_verify(&signed_id) == ESTALE);
    guest_current_epoch = UINT64_C(0x1122334455667788);
    colliding = (mbufid_v2_t){ .mv2_id = {
        .mid_hostid = 37, .mid_msgid = 102,
        .mid_magic = MBUFID_MAGIC_NUMBER } };
    assert(mbufid_v2_stamp(&colliding, mbufid_v2_host_epoch) == 0);
    guest_current_epoch = mbufid_v2_host_epoch;
    assert(mbufid_v2_verify(&colliding) == 0);
    guest_current_epoch = 0;
    assert(mbufid_v2_verify(&colliding) == ESTALE);
    /* A host packet has an independent origin even with no DTrace node ID. */
    assert(mbufid_v2_make_host(&host) == 0);
    assert(host.mv2_id.mid_hostid == mbufid_v2_hostid);
    assert(host.mv2_id.mid_hostid >= HYPERTRACE_MAX_VMS);
    assert(le64toh(host.mv2_epoch) == mbufid_v2_host_epoch);
    assert(mbufid_v2_verify(&host) == 0);
    wrong_host = (mbufid_v2_t){ .mv2_id = {
        .mid_hostid = mbufid_v2_hostid,
        .mid_msgid = 103, .mid_magic = MBUFID_MAGIC_NUMBER } };
    assert(mbufid_v2_stamp(&wrong_host, 33) == 0);
    assert(mbufid_v2_verify(&wrong_host) == ESTALE);
    wrong_host.mv2_id.mid_hostid--;
    wrong_host.mv2_epoch = 0;
    wrong_host.mv2_stamp = 0;
    assert(mbufid_v2_stamp(&wrong_host, mbufid_v2_host_epoch) == 0);
    assert(mbufid_v2_verify(&wrong_host) == ESTALE);
    mbufid_v2_key_ready = false;
    assert(mbufid_v2_verify(&host) == EAGAIN);
    puts("PASS: actual V2 stamp, tamper rejection, relay preservation, host origin");
    return (0);
}
