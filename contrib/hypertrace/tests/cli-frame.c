/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "hypertrace_frame.h"
int main(void)
{
    unsigned char allocation[128], *wire = allocation + 1;
    struct dtrace_ht_view view;
    struct hypertrace_vm_envelope envelope = {
        .magic = HYPERTRACE_ENVELOPE_MAGIC, .version = HYPERTRACE_ENVELOPE_VERSION,
        .vmid = 7, .epoch = 42, .name_length = 3 };
    size_t prefix = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, total = prefix + 7;
    memset(allocation, 0, sizeof(allocation));
    hypertrace_envelope_encode(wire, &envelope);
    memcpy(wire + prefix, "vm7\177ELF", 7);
    assert(wire[0] == 'H' && wire[1] == 'T' && wire[2] == 'V' &&
        wire[3] == '2' && wire[4] == 2 && wire[5] == 0 &&
        wire[6] == 7 && wire[7] == 0 && wire[8] == 42 &&
        wire[16] == 3 && wire[23] == 0);
    assert(dtrace_ht_decode(wire, total, 8, &view) == 0);
    assert(view.vmid == 7 && view.epoch == 42 && view.name_length == 3 && view.length == 4);
    uint8_t program_id[16] = {1}, source_id[16] = {2}, zero_id[16] = {0};
    assert(dtrace_ht_validate_delivery(&view, 99, program_id, source_id,
        7, 42) == 0);
    assert(dtrace_ht_validate_delivery(&view, 99, program_id, source_id,
        8, 42) == EPROTO);
    assert(dtrace_ht_validate_delivery(&view, 99, program_id, source_id,
        7, 43) == EPROTO);
    assert(dtrace_ht_validate_delivery(&view, 0, program_id, source_id,
        7, 42) == EPROTO);
    assert(dtrace_ht_validate_delivery(&view, 99, zero_id, source_id,
        7, 42) == EPROTO);
    assert(dtrace_ht_validate_delivery(&view, 99, program_id, zero_id,
        7, 42) == EPROTO);
    assert(dtrace_ht_validate_delivery(&view, 0, zero_id, zero_id,
        0, 0) == 0);
    for (size_t n = 0; n < total; n++) assert(dtrace_ht_decode(wire, n, 8, &view) == EINVAL);
    assert(dtrace_ht_decode(wire, total, 3, &view) == EINVAL);
    assert(dtrace_ht_decode(wire, 64U * 1024U * 1024U + 1U, 8, &view) == EINVAL);
    envelope.name_length = UINT64_MAX; hypertrace_envelope_encode(wire, &envelope);
    assert(dtrace_ht_decode(wire, total, 8, &view) == EINVAL);
    envelope.name_length = 3; envelope.epoch = 0;
    hypertrace_envelope_encode(wire, &envelope);
    assert(dtrace_ht_decode(wire, total, 8, &view) == EINVAL);
    envelope.epoch = 42; envelope.version--;
    hypertrace_envelope_encode(wire, &envelope);
    assert(dtrace_ht_decode(wire, total, 8, &view) == EINVAL);
    envelope.version++; envelope.vmid = HYPERTRACE_MAX_VMS;
    hypertrace_envelope_encode(wire, &envelope);
    assert(dtrace_ht_decode(wire, total, 8, &view) == EINVAL);
    envelope.vmid = 7; hypertrace_envelope_encode(wire, &envelope);
    wire[prefix + 1] = 0;
    assert(dtrace_ht_decode(wire, total, 8, &view) == EINVAL);
    /* A legacy VM-ID-only frame must never be accepted as a current lifetime. */
    memset(wire, 0, 64); uint16_t id = 7; uint64_t length = 3;
    memcpy(wire, &id, sizeof(id)); memcpy(wire + 8, &length, sizeof(length));
    memcpy(wire + 16, "vm7\177ELF", 7);
    assert(dtrace_ht_decode(wire, 23, 8, &view) == EINVAL);
    assert(dtrace_ht_decode("\177ELF", 4, 8, &view) == 0);
    assert(view.vmid == 0 && view.epoch == 0 && view.name == NULL && view.length == 4);
    for (unsigned round = 0; round < 4096; round++) {
        for (size_t i = 0; i < 64; i++) wire[i] = rand();
        for (size_t n = 0; n <= 64; n++) (void)dtrace_ht_decode(wire, n, 32, &view);
    }
    puts("PASS: versioned VM lifetime envelope, legacy rejection, bounds and unaligned input");
}
