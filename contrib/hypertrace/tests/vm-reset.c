/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
struct vm { uint16_t id; uint64_t hypertrace_epoch; };
static int fail, stage, release_count, init_count;
static uint16_t released_id;
static int hypertrace_vm_alloc(uint16_t *id, uint64_t *epoch) {
    assert(stage++ == 0); if (fail == 0) return ENOSPC;
    *id = 7; *epoch = 77; return 0;
}
static int hypertrace_vm_release(uint16_t id, uint64_t epoch) {
    assert((id == 7 && epoch == 77) || (id == 3 && epoch == 33));
    release_count++; released_id = id;
    return fail == 5 && id == 3 ? EIO : 0;
}
static int vm_vcpu_event_cleanup(struct vm *vm) { assert(vm->id == 3 && stage++ == 1); return fail == 1 ? EBUSY : 0; }
static int vm_event_coordinator_reset(struct vm *vm) { assert(vm->id == 3 && stage++ == 2); return fail == 2 ? EBUSY : 0; }
static int vm_cleanup(struct vm *vm, bool destroy) { assert(vm->id == 3 && !destroy && stage++ == 3); return fail == 3 ? EBUSY : 0; }
static void vm_init(struct vm *vm, bool create) {
    assert(!create && vm->id == 7 && vm->hypertrace_epoch == 77 && stage++ == 4); init_count++;
}
#include "vm-reset.inc"
int main(void) {
    for (fail = 0; fail <= 5; fail++) {
        struct vm vm = {3, 33}; stage = release_count = init_count = 0; released_id = 0;
        int error = vm_reset(&vm);
        if (fail == 4) {
            assert(error == 0 && init_count == 1 && release_count == 1 && released_id == 3);
            assert(vm.id == 7 && vm.hypertrace_epoch == 77);
        } else {
            assert(error == (fail == 0 ? ENOSPC :
                fail == 5 ? EIO : EBUSY) && init_count == 0);
            assert(vm.id == 3 && vm.hypertrace_epoch == 33);
            assert(release_count == (fail == 0 ? 0 : fail == 5 ? 2 : 1));
            if (fail) assert(released_id == 7);
        }
    }
    puts("PASS: actual VM reset identity reservation, existing coordinator ordering and failure rollback");
}
