/* SPDX-License-Identifier: BSD-2-Clause */
#define main map_main
#include "probe-map.c"
#undef main
#include <setjmp.h>
#include <stdbool.h>
#define HYPERTRACE_HOSTID 0
#define DTRACE_IDNONE 0
#define panic(...) abort()
typedef int hypertrace_id_t;
typedef struct {
    dtrace_id_t dtpd_id;
    char dtpd_provider[64], dtpd_mod[64], dtpd_func[64], dtpd_name[64];
} dtrace_probedesc_t;
static hypertrace_map_t *hypertrace_map;
static bool core[16];
static unsigned rejected_id, resource_id;
static uint64_t live_epoch = 42;
static uint64_t hypertrace_vm_epochs[HYPERTRACE_MAX_VMS];
static uint8_t hypertrace_vm_gate_tokens[HYPERTRACE_MAX_VMS][16];
static uint64_t dtrace_vm_epochs[HYPERTRACE_MAX_VMS];
static uint64_t suspended_epoch[HYPERTRACE_MAX_VMS];
static unsigned dtrace_drains;
static int dtrace_hypertrace_epoch_suspended(uint16_t id, uint64_t epoch) {
    return (id > 0 && id < HYPERTRACE_MAX_VMS && epoch != 0 &&
        suspended_epoch[id] == epoch);
}
static int dtrace_hypertrace_epoch_publish(uint16_t id, uint64_t epoch) {
    CHECK(id > 0 && id < HYPERTRACE_MAX_VMS && epoch != 0);
    if (dtrace_vm_epochs[id] != 0) return EBUSY;
    dtrace_vm_epochs[id] = epoch;
    return 0;
}
static int dtrace_hypertrace_epoch_revoke(uint16_t id, uint64_t epoch) {
    CHECK(id > 0 && id < HYPERTRACE_MAX_VMS && epoch != 0);
    if (dtrace_vm_epochs[id] != epoch && suspended_epoch[id] != epoch)
        return ESTALE;
    dtrace_vm_epochs[id] = 0;
    suspended_epoch[id] = 0;
    dtrace_drains++;
    return 0;
}
static uint64_t packet_vm_epochs[HYPERTRACE_MAX_VMS];
static unsigned packet_publishes, packet_revokes;
static void mbufid_v2_vm_epoch_publish(uint16_t id, uint64_t epoch) {
    CHECK(id > 0 && id < HYPERTRACE_MAX_VMS && epoch != 0);
    CHECK(packet_vm_epochs[id] == 0);
    packet_vm_epochs[id] = epoch;
    packet_publishes++;
}
static void mbufid_v2_vm_epoch_revoke(uint16_t id, uint64_t epoch) {
    CHECK(id > 0 && id < HYPERTRACE_MAX_VMS && epoch != 0);
    /* Later fixture epochs are synthesized to test stale virtual probes. */
    CHECK(packet_vm_epochs[id] == 0 || packet_vm_epochs[id] == epoch);
    packet_vm_epochs[id] = 0;
    packet_revokes++;
}
static int config_depth;
static void dtrace_hypertrace_config_lock(void) { CHECK(config_depth++ == 0); }
static void dtrace_hypertrace_config_unlock(void) { CHECK(--config_depth == 0); }
static uint64_t getepoch(const void *handle) { CHECK(handle != NULL); return live_epoch; }
static uint64_t (*vmm_getepoch)(const void *) = getepoch;
static uint16_t hypertrace_priv_getns(const void *h) { CHECK(h != NULL); return 1; }
typedef int dtrace_icookie_t;
typedef struct { int unused; } hypertrace_args_t;
static int interrupts = 1, fired;
static dtrace_icookie_t dtrace_interrupt_disable(void) { int old = interrupts; interrupts = 0; return old; }
static void dtrace_interrupt_enable(int old) { interrupts = old; }
static struct { const void *t_hypertrace_vmhdl; } thread;
#define curthread (&thread)
static void dtrace_probe(int id, uintptr_t args, int a, int b, int c, int d) {
    CHECK(id == 1 && args && !interrupts && thread.t_hypertrace_vmhdl != NULL);
    CHECK(a == 0 && b == 0 && c == 0 && d == 0); fired++;
}
static dtrace_id_t dtrace_vprobe_create(uint16_t vmid, dtrace_id_t id,
    const char *prov, const char *mod, const char *func, const char *name,
    int *errorp)
{
    CHECK(vmid == 1 && id < 16 && prov && mod && func && name);
    if (core[id] || id == rejected_id) {
        *errorp = EEXIST; return DTRACE_IDNONE;
    }
    if (id == resource_id) {
        *errorp = ENOSPC; return DTRACE_IDNONE;
    }
    *errorp = 0; core[id] = true; return id;
}
static void dtrace_vprobe_discard(uint16_t vmid, hypertrace_id_t id)
{
    CHECK(vmid == 1 && id > 0 && id < 16 && core[id]); core[id] = false;
}
/* A failed ASSERT is a debug-kernel panic: trap it where a case expects one. */
#define INVARIANTS
static jmp_buf assert_trap;
static int assert_armed;
static const char *assert_text;
#undef ASSERT
#define ASSERT(x) do { if (!(x)) { CHECK(assert_armed); \
    assert_text = #x; longjmp(assert_trap, 1); } } while (0)
/* Only the named assertion will do: say which one tripped instead. */
#define ASSERT_TRIPS(stmt, text) do { assert_armed = 1; \
    if (setjmp(assert_trap) == 0) { stmt; CHECK(!"ASSERT held"); } \
    if (strcmp(assert_text, text) != 0) { fprintf(stderr, \
    "tripped ASSERT(%s), not ASSERT(%s)\n", assert_text, text); abort(); } \
    assert_armed = 0; } while (0)
#include "batch.inc"
static void empty(void)
{
    size_t count;
    CHECK(map_count(hypertrace_map, 0, &count) == 0 && count == 0);
    CHECK(hypertrace_map->table_bytes == 0 &&
        hypertrace_map->nprobes[1] == 0);
    for (unsigned i = 0; i < 16; i++) CHECK(!core[i]);
    for (unsigned i = 0; i < HASH_SIZE; i++) CHECK(provtab[i] == NULL);
}
int main(void)
{
    CHECK(map_main() == 0); memset(provtab, 0, sizeof(provtab));
    hypertrace_map = map_init();
    uint16_t first, second; uint64_t first_epoch, second_epoch;
    CHECK(hypertrace_vm_alloc(&first, &first_epoch) == 0 && first == 1 && first_epoch != 0);
    CHECK(hypertrace_vm_alloc(&second, &second_epoch) == 0 && second == 2 && second_epoch != 0);
    CHECK(packet_publishes == 2 && packet_vm_epochs[first] == first_epoch &&
        packet_vm_epochs[second] == second_epoch);
    CHECK(dtrace_vm_epochs[first] == first_epoch &&
        dtrace_vm_epochs[second] == second_epoch);
    CHECK(hypertrace_vm_release(first, first_epoch ^ 1) == ESTALE);
    CHECK(packet_revokes == 0 && packet_vm_epochs[first] == first_epoch);
    dtrace_vm_epochs[first] = 0;
    suspended_epoch[first] = first_epoch;
    hypertrace_vm_gate_tokens[first][0] = 0xa1;
    CHECK(hypertrace_vm_release(first, first_epoch) == 0);
    CHECK(suspended_epoch[first] == 0 && hypertrace_vm_gate_tokens[first][0] == 0);
    CHECK(hypertrace_vm_release(second, second_epoch) == 0);
    CHECK(packet_revokes == 2 && packet_vm_epochs[first] == 0 &&
        packet_vm_epochs[second] == 0);
    CHECK(dtrace_drains == 2 && dtrace_vm_epochs[first] == 0 &&
        dtrace_vm_epochs[second] == 0);
    hypertrace_vm_epochs[1] = 42;
    dtrace_vm_epochs[1] = 42;

    dtrace_probedesc_t batch[3] = {0};
    for (unsigned i = 0; i < 3; i++) {
        batch[i].dtpd_id = i + 1;
        strlcpy(batch[i].dtpd_provider, "provider", sizeof(batch[i].dtpd_provider));
        strlcpy(batch[i].dtpd_name, "probe", sizeof(batch[i].dtpd_name));
    }
    suspended_epoch[1] = 42;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 1) == EBUSY); empty();
    suspended_epoch[1] = 0;
    CHECK(hypertrace_priv_create_probes(1, 0, batch, 1) == ESTALE);
    CHECK(hypertrace_priv_create_probes(1, 43, batch, 1) == ESTALE); empty();
    /* Differing bytes after the terminating NUL do not create new providers. */
    memset(batch[1].dtpd_provider + 9, 0xa5, sizeof(batch[1].dtpd_provider) - 9);
    batch[2].dtpd_id = 1;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 3) == EEXIST); empty();
    batch[2].dtpd_id = 3; rejected_id = 3;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 3) == EEXIST); empty();
    rejected_id = 0;
    resource_id = 3;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 3) == ENOSPC); empty();
    resource_id = 0;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 1) == 0);
    hypertrace_args_t args = {0};
    thread.t_hypertrace_vmhdl = &batch;
    CHECK(hypertrace_probe(&args, 1, &args) == 0);
    CHECK(fired == 1 && interrupts == 1 && thread.t_hypertrace_vmhdl == &batch);
    hypertrace_vm_epochs[1] = live_epoch = 43; /* A replacement VM reuses numeric ID 1. */
    CHECK(hypertrace_probe(&args, 1, &args) == ESTALE);
    CHECK(fired == 1 && interrupts == 1 && thread.t_hypertrace_vmhdl == &batch);
    CHECK(hypertrace_priv_create_probes(1, 42, batch + 1, 1) == ESTALE);
    /* An ID is reallocated only once its probes are gone, as checked below. */
    ASSERT_TRIPS(hypertrace_priv_create_probes(1, 43, batch + 1, 1),
        "probe == NULL || probe->htpb_epoch == epoch");
    CHECK(core[1] && !core[2]);
    hypertrace_vm_epochs[1] = live_epoch = 42;
    CHECK(hypertrace_vm_release(1, 42) == 0);
    CHECK(hypertrace_vm_alloc(&second, &second_epoch) == 0 && second == 2);
    CHECK(hypertrace_vm_release(second, second_epoch) == 0);
    hypertrace_vm_epochs[1] = 42;

    batch[2].dtpd_id = 1;
    CHECK(hypertrace_priv_create_probes(1, 42, batch + 1, 2) == EEXIST);
    CHECK(core[1] && !core[2] && map_get(hypertrace_map, 1, 1)->htpb_enabled);
    CHECK(hypertrace_priv_disable(1, 1) == 0);
    CHECK(hypertrace_probe(&args, 1, &args) == EACCES);
    CHECK(hypertrace_priv_rmprobe(1, 1) == 0); dtrace_vprobe_discard(1, 1); empty();
    batch[2].dtpd_id = 3;
    CHECK(hypertrace_priv_create_probes(1, 42, batch, 3) == 0);
    CHECK(map_get(hypertrace_map, 1, 1)->htpb_provider == map_get(hypertrace_map, 1, 2)->htpb_provider);
    for (unsigned i = 1; i <= 3; i++) {
        CHECK(hypertrace_priv_disable(1, i) == 0);
        CHECK(hypertrace_priv_rmprobe(1, i) == 0); dtrace_vprobe_discard(1, i);
    }
    empty();
    for (unsigned i = 1; i < HYPERTRACE_MAX_VMS; i++) hypertrace_vm_epochs[i] = 1;
    CHECK(hypertrace_vm_alloc(&first, &first_epoch) == ENOSPC && config_depth == 0);
    map_teardown(hypertrace_map);
    puts("PASS: actual batch rollback, preserved preexisting probes and canonical provider names");
}
