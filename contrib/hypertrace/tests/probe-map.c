/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); abort(); } } while (0)
#define ASSERT CHECK
#define dtrace_membar_consumer() ((void)0)
#define dtrace_membar_producer() ((void)0)
#define KM_SLEEP 0
#define MUTEX_DEFAULT 0
#define HYPERTRACE_MAX_VMS 1024
#define DTRACE_SENSIBLE_PROBELIMIT (1 << 20)
#define DTRACE_PROVNAMELEN 64
#define HASH_SIZE 4096
#define HASH_MASK (HASH_SIZE - 1)
#define HYPERTRACE_MAX_PROVIDERS_PER_VM 256
#define HYPERTRACE_MAP_TABLE_LIMIT 4096
#define HASHINIT 1
#define sync map_sync
#define all_cpus 0
#define smp_no_rendezvous_barrier NULL
#define smp_rendezvous_cpus(c, a, fn, b, arg) fn(arg)
typedef uint32_t dtrace_id_t;
typedef pthread_mutex_t kmutex_t;
#define mutex_init(m, n, k, a) CHECK(pthread_mutex_init(m, NULL) == 0)
#define mutex_enter(m) CHECK(pthread_mutex_lock(m) == 0)
#define mutex_exit(m) CHECK(pthread_mutex_unlock(m) == 0)
#define mutex_destroy(m) CHECK(pthread_mutex_destroy(m) == 0)
typedef struct hypertrace_vprovider {
	char name[DTRACE_PROVNAMELEN];
	size_t nprobes;
	uint32_t hash_ndx;
	uint32_t vm_refs[HYPERTRACE_MAX_VMS];
} hypertrace_vprovider_t;
typedef struct hypertrace_probe {
	hypertrace_vprovider_t *htpb_provider;
	dtrace_id_t htpb_id;
	uint16_t htpb_vmid;
	uint64_t htpb_epoch;
	int htpb_running, htpb_enabled;
} hypertrace_probe_t;
typedef struct hypertrace_map {
	hypertrace_probe_t **probes[HYPERTRACE_MAX_VMS];
	size_t nprobes[HYPERTRACE_MAX_VMS];
	size_t active[HYPERTRACE_MAX_VMS];
	size_t table_bytes;
	kmutex_t mtx;
} hypertrace_map_t;
static void *kmem_zalloc(size_t n, int flags __unused)
{
	size_t *allocation = calloc(1, n + sizeof(size_t));
	CHECK(allocation != NULL);
	*allocation = n;
	return (allocation + 1);
}
static void kmem_free(void *p, size_t n)
{
	size_t *allocation = (size_t *)p - 1;
	CHECK(*allocation == n);
	free(allocation);
}
static size_t dtrace_nextpow2(size_t n)
{
	size_t value = 1;
	while (value < n) value *= 2;
	return (value);
}
/* Force all provider names to collide to exercise the actual table code. */
static uint32_t murmur3_32_hash(const char *p __unused, size_t n __unused,
    uint32_t seed __unused) { return (1); }
static kmutex_t provmtx = PTHREAD_MUTEX_INITIALIZER;
static hypertrace_vprovider_t *provtab[HASH_SIZE];
#include "map.inc"
#include "provider.inc"
int main(void)
{
	hypertrace_map_t *map = map_init();
	hypertrace_probe_t bad = { .htpb_id = 1, .htpb_vmid = HYPERTRACE_MAX_VMS };
	hypertrace_probe_t *a = kmem_zalloc(sizeof(*a), KM_SLEEP);
	hypertrace_probe_t *b = kmem_zalloc(sizeof(*b), KM_SLEEP);
	size_t count;
	char name[DTRACE_PROVNAMELEN] = { 0 };
	hypertrace_vprovider_t *first, *second;

	a->htpb_id = 1; a->htpb_vmid = 1;
	b->htpb_id = 4; b->htpb_vmid = 1;
	CHECK(map_insert(map, &bad) == EINVAL);
	bad.htpb_vmid = 1; bad.htpb_id = 0;
	CHECK(map_insert(map, &bad) == EINVAL);
	bad.htpb_id = DTRACE_SENSIBLE_PROBELIMIT + 1U;
	CHECK(map_insert(map, &bad) == EINVAL);
	CHECK(map_insert(map, a) == 0 && map_get(map, 1, 1) == a);
	CHECK(map_get(map, 1, 0) == NULL);
	CHECK(map_get(map, HYPERTRACE_MAX_VMS, 1) == NULL);
	CHECK(map_get(map, UINT16_MAX, 1) == NULL);
	CHECK(map_insert(map, b) == 0 && map_get(map, 1, 4) == b);
	CHECK(map_insert(map, b) == EEXIST);
	CHECK(map_get(map, 1, 5) == NULL);
	CHECK(map_count(map, 0, &count) == 0 && count == 2);
	map_rm(map, b);
	CHECK(map_get(map, 1, 4) == NULL);
	CHECK(map_count(map, 1, &count) == 0 && count == 1);
	kmem_free(b, sizeof(*b));
	map_teardown(map); /* Checks the exact table allocation size on free. */
	map = map_init();
	a = kmem_zalloc(sizeof(*a), KM_SLEEP);
	b = kmem_zalloc(sizeof(*b), KM_SLEEP);
	a->htpb_id = 512; a->htpb_vmid = 2;
	b->htpb_id = 1; b->htpb_vmid = 3;
	CHECK(map_insert(map, a) == 0);
	CHECK(map->table_bytes == HYPERTRACE_MAP_TABLE_LIMIT);
	CHECK(map_insert(map, b) == ENOSPC);
	map_rm(map, a);
	CHECK(map->table_bytes == 0 && map->nprobes[2] == 0);
	CHECK(map_insert(map, b) == 0);
	CHECK(map_get(map, 3, 1) == b);
	kmem_free(a, sizeof(*a));
	map_teardown(map);
	strlcpy(name, "first", sizeof(name));
	first = hypertrace_get_vprovider(name);
	strlcpy(name, "second", sizeof(name));
	second = hypertrace_get_vprovider(name);
	CHECK(first != second && first->hash_ndx != second->hash_ndx);
	CHECK(hypertrace_get_vprovider(name) == second);
	provtab[first->hash_ndx] = NULL;
	kmem_free(first, sizeof(*first));
	CHECK(hypertrace_get_vprovider(name) == second); /* Search past a hole. */
	hypertrace_vprovider_t *quota[HYPERTRACE_MAX_PROVIDERS_PER_VM];
	for (unsigned i = 0; i < HYPERTRACE_MAX_PROVIDERS_PER_VM; i++) {
		quota[i] = kmem_zalloc(sizeof(*quota[i]), KM_SLEEP);
		CHECK(hypertrace_provider_reserve(quota[i], 1) == 0);
	}
	CHECK(vm_provider_counts[1] == HYPERTRACE_MAX_PROVIDERS_PER_VM);
	CHECK(hypertrace_provider_reserve(quota[0], 1) == 0);
	CHECK(vm_provider_counts[1] == HYPERTRACE_MAX_PROVIDERS_PER_VM);
	hypertrace_vprovider_t *extra = kmem_zalloc(sizeof(*extra), KM_SLEEP);
	CHECK(hypertrace_provider_reserve(extra, 1) == ENOSPC);
	CHECK(hypertrace_provider_reserve(extra, 2) == 0);
	hypertrace_provider_release(quota[0], 1);
	CHECK(vm_provider_counts[1] == HYPERTRACE_MAX_PROVIDERS_PER_VM);
	hypertrace_provider_release(quota[0], 1);
	CHECK(hypertrace_provider_reserve(extra, 1) == 0);
	for (unsigned i = 1; i < HYPERTRACE_MAX_PROVIDERS_PER_VM; i++) {
		hypertrace_provider_release(quota[i], 1);
		kmem_free(quota[i], sizeof(*quota[i]));
	}
	kmem_free(quota[0], sizeof(*quota[0]));
	hypertrace_provider_release(extra, 1);
	hypertrace_provider_release(extra, 2);
	CHECK(vm_provider_counts[1] == 0 && vm_provider_counts[2] == 0);
	kmem_free(extra, sizeof(*extra));
	for (unsigned i = 0; i < HASH_SIZE - 1; i++) {
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "provider-%u", i);
		CHECK(hypertrace_get_vprovider(name) != NULL);
	}
	memset(name, 0, sizeof(name)); strlcpy(name, "overflow", sizeof(name));
	CHECK(hypertrace_get_vprovider(name) == NULL);
	for (unsigned i = 0; i < HASH_SIZE; i++)
		kmem_free(provtab[i], sizeof(*provtab[i]));
	puts("PASS: VM/probe bounds, duplicate IDs, table budget/reclaim, counts, provider collisions/full table");
	return (0);
}
