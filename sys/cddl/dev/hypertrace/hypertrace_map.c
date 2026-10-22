/*-
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include "hypertrace.h"

#define MAP_HOSTID     0
#define MAP_BUCKETSIZE 4096
#ifndef HYPERTRACE_MAP_TABLE_LIMIT
#define HYPERTRACE_MAP_TABLE_LIMIT (64 * 1024 * 1024)
#endif

static void
syncfn(void *arg __unused)
{
}

static void
sync(void)
{

	smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier, syncfn,
	    smp_no_rendezvous_barrier, NULL);
}

hypertrace_map_t *
map_init(void)
{
	hypertrace_map_t *map;

	map = kmem_zalloc(sizeof(hypertrace_map_t), KM_SLEEP);
	mutex_init(&map->mtx, "hypertrace map state", MUTEX_DEFAULT, NULL);
	return (map);
}

void
map_teardown(hypertrace_map_t *map)
{
	size_t i, j, capacity;
	hypertrace_probe_t **probes, *probe;

	if (map == NULL)
		return;

	/*
	 * Go over all of the buckets in a map and free each probe, followed by
	 * freeing the probe table itself. At the end, free the map.
	 */
	mutex_enter(&map->mtx);
	for (i = 0; i < HYPERTRACE_MAX_VMS; i++) {
		if (map->probes[i] == NULL)
			continue;

		probes = map->probes[i];
		capacity = map->nprobes[i];
		map->probes[i] = NULL;
		map->nprobes[i] = 0;
		map->active[i] = 0;
		sync();
		for (j = 0; j < capacity; j++) {
			probe = probes[j];
			if (probe != NULL)
				kmem_free(probe, sizeof(*probe));
		}
		kmem_free(probes, capacity * sizeof(*probes));
	}

	mutex_exit(&map->mtx);
	mutex_destroy(&map->mtx);
	kmem_free(map, sizeof(hypertrace_map_t));
}

int
map_insert(hypertrace_map_t *map, hypertrace_probe_t *probe)
{
	size_t nprobes;
	hypertrace_probe_t **new_probes;
	dtrace_id_t id;
	uint16_t vmid;

	if (map == NULL || probe == NULL ||
	    probe->htpb_vmid >= HYPERTRACE_MAX_VMS || probe->htpb_id == 0 ||
	    probe->htpb_id > DTRACE_SENSIBLE_PROBELIMIT)
		return (EINVAL);
	vmid = probe->htpb_vmid;
	id = probe->htpb_id;
	mutex_enter(&map->mtx);
	nprobes = map->nprobes[vmid];
	if (id > nprobes) {
		size_t nsize;
		size_t osize;

		osize = nprobes * sizeof(hypertrace_probe_t *);
		nsize = dtrace_nextpow2(id) * sizeof(hypertrace_probe_t *);
		if (nsize - osize >
		    HYPERTRACE_MAP_TABLE_LIMIT - map->table_bytes) {
			mutex_exit(&map->mtx);
			return (ENOSPC);
		}

		ASSERT((nsize / sizeof(hypertrace_probe_t *)) > id - 1);
		new_probes = kmem_zalloc(nsize, KM_SLEEP);
		map->table_bytes += nsize - osize;

		if (map->probes[vmid] == NULL) {
			ASSERT(osize == 0);
			map->probes[vmid] = new_probes;
			dtrace_membar_producer();
			map->nprobes[vmid] = nsize / sizeof(hypertrace_probe_t *);
		} else {
			hypertrace_probe_t **oprobes = map->probes[vmid];

			memcpy(new_probes, oprobes, osize);
			map->probes[vmid] = new_probes;
			sync();

			kmem_free(oprobes, osize);
			dtrace_membar_producer();
			map->nprobes[vmid] = nsize / sizeof(hypertrace_probe_t *);
		}

		ASSERT(id - 1 < map->nprobes[vmid]);
	}

	if (map->probes[vmid][id - 1] != NULL) {
		mutex_exit(&map->mtx);
		return (EEXIST);
	}
	dtrace_membar_producer();
	map->probes[vmid][id - 1] = probe;
	map->active[vmid]++;
	mutex_exit(&map->mtx);
	return (0);
}

/*
 * Safe getter for an element.
 */
hypertrace_probe_t *
map_get(hypertrace_map_t *map, uint16_t vmid, dtrace_id_t id)
{
	hypertrace_probe_t **probes;
	size_t capacity;

	if (map == NULL || vmid >= HYPERTRACE_MAX_VMS || id == 0)
		return (NULL);
	capacity = map->nprobes[vmid];
	if (id > capacity)
		return (NULL);
	dtrace_membar_consumer();
	probes = map->probes[vmid];
	return (probes == NULL ? NULL : probes[id - 1]);
}

void
map_rm(hypertrace_map_t *map, hypertrace_probe_t *probe)
{
	hypertrace_probe_t **probes = NULL;
	size_t size = 0;
	uint16_t vmid;

	if (map == NULL || probe == NULL ||
	    probe->htpb_vmid >= HYPERTRACE_MAX_VMS || probe->htpb_id == 0)
		return;
	vmid = probe->htpb_vmid;
	mutex_enter(&map->mtx);
	if (map->probes[vmid] != NULL &&
	    probe->htpb_id <= map->nprobes[vmid] &&
	    map->probes[vmid][probe->htpb_id - 1] == probe) {
		map->probes[vmid][probe->htpb_id - 1] = NULL;
		ASSERT(map->active[vmid] > 0);
		if (--map->active[vmid] == 0) {
			probes = map->probes[vmid];
			size = map->nprobes[vmid] * sizeof(*probes);
			map->probes[vmid] = NULL;
			dtrace_membar_producer();
			map->nprobes[vmid] = 0;
			ASSERT(map->table_bytes >= size);
			map->table_bytes -= size;
		}
	}
	/* Probe readers run with interrupts disabled, as in DTrace itself. */
	sync();
	if (probes != NULL)
		kmem_free(probes, size);
	mutex_exit(&map->mtx);
}

int
map_count(hypertrace_map_t *map, uint16_t vmid, size_t *count)
{
	size_t first, last, i, total = 0;

	if (map == NULL || count == NULL || vmid >= HYPERTRACE_MAX_VMS)
		return (EINVAL);
	first = vmid == MAP_HOSTID ? 0 : vmid;
	last = vmid == MAP_HOSTID ? HYPERTRACE_MAX_VMS : vmid + 1;
	mutex_enter(&map->mtx);
	for (i = first; i < last; i++)
		total += map->active[i];
	mutex_exit(&map->mtx);
	*count = total;
	return (0);
}
