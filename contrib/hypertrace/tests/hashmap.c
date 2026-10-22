/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int fail_malloc;
void *__real_malloc(size_t);
void *
__wrap_malloc(size_t size)
{
	if (fail_malloc) {
		fail_malloc = 0;
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

#include "dt_hashmap.c"

int
main(void)
{
	dt_hashmap_t *map;
	uint32_t keys[4] = { 0 }, candidate;
	uint32_t values[4] = { 11, 22, 33, 44 };
	size_t found = 0, bucket;

	assert(dt_hashmap_create(0) == NULL && errno == EINVAL);
	map = dt_hashmap_create(4);
	assert(map != NULL);
	bucket = _hash(&keys[0], sizeof(keys[0])) % map->dthm_size;
	for (candidate = 0; found < 4; candidate++) {
		if (_hash(&candidate, sizeof(candidate)) % map->dthm_size ==
		    bucket)
			keys[found++] = candidate;
	}
	fail_malloc = 1;
	assert(dt_hashmap_insert(map, &keys[0], sizeof(keys[0]), &values[0],
	    DTH_MANAGED) == ENOMEM);
	assert(map->dthm_nitems == 0 &&
	    dt_hashmap_lookup(map, &keys[0], sizeof(keys[0])) == NULL);
	for (size_t i = 0; i < 4; i++)
		assert(dt_hashmap_insert(map, &keys[i], sizeof(keys[i]),
		    &values[i], DTH_MANAGED) == 0);
	assert(map->dthm_nitems == 4);
	for (size_t i = 0; i < 4; i++)
		assert(dt_hashmap_lookup(map, &keys[i], sizeof(keys[i])) ==
		    &values[i]);
	candidate = UINT32_MAX;
	assert(dt_hashmap_lookup(map, &candidate, sizeof(candidate)) == NULL);
	assert(dt_hashmap_insert(map, &candidate, sizeof(candidate),
	    &values[0], DTH_MANAGED) == ENOSPC);
	assert(dt_hashmap_delete(map, &keys[1], sizeof(keys[1])) == &values[1]);
	assert(map->dthm_nitems == 3);
	assert(dt_hashmap_lookup(map, &keys[2], sizeof(keys[2])) == &values[2]);
	assert(dt_hashmap_lookup(map, &keys[3], sizeof(keys[3])) == &values[3]);
	assert(dt_hashmap_insert(map, &keys[1], sizeof(keys[1]),
	    &values[1], DTH_MANAGED) == 0);
	assert(dt_hashmap_lookup(map, &keys[1], sizeof(keys[1])) == &values[1]);
	dt_hashmap_free(map, 1);
	/* Mixed-home wraparound clusters retain every reachable key. */
	map = dt_hashmap_create(7);
	assert(map != NULL);
	uint32_t many_keys[32], many_values[32], random = 0x9e3779b9;
	bool live[32] = { false };
	size_t live_count = 0;
	for (size_t i = 0; i < 32; i++) {
		many_keys[i] = i;
		many_values[i] = i + 100;
	}
	for (size_t step = 0; step < 5000; step++) {
		random ^= random << 13;
		random ^= random >> 17;
		random ^= random << 5;
		size_t item = random % 32;
		if ((random & 0x80) != 0) {
			int error = dt_hashmap_insert(map, &many_keys[item],
			    sizeof(many_keys[item]), &many_values[item], DTH_MANAGED);
			assert(error == (live[item] ? 0 :
			    live_count == 7 ? ENOSPC : 0));
			if (!live[item] && error == 0) {
				live[item] = true;
				live_count++;
			}
		} else {
			assert(dt_hashmap_delete(map, &many_keys[item],
			    sizeof(many_keys[item])) ==
			    (live[item] ? &many_values[item] : NULL));
			if (live[item]) {
				live[item] = false;
				live_count--;
			}
		}
		assert(map->dthm_nitems == live_count);
		for (size_t i = 0; i < 32; i++)
			assert(dt_hashmap_lookup(map, &many_keys[i],
			    sizeof(many_keys[i])) ==
			    (live[i] ? &many_values[i] : NULL));
	}
	dt_hashmap_free(map, 1);
	puts("PASS: bounded full-table lookup, transactional OOM and collision deletion");
	return (0);
}
