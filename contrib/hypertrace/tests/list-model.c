/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "dt_list.h"
struct item { dt_list_t link; uint32_t key; };
int main(void) {
    dt_list_t list = {0};
    struct item items[64] = {0};
    dt_list_prepend(&list, &items[0]);
    assert(list.dl_next == &items[0].link && list.dl_prev == &items[0].link);
    dt_list_delete(&list, &items[0]);
    assert(list.dl_next == NULL && list.dl_prev == NULL);
    unsigned model[64], count = 0;
    uint32_t random = 0x5b5d2029;
    for (unsigned i = 0; i < 64; ++i) items[i].key = i + 1;
    for (unsigned step = 0; step < 10000; ++step) {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        unsigned id = random % 64, pos = 0;
        while (pos < count && model[pos] != id) ++pos;
        if (pos < count) {
            dt_list_delete(&list, &items[id]);
            memmove(model + pos, model + pos + 1, (count - pos - 1)*sizeof(*model));
            --count;
        } else {
            unsigned operation = (random >> 8) % 4;
            if (operation == 0) { pos = 0; dt_list_prepend(&list, &items[id]); }
            else if (operation == 1) { pos = count; dt_list_append(&list, &items[id]); }
            else if (operation == 2 || count == 0) {
                pos = count; dt_list_insert(&list, NULL, &items[id]);
            } else {
                pos = (random >> 16) % count + 1;
                dt_list_insert(&list, &items[model[pos - 1]], &items[id]);
            }
            memmove(model + pos + 1, model + pos, (count - pos)*sizeof(*model));
            model[pos] = id; ++count;
        }
        dt_list_t *next = list.dl_next, *prev = NULL;
        for (unsigned i = 0; i < count; ++i) {
            assert(next == &items[model[i]].link && next->dl_prev == prev);
            prev = next; next = next->dl_next;
        }
        assert(next == NULL && list.dl_prev == prev);
        next = list.dl_prev; prev = NULL;
        for (unsigned i = count; i > 0; --i) {
            assert(next == &items[model[i-1]].link && next->dl_next == prev);
            prev = next; next = next->dl_prev;
        }
        assert(next == NULL && list.dl_next == prev);
        for (unsigned i = 0; i < 64; ++i) {
            unsigned found = 0;
            while (found < count && model[found] != i) ++found;
            assert(dt_in_list(&list, &items[i].key, sizeof(items[i].key)) ==
                (found < count ? &items[i] : NULL));
        }
    }
    while (count) dt_list_delete(&list, &items[model[--count]]);
    assert(list.dl_next == NULL && list.dl_prev == NULL);
    puts("PASS: 10000 modeled list operations, bidirectional links and membership");
}
