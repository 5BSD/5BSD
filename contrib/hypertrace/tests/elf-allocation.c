/* SPDX-License-Identifier: BSD-2-Clause */
/* Preload only into the offline regression process. */
#include <assert.h>
#include <errno.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
static void *tracked[4096];
static int armed, remaining, attempts, live_count;
static void (*real_free)(void *);
void free(void *p) {
    if (real_free == NULL) {
        real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
        assert(real_free != NULL);
    }
    if (p && live_count) for (size_t i = 0; i < 4096; i++)
        if (tracked[i] == p) { tracked[i] = NULL; live_count--; break; }
    real_free(p);
}
void elf_test_arm(int fail) {
    for (size_t i = 0; i < 4096; i++) assert(tracked[i] == NULL);
    remaining = fail; attempts = 0; armed = 1;
}
int elf_test_attempts(void) { return attempts; }
int elf_test_disarm(void) {
    int live = 0; armed = 0;
    for (size_t i = 0; i < 4096; i++) if (tracked[i]) live++;
    return live;
}
void *dt_alloc(void *handle, size_t size) {
    (void)handle;
    if (armed) {
        attempts++;
        if (remaining == 0) { errno = ENOMEM; return NULL; }
        if (remaining > 0) remaining--;
    }
    void *p = malloc(size);
    if (p && armed) {
        for (size_t i = 0; i < 4096; i++) if (!tracked[i]) { tracked[i] = p; live_count++; return p; }
        abort();
    }
    return p;
}
void *dt_zalloc(void *handle, size_t size) {
    void *p = dt_alloc(handle, size); if (p) memset(p, 0, size); return p;
}
void dt_free(void *handle, void *p) {
    (void)handle;
    free(p);
}
