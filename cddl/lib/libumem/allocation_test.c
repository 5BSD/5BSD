/* SPDX-License-Identifier: BSD-2-Clause */
#include <umem.h>
#include <err.h>
static int constructed, destroyed;
static int construct(void *p, void *arg, int flags) {
    (void)flags; *(int *)p = *(int *)arg; constructed++; return 0;
}
static void destroy(void *p, void *arg) {
    if (*(int *)p != *(int *)arg) errx(1, "callback data");
    destroyed++;
}
int main(void) {
    unsigned char *zero = umem_zalloc(128, UMEM_DEFAULT);
    if (!zero) errx(1, "zero allocation");
    for (unsigned i = 0; i < 128; i++) if (zero[i]) errx(1, "nonzero byte");
    umem_free(zero, 128);
    int value = 42;
    umem_cache_t *cache = umem_cache_create("native-test", sizeof(int), 0,
        construct, destroy, NULL, &value, NULL, 0);
    if (!cache) errx(1, "cache create");
    for (int i = 0; i < 32; i++) {
        int *p = umem_cache_alloc(cache, UMEM_DEFAULT);
        if (!p || *p != value) errx(1, "constructed allocation");
        umem_cache_free(cache, p);
    }
    umem_cache_destroy(cache);
    if (constructed != 32 || destroyed != 32) errx(1, "callback counts");
    return 0;
}
