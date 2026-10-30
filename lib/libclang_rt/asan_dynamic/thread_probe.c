/* SPDX-License-Identifier: BSD-2-Clause */
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static pthread_key_t key;
static unsigned destroyed;
#ifdef PROBE_TLS
static _Thread_local volatile int tls_value;
#endif
static void cleanup(void *value)
{
    if ((uintptr_t)value != 42) abort();
#ifdef PROBE_TLS
    if (tls_value != 42) abort();
#endif
    ++destroyed;
}
static void *worker(void *argument)
{
    const char *mode = argument;
#ifdef PROBE_TLS
    if (tls_value != 0) abort();
    tls_value = 42;
#endif
    if (pthread_setspecific(key, (void *)(uintptr_t)42) != 0) abort();
    volatile unsigned char *p = malloc(8);
    if (p == NULL) abort();
    if (strcmp(mode, "freed") == 0) {
        free((void *)p);
        return (void *)(uintptr_t)p[0];
    }
    p[atoi(mode)] = 42;
    free((void *)p);
    return NULL;
}
int main(int argc, char **argv)
{
    if (argc != 2 || pthread_key_create(&key, cleanup) != 0) return 2;
#ifdef PROBE_TLS
    tls_value = 99;
#endif
    for (unsigned i = 0; i < 4; ++i) {
        pthread_t thread;
        void *result;
        if (pthread_create(&thread, NULL, worker, argv[1]) != 0 ||
            pthread_join(thread, &result) != 0 || result != NULL ||
            destroyed != i + 1) return 3;
#ifdef PROBE_TLS
        if (tls_value != 99) return 4;
#endif
    }
    return pthread_key_delete(key) != 0;
}
