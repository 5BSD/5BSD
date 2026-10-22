/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <dev/dttransport/dttransport.h>
typedef int dtt_send_t(void *, dtt_entry_t *);
typedef int dtt_identity_t(void *, struct dtt_vm_identity *);
typedef int dtt_rekey_commit_t(void *, const struct dtt_vm_identity *);
typedef int dtt_cleanup_query_t(void *, struct dtt_cleanup_state *);
struct sx { pthread_rwlock_t lock; };
#define SX_SYSINIT(name, lock, description)
static void sx_xlock(struct sx *s) { assert(pthread_rwlock_wrlock(&s->lock) == 0); }
static void sx_xunlock(struct sx *s) { assert(pthread_rwlock_unlock(&s->lock) == 0); }
static void sx_slock(struct sx *s) { assert(pthread_rwlock_rdlock(&s->lock) == 0); }
static void sx_sunlock(struct sx *s) { assert(pthread_rwlock_unlock(&s->lock) == 0); }
#include "registration.inc"
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static bool entered, release_send;
static bool hold_identity, identity_entered, release_identity;
static bool hold_commit, commit_entered, release_commit;
static atomic_bool retiring, retired;
static int device, other;
static int callback(void *arg, dtt_entry_t *entry) {
    assert(arg == &device && entry->event_kind == DTT_ELF);
    pthread_mutex_lock(&mutex); entered = true; pthread_cond_broadcast(&cond);
    while (!release_send) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex); return EIO;
}
static int identity_callback(void *arg, struct dtt_vm_identity *identity) {
    assert(arg == &device);
    pthread_mutex_lock(&mutex);
    if (hold_identity) {
        identity_entered = true;
        pthread_cond_broadcast(&cond);
        while (!release_identity) pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);
    identity->vmid = 7;
    identity->epoch = 11;
    return 0;
}
static int commit_callback(void *arg, const struct dtt_vm_identity *identity) {
    assert(arg == &device && identity->old_vmid == 7 &&
        identity->vmid == 8);
    pthread_mutex_lock(&mutex);
    if (hold_commit) {
        commit_entered = true;
        pthread_cond_broadcast(&cond);
        while (!release_commit) pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int cleanup_callback(void *arg, struct dtt_cleanup_state *state) {
    assert(arg == &device);
    state->vmid = 7;
    state->epoch = 11;
    state->delivery_id = 123;
    state->flags = DTT_CLEANUP_STATE_PENDING;
    return 0;
}
static void *commit_writer(void *arg) {
    assert(arg == &device);
    struct dtt_vm_identity identity = {.old_vmid = 7, .vmid = 8};
    assert(dtt_transport_rekey_commit(&identity) == 0);
    return NULL;
}
static void *identity_reader(void *arg) {
    assert(arg == &device);
    struct dtt_vm_identity identity = {0};
    assert(dtt_transport_identity(&identity) == 0);
    assert(identity.vmid == 7 && identity.epoch == 11);
    return NULL;
}
static void *sender(void *arg) {
    assert(arg == &device); dtt_entry_t entry = { .event_kind = DTT_ELF };
    assert(dtt_transport_send(&entry) == EIO); return NULL;
}
static void *remover(void *arg) {
    atomic_store(&retiring, true); dtt_unregister_transport(arg);
    atomic_store(&retired, true); return NULL;
}
static void *late_registrar(void *arg) {
    int error = dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, arg);
    assert(error == ENXIO);
    return NULL;
}
int main(void) {
    alarm(10); assert(pthread_rwlock_init(&dtt_transport_lock.lock, NULL) == 0);
    dtt_entry_t entry = {0};
    struct dtt_vm_identity identity = {0};
    struct dtt_cleanup_state cleanup = {0};
    assert(dtt_transport_send(&entry) == ENXIO);
    assert(dtt_transport_identity(&identity) == ENXIO);
    assert(dtt_transport_rekey_commit(&identity) == ENXIO);
    assert(dtt_transport_cleanup_query(&cleanup) == ENXIO);
    assert(dtt_register_transport(NULL, identity_callback,
        commit_callback, cleanup_callback, &device) == EINVAL);
    assert(dtt_register_transport(callback, NULL,
        commit_callback, cleanup_callback, &device) == EINVAL);
    assert(dtt_register_transport(callback, identity_callback,
        NULL, cleanup_callback, &device) == EINVAL);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, NULL, &device) == EINVAL);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, NULL) == EINVAL);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &device) == 0);
    assert(dtt_transport_identity(&identity) == 0);
    assert(identity.vmid == 7 && identity.epoch == 11);
    assert(dtt_transport_cleanup_query(&cleanup) == 0 &&
        cleanup.delivery_id == 123 && cleanup.vmid == 7 &&
        cleanup.epoch == 11 &&
        cleanup.flags == DTT_CLEANUP_STATE_PENDING);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &other) == EBUSY);
    dtt_unregister_transport(&other); assert(dtt_send_arg == &device);
    pthread_t send, remove; assert(pthread_create(&send, NULL, sender, &device) == 0);
    pthread_mutex_lock(&mutex);
    while (!entered) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    assert(pthread_create(&remove, NULL, remover, &device) == 0);
    while (!atomic_load(&retiring)) usleep(1000);
    assert(!atomic_load(&retired));
    pthread_mutex_lock(&mutex); release_send = true; pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);
    assert(pthread_join(send, NULL) == 0 && pthread_join(remove, NULL) == 0);
    assert(atomic_load(&retired) && dtt_transport_send(&entry) == ENXIO);
    assert(dtt_transport_identity(&identity) == ENXIO);
    assert(dtt_transport_cleanup_query(&cleanup) == ENXIO);
    atomic_store(&retiring, false);
    atomic_store(&retired, false);
    hold_identity = true;
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &device) == 0);
    assert(pthread_create(&send, NULL, identity_reader, &device) == 0);
    pthread_mutex_lock(&mutex);
    while (!identity_entered) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    assert(pthread_create(&remove, NULL, remover, &device) == 0);
    while (!atomic_load(&retiring)) usleep(1000);
    assert(!atomic_load(&retired));
    pthread_mutex_lock(&mutex);
    release_identity = true;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);
    assert(pthread_join(send, NULL) == 0 && pthread_join(remove, NULL) == 0);
    assert(atomic_load(&retired) && dtt_transport_identity(&identity) == ENXIO);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &other) == 0);
    dtt_unregister_transport(&other);
    hold_commit = true;
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &device) == 0);
    assert(pthread_create(&send, NULL, commit_writer, &device) == 0);
    pthread_mutex_lock(&mutex);
    while (!commit_entered) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    atomic_store(&retiring, false);
    atomic_store(&retired, false);
    assert(pthread_create(&remove, NULL, remover, &device) == 0);
    while (!atomic_load(&retiring)) usleep(1000);
    assert(!atomic_load(&retired));
    pthread_mutex_lock(&mutex); release_commit = true;
    pthread_cond_broadcast(&cond); pthread_mutex_unlock(&mutex);
    assert(pthread_join(send, NULL) == 0 && pthread_join(remove, NULL) == 0);
    assert(atomic_load(&retired) &&
        dtt_transport_rekey_commit(&identity) == ENXIO);
    sx_xlock(&dtt_transport_lock);
    assert(pthread_create(&send, NULL, late_registrar, &device) == 0);
    dtt_transport_dying = true;
    sx_xunlock(&dtt_transport_lock);
    assert(pthread_join(send, NULL) == 0);
    assert(dtt_register_transport(callback, identity_callback,
        commit_callback, cleanup_callback, &device) == ENXIO);
    assert(dtt_transport_send(&entry) == ENXIO);
    assert(dtt_transport_identity(&identity) == ENXIO);
    assert(dtt_transport_rekey_commit(&identity) == ENXIO);
    assert(dtt_transport_cleanup_query(&cleanup) == ENXIO);
    pthread_rwlock_destroy(&dtt_transport_lock.lock);
    puts("PASS: transport registration, identity, send and rekey callback retirement");
}
