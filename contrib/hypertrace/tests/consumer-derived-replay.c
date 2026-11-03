/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dtraced_derived.h>
#include <dtraced_io.h>
#include <dt_list.h>

typedef struct { int marker; } dtrace_prog_t;
typedef char hypertrace_errmsg_t[256];
typedef struct {
    dt_list_t list;
    dtrace_prog_t *gpgp;
    dtraced_derived_parent_t derived_parent;
    uint8_t ingress_digest[SHA256_DIGEST_LENGTH];
    int derived_parent_known;
    int ingress_digest_known;
    int derived_failures;
    int64_t derived_retry_at;
} dt_pgplist_t;
typedef struct { uint8_t rx_session[16]; } dtd_arg_t;

static void *g_dtp;
static _Atomic int g_intr, g_stop;
static pthread_mutex_t g_pgplistmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pgpcond;
static dt_list_t g_pgplist, g_derived_replaylist;
static char created_path[80];
static int creates, sends, fail_create, fail_send;

static int
dtrace_elf_create(void *handle, dtrace_prog_t *program, int encoding,
    int fd, const char *path, hypertrace_errmsg_t errmsg)
{
    (void)handle;
    (void)errmsg;
    assert(program->marker == 7 && encoding == ELFDATA2LSB);
    assert(strlen(path) < sizeof(created_path));
    strcpy(created_path, path);
    creates++;
    if (fail_create)
        return (-1);
    assert(write(fd, "ELF", 3) == 3);
    return (0);
}

static int
dtrace_send_elf_derived(dtrace_prog_t *program, int fd, int socket,
    const dtraced_derived_parent_t *parent)
{
    char contents[3];
    assert(program->marker == 7 && socket == 13);
    assert(read(fd, contents, sizeof(contents)) == sizeof(contents));
    assert(memcmp(contents, "ELF", sizeof(contents)) == 0);
    assert(parent->delivery_id == 99 && parent->vmid == 7 &&
        parent->epoch == 42 && parent->program_id[0] == 0xaa &&
        parent->source_id[0] == 0xbb);
    sends++;
    if (fail_send) {
        errno = EPIPE;
        return (-1);
    }
    return (0);
}

/* dtrace.c helpers used by the extracted replay code. */
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
static void dtp_lock(void) { }
static void dtp_unlock(void) { }
static int
tmp_mkstemp(char *path, size_t size, const char *name)
{
    snprintf(path, size, "/tmp/%s.XXXXXXXXXXXX", name);
    return (mkstemp(path));
}
static int tmp_unlink(const char *path) { return (unlink(path)); }
/* The listener never sleeps or ends the session over one delivery. */
static int __unused
test_usleep(useconds_t delay)
{
    (void)delay;
    abort();
}
#define usleep test_usleep
static void __unused
fatal(const char *fmt, ...)
{
    (void)fmt;
    abort();
}

#include "consumer-derived-replay.inc"

int
main(void)
{
    dtrace_prog_t guest = { .marker = 7 };
    dt_pgplist_t entry = { .gpgp = &guest, .derived_parent_known = 1,
        .ingress_digest_known = 1 };
    dtd_arg_t connection = { .rx_session = { 0x76 } };
    dtraced_hdr_t header = { 0 };
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t changed[SHA256_DIGEST_LENGTH];
    dtraced_derived_parent_t *parent = &entry.derived_parent;
    parent->consumer_session[0] = 0x76;
    parent->delivery_id = header.elf.delivery_id = 99;
    parent->vmid = header.elf.vmid = 7;
    parent->epoch = header.elf.epoch = 42;
    parent->program_id[0] = header.elf.program_id[0] = 0xaa;
    parent->source_id[0] = header.elf.source_id[0] = 0xbb;
    assert(SHA256((const unsigned char *)"frame-one", 9, digest) != NULL);
    assert(SHA256((const unsigned char *)"frame-two", 9, changed) != NULL);
    memcpy(entry.ingress_digest, digest, sizeof(digest));

    dt_list_append(&g_pgplist, &entry);
    assert(find_identified_derived(&connection, &header) == &entry);
    dt_list_delete(&g_pgplist, &entry);
    assert(find_identified_derived(&connection, &header) == NULL);
    dt_list_append(&g_derived_replaylist, &entry);
    assert(find_identified_derived(&connection, &header) == &entry);
    assert(identified_derived_parent_matches(&entry, &connection, &header));
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == 1);
    assert(creates == 1 && sends == 1 && access(created_path, F_OK) == -1 &&
        errno == ENOENT);
    assert(reemit_identified_derived(&entry, &connection, &header,
        changed, 13) == -1 && errno == EPROTO);
    assert(creates == 1 && sends == 1);
    entry.ingress_digest_known = 0;
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == -1 && errno == EPROTO);
    assert(creates == 1 && sends == 1);
    entry.ingress_digest_known = 1;
    header.elf.delivery_id++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == 0);
    header.elf.delivery_id--;
    connection.rx_session[0]++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == 0);
    connection.rx_session[0]--;
    header.elf.source_id[0]++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == 0);
    header.elf.source_id[0]--;
    header.elf.program_id[0]++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    header.elf.program_id[0]--;
    header.elf.vmid++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    header.elf.vmid--;
    header.elf.epoch++;
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    header.elf.epoch--;
    entry.derived_parent_known = 0;
    assert(find_identified_derived(&connection, &header) == NULL);
    assert(!identified_derived_parent_matches(&entry, &connection, &header));
    entry.derived_parent_known = 1;
    assert(creates == 1 && sends == 1);
    fail_send = 1;
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == -1 &&
        errno == EPIPE);
    assert(access(created_path, F_OK) == -1 && errno == ENOENT);
    fail_send = 0;
    fail_create = 1;
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == -1 &&
        errno == EIO);
    assert(access(created_path, F_OK) == -1 && errno == ENOENT);
    /* A persistent refusal backs off per delivery and gives that delivery
     * up; it neither spins, nor sleeps the listener, nor ends the session. */
    assert(dtraced_connection_lost(EPIPE) && !dtraced_connection_lost(EPROTO));
    pthread_condattr_t attr;
    assert(pthread_condattr_init(&attr) == 0 &&
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0 &&
        pthread_cond_init(&g_pgpcond, &attr) == 0);
    dt_pgplist_t other = entry;
    other.derived_parent.delivery_id = 100;
    static const int64_t backoff[] = { 250, 500, 1000, 2000, 4000 };
    for (int n = 0; n < 5; n++) {
        /* Failures of different deliveries do not add up. */
        int64_t before = dtraced_io_milliseconds();
        assert(derived_send_failed(&entry, EPROTO) == 0);
        assert(derived_send_failed(&other, EPROTO) == 0);
        int64_t after = dtraced_io_milliseconds();
        assert(entry.derived_retry_at >= before + backoff[n] &&
            entry.derived_retry_at <= after + backoff[n]);
    }
    assert(entry.derived_failures == 5 && other.derived_failures == 5 &&
        entry.derived_parent_known && other.derived_parent_known);
    /* The replay of a failed delivery waits out its own deadline, with
     * g_pgplistmtx released while it waits. */
    other.derived_retry_at = dtraced_io_milliseconds() - 1;
    assert(pthread_mutex_lock(&g_pgplistmtx) == 0);
    assert(derived_send_wait(&other) == 0);
    entry.derived_retry_at = dtraced_io_milliseconds() + 200;
    int64_t started = dtraced_io_milliseconds();
    int waits = 0;
    while (derived_send_wait(&entry))
        waits++;
    assert(waits >= 1 && dtraced_io_milliseconds() >= entry.derived_retry_at &&
        dtraced_io_milliseconds() - started < 2000);
    atomic_store(&g_stop, 1);
    entry.derived_retry_at = dtraced_io_milliseconds() + 60000;
    assert(derived_send_wait(&entry) == 0);
    atomic_store(&g_stop, 0);
    assert(pthread_mutex_unlock(&g_pgplistmtx) == 0);
    /* The sixth failure gives this delivery up: a replay no longer
     * re-sends it, and the other delivery keeps its own budget. */
    assert(derived_send_failed(&entry, EPROTO) == 1);
    assert(!entry.derived_parent_known && find_identified_derived(&connection,
        &header) == NULL);
    assert(reemit_identified_derived(&entry, &connection, &header,
        digest, 13) == 0);
    assert(other.derived_parent_known && other.derived_failures == 5);
    puts("PASS: active and completed parent replay exact ELF; distinct uploads and failures do not ACK success; a persistent derived refusal backs off per delivery and gives that delivery up without sleeping the listener or ending the session");
    return (0);
}
