/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dtraced_derived.h>
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
} dt_pgplist_t;
typedef struct { uint8_t rx_session[16]; } dtd_arg_t;

static void *g_dtp;
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
static useconds_t slept[8];
static int sleeps, failures;	/* static: read after longjmp() */
static char fatal_message[160];
static jmp_buf fatal_return;
static int
test_usleep(useconds_t delay)
{
    assert(sleeps < 8);
    slept[sleeps++] = delay;
    return (0);
}
#define usleep test_usleep
static void
fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(fatal_message, sizeof(fatal_message), fmt, ap);
    va_end(ap);
    longjmp(fatal_return, 1);
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
    /* A persistent refusal backs off and ends; it does not spin. */
    assert(dtraced_connection_lost(EPIPE) && !dtraced_connection_lost(EPROTO));
    if (setjmp(fatal_return) == 0) {
        for (;;)
            derived_send_failed(&failures, EPROTO);
    }
    assert(failures == 6 && sleeps == 5);
    assert(slept[0] == 250000 && slept[1] == 500000 && slept[2] == 1000000 &&
        slept[3] == 2000000 && slept[4] == 4000000);
    assert(strcmp(fatal_message, "dtraced did not accept the derived "
        "program after 6 attempts: Protocol error\n") == 0);
    puts("PASS: active and completed parent replay exact ELF; distinct uploads and failures do not ACK success; a persistent derived refusal gives up after bounded backoff");
    return (0);
}
