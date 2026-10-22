/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <dtraced.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <dt_list.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>
#define DT_PROG_IDENTLEN DTRACED_PROGIDENTLEN
#define EDT_NOMEM ENOMEM
typedef struct { char dp_ident[DT_PROG_IDENTLEN]; char dp_srcident[DT_PROG_IDENTLEN]; uint16_t dp_vmid; uint64_t dp_vmepoch; } dtrace_prog_t;
int dtrace_program_source_id(const dtrace_prog_t *, uint8_t[16]);
int dtrace_send_elf(dtrace_prog_t *, int, int, const char *, int);
static char test_dtraced_sockpath[sizeof(((struct sockaddr_un *)0)->sun_path)];
#undef DTRACED_SOCKPATH
#define DTRACED_SOCKPATH test_dtraced_sockpath
#include "library-transport.inc"
struct peer { int fd, count; bool nak; };
static void transfer(int fd, void *data, size_t size, bool writing)
{
    size_t transferred;
    assert(dtraced_io_transfer(fd, data, size, writing,
        dtraced_io_milliseconds() + 3000, &transferred) == 0);
}
struct hello_peer {
    int listener;
    uint8_t sessions[3][16];
    char birth_ident[DTRACED_FDIDENTLEN];
};
static void *receive_hellos(void *arg)
{
    struct hello_peer *fixture = arg;
    for (unsigned i = 0; i < 3; i++) {
        int fd = accept(fixture->listener, NULL, NULL);
        assert(fd >= 0);
        dtd_initmsg_t banner = {
            .protocol_version = DTRACED_PROTOCOL_VERSION,
            .kind = DTRACED_KIND_DTRACED
        }, hello = { 0 };
        size_t transferred;
        int64_t deadline = dtraced_io_milliseconds() + 3000;
        assert(dtraced_wire_write_init(fd, &banner, deadline,
            &transferred) == 0);
        assert(dtraced_wire_read_init(fd, &hello, deadline,
            &transferred) == 0);
        assert(hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
            hello.kind == DTRACED_KIND_CONSUMER &&
            hello.subs == DTD_SUB_ELFWRITE);
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "dtrace-%d-", getpid());
        assert(strncmp(hello.ident, prefix, strlen(prefix)) == 0 &&
            strlen(hello.ident) == strlen(prefix) + 32);
        if (i == 0)
            strlcpy(fixture->birth_ident, hello.ident,
                sizeof(fixture->birth_ident));
        else
            assert(strcmp(hello.ident, fixture->birth_ident) == 0);
        const uint8_t zero[16] = { 0 };
        assert(memcmp(hello.session_id, zero, sizeof(zero)) != 0);
        memcpy(fixture->sessions[i], hello.session_id, 16);
        close(fd);
    }
    return NULL;
}
static void test_consumer_sessions(void)
{
    char directory[] = "/tmp/hypertrace-consumer-session.XXXXXX";
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(test_dtraced_sockpath, sizeof(test_dtraced_sockpath),
        "%s/sub.sock", directory) < (int)sizeof(test_dtraced_sockpath));
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strlcpy(addr.sun_path, test_dtraced_sockpath, sizeof(addr.sun_path));
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 3) == 0);
    struct hello_peer fixture = { .listener = listener };
    pthread_t server;
    assert(pthread_create(&server, NULL, receive_hellos, &fixture) == 0);
    uint8_t retained_session[16] = { 0 };
    for (unsigned i = 0; i < 2; i++) {
        int client = open_dtraced_session(DTD_SUB_ELFWRITE,
            retained_session);
        assert(client >= 0);
        close(client);
    }
    int fresh = open_dtraced(DTD_SUB_ELFWRITE);
    assert(fresh >= 0);
    close(fresh);
    assert(pthread_join(server, NULL) == 0);
    assert(memcmp(fixture.sessions[0], fixture.sessions[1], 16) == 0);
    assert(memcmp(fixture.sessions[0], fixture.sessions[2], 16) != 0);
    close(listener);
    assert(unlink(test_dtraced_sockpath) == 0);
    assert(rmdir(directory) == 0);
}
struct derived_peer {
    int fd;
    dtraced_derived_parent_t parent;
};
static void *receive_derived(void *arg)
{
    struct derived_peer *peer = arg;
    size_t length;
    transfer(peer->fd, &length, sizeof(length), false);
    assert(length > DTRACED_MSGHDRSIZE && length < 4096);
    unsigned char wire[4096];
    transfer(peer->fd, wire, length, false);
    dtraced_hdr_t header = { 0 };
    assert(dtraced_wire_decode_header(&header, wire) == 0);
    assert(header.msg_type == DTRACED_MSG_ELF &&
        strcmp(header.elf.location, "outbound") == 0 &&
        header.elf.len == length - DTRACED_MSGHDRSIZE);
    dtraced_derived_parent_t observed = { 0 };
    assert(dtraced_derived_parent_from_header(&observed, &header) == 0);
    assert(observed.delivery_id == peer->parent.delivery_id &&
        memcmp(observed.consumer_session,
        peer->parent.consumer_session, 16) == 0 &&
        observed.vmid == peer->parent.vmid &&
        observed.epoch == peer->parent.epoch &&
        memcmp(observed.program_id, peer->parent.program_id, 16) == 0 &&
        memcmp(observed.source_id, peer->parent.source_id, 16) == 0);
    uint8_t expected[16];
    assert(dtraced_derived_program_id(&observed,
        wire + DTRACED_MSGHDRSIZE, header.elf.len, expected) == 0);
    assert(memcmp(expected, header.elf.program_id, 16) == 0 &&
        memcmp(header.elf.source_id, observed.source_id, 16) == 0);
    const unsigned char ack = 1;
    transfer(peer->fd, (void *)&ack, 1, true);
    return NULL;
}
static void test_derived_send(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    char path[] = "/tmp/hypertrace-derived.XXXXXX";
    int source = mkstemp(path);
    assert(source >= 0);
    const char elf[] = "\177ELFderived";
    assert(write(source, elf, sizeof(elf)) == (ssize_t)sizeof(elf));
    dtrace_prog_t program = { 0 };
    strcpy(program.dp_ident, "derived");
    strcpy(program.dp_srcident, "source");
    program.dp_vmid = 9;
    program.dp_vmepoch = 43;
    struct derived_peer peer = { .fd = sockets[1], .parent = {
        .consumer_session = { 0x76 },
        .delivery_id = 99, .vmid = 7, .epoch = 42,
        .program_id = { 0xaa }
    } };
    assert(dtrace_program_source_id(&program, peer.parent.source_id) == 0);
    pthread_t server;
    assert(pthread_create(&server, NULL, receive_derived, &peer) == 0);
    assert(dtrace_send_elf_derived(&program, source, sockets[0],
        &peer.parent) == 0);
    assert(pthread_join(server, NULL) == 0);
    close(source);
    close(sockets[0]);
    close(sockets[1]);
    assert(unlink(path) == 0);
}
static void *receive(void *arg)
{
    struct peer *peer = arg;
    for (int i = 0; i < peer->count; i++) {
        size_t length; transfer(peer->fd, &length, sizeof(length), false);
        assert(length >= DTRACED_MSGHDRSIZE && length < 4096);
        unsigned char buf[4096]; transfer(peer->fd, buf, length, false);
        dtraced_hdr_t hdr;
        assert(dtraced_wire_decode_header(&hdr, buf) == 0);
        if (hdr.msg_type == DTRACED_MSG_ELF) {
            size_t prefix = hdr.elf.len == 4 ? 0 :
                HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
            assert(hdr.elf.len == 4 + prefix &&
                length == DTRACED_MSGHDRSIZE + prefix + 4);
            if (prefix) {
                struct hypertrace_vm_envelope target;
                hypertrace_envelope_decode(&target,
                    (const uint8_t *)buf + DTRACED_MSGHDRSIZE);
                assert(target.magic == HYPERTRACE_TARGET_MAGIC && target.version == HYPERTRACE_ENVELOPE_VERSION);
                assert(target.vmid == 7 && target.epoch == 42 && target.name_length == 0);
            }
            assert(memcmp(buf + DTRACED_MSGHDRSIZE + prefix,
                "\177ELF", 4) == 0);
            assert(strcmp(hdr.elf.location, "outbound") == 0);
            assert(hdr.elf.ident_present == 1 && hdr.elf.ident[0] == 'x');
	    unsigned char digest[SHA256_DIGEST_LENGTH];
	    char source[DT_PROG_IDENTLEN] = { 'x' };
	    assert(SHA256((unsigned char *)source, sizeof(source), digest));
	    assert(memcmp(hdr.elf.source_id, digest, 16) == 0);
            assert(hdr.elf.filter_by_vmid == 0 && hdr.elf.vmid == 0);
            assert(hdr.kill.pid == 0 && hdr.cleanup.num_entries == 0 && hdr.info.count == 0);
        } else assert(hdr.msg_type == DTRACED_MSG_KILL &&
            length == DTRACED_MSGHDRSIZE);
        unsigned char ack = peer->nak ? 0 : 1;
        transfer(peer->fd, &ack, 1, true);
    }
    return NULL;
}
int main(void)
{
    alarm(20); signal(SIGPIPE, SIG_DFL);
    test_consumer_sessions();
    test_derived_send();
    dtrace_async_teardown(); /* Safe before initialization and after teardown. */
    for (int iteration = 0; iteration < 2; iteration++) {
        char path[] = "/tmp/hypertrace-library.XXXXXX";
        int file = mkstemp(path), fds[2]; assert(file >= 0);
        assert(write(file, "\177ELF", 4) == 4); /* File offset deliberately at EOF. */
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        struct peer peer = { fds[1], 1, false };
        pthread_t thread; assert(pthread_create(&thread, NULL, receive, &peer) == 0);
        dtrace_prog_t *pgp = calloc(1, sizeof(*pgp)); assert(pgp); pgp->dp_ident[0] = 'x';
	uint8_t lineage[16];
	assert(dtrace_program_source_id(pgp, lineage) == 0);
	pgp->dp_srcident[0] = 'x';
	pgp->dp_ident[0] = 'y';
	uint8_t inherited[16];
	assert(dtrace_program_source_id(pgp, inherited) == 0 &&
	    memcmp(lineage, inherited, sizeof(lineage)) == 0);
	pgp->dp_ident[0] = 'x';
        if (iteration == 1) {
            pgp->dp_vmid = 7;
            assert(dtrace_send_elf(pgp, file, fds[0], "outbound", 1) == -1 && errno == ESTALE);
            pgp->dp_vmepoch = 42;
        }
        assert(dtrace_send_elf_async(pgp, file, fds[0], path, "outbound", 1) == 0);
        memset(pgp, 0xa5, sizeof(*pgp)); free(pgp);
        close(fds[0]); /* The worker owns a separate descriptor reference. */
        assert(pthread_join(thread, NULL) == 0);
        dtrace_async_teardown(); dtrace_async_teardown();
        assert(fcntl(file, F_GETFD) == -1 && errno == EBADF);
        assert(access(path, F_OK) == -1 && errno == ENOENT);
        close(fds[1]);
    }
    int fds[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    struct peer peer = { fds[1], 1, true }; pthread_t thread;
    assert(pthread_create(&thread, NULL, receive, &peer) == 0);
    dtraced_hdr_t hdr = { .msg_type = DTRACED_MSG_KILL };
    hdr.kill.pid = 123;
    hdr.kill.vmid = 7;
    hdr.kill.epoch = 42;
    hdr.kill.source_id[0] = 0xa5;
    assert(dtrace_send_message(fds[0], &hdr, NULL, 0) == -1 && errno == EPROTO);
    assert(pthread_join(thread, NULL) == 0);
    char c; assert(read(fds[1], &c, 1) == 0); close(fds[0]); close(fds[1]);
    char path[] = "/tmp/hypertrace-library-large.XXXXXX";
    int file = mkstemp(path); assert(file >= 0);
    assert(ftruncate(file, 65U * 1024U * 1024U) == 0);
    assert(dtrace_send_elf(NULL, file, 1, "outbound", 0) == -1 && errno == EMSGSIZE);
    close(file); unlink(path);
    /* A supplied program still supplies lineage when ident_present is off. */
    {
        char program_path[]="/tmp/hypertrace-no-ident.XXXXXX";
        int program_file=mkstemp(program_path),pair[2];assert(program_file>=0);
        assert(write(program_file,"\177ELF",4)==4);
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
        dtrace_prog_t program={0};program.dp_ident[0]='z';
        uint8_t source_id[16];assert(dtrace_program_source_id(&program,source_id)==0);
        assert(dtrace_send_elf_async(&program,program_file,pair[0],program_path,"outbound",0)==0);
        uint8_t count[8];transfer(pair[1],count,sizeof(count),false);
        assert(dtraced_wire_get_u64(count)==DTRACED_MSGHDRSIZE+4);
        uint8_t payload[DTRACED_MSGHDRSIZE+4];transfer(pair[1],payload,sizeof(payload),false);
        dtraced_hdr_t decoded;assert(dtraced_wire_decode_header(&decoded,payload)==0);
        assert(decoded.elf.ident_present==0 && memcmp(decoded.elf.source_id,source_id,16)==0);
        unsigned char accepted=1;transfer(pair[1],&accepted,1,true);
        dtrace_async_teardown();
        assert(access(program_path,F_OK)==-1 && errno==ENOENT);
        close(pair[0]);close(pair[1]);
    }
    /* Leave one real async frame waiting for its ACK and a second queued.
     * Discard must interrupt the first and never send the second. */
    int stopped[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,stopped)==0);
    char active_path[]="/tmp/hypertrace-active-discard.XXXXXX";
    char queued_path[]="/tmp/hypertrace-queued-discard.XXXXXX";
    int active_file=mkstemp(active_path),queued_file=mkstemp(queued_path);
    assert(active_file>=0 && queued_file>=0);
    assert(write(active_file,"\177ELF",4)==4 && write(queued_file,"\177ELF",4)==4);
    assert(dtrace_send_elf_async(NULL,active_file,stopped[0],active_path,"outbound",0)==0);
    unsigned char size_wire[8];transfer(stopped[1],size_wire,sizeof(size_wire),false);
    size_t length=dtraced_wire_get_u64(size_wire);
    assert(length==DTRACED_MSGHDRSIZE+4);
    void *frame=malloc(length);assert(frame);transfer(stopped[1],frame,length,false);free(frame);
    assert(dtrace_send_elf_async(NULL,queued_file,stopped[0],queued_path,"outbound",0)==0);
    assert(pthread_mutex_lock(&_elf_async_mtx)==0);
    assert(_elf_async_active && _elf_async_count==1);
    assert(dtrace_async_discard_step()==0); /* Busy queue lock never blocks. */
    assert(pthread_mutex_unlock(&_elf_async_mtx)==0);
    int64_t stop_deadline=dtraced_io_deadline_after(2000);
    int done;
    while((done=dtrace_async_discard_step())==0) {
        assert(dtraced_io_milliseconds()<stop_deadline);
        usleep(1000);
    }
    assert(done==1 && _elf_async_count==0 && _elf_async_active==NULL);
    assert(read(stopped[1],&c,1)==0); /* No queued frame after the cut. */
    assert(fcntl(active_file,F_GETFD)==-1 && errno==EBADF);
    assert(fcntl(queued_file,F_GETFD)==-1 && errno==EBADF);
    assert(access(active_path,F_OK)==-1 && errno==ENOENT);
    assert(access(queued_path,F_OK)==-1 && errno==ENOENT);
    char rejected_path[]="/tmp/hypertrace-rejected-discard.XXXXXX";
    int rejected_file=mkstemp(rejected_path);assert(rejected_file>=0);
    for(int retry=0;retry<2;retry++) {
        assert(dtrace_send_elf_async(NULL,rejected_file,stopped[0],rejected_path,"outbound",0)==ESHUTDOWN);
        assert(fcntl(rejected_file,F_GETFD)>=0 && access(rejected_path,F_OK)==0);
        dtrace_async_teardown();
        assert(dtrace_async_discard_step()==1);
    }
    assert(close(rejected_file)==0 && unlink(rejected_path)==0);
    close(stopped[0]);close(stopped[1]);
    puts("PASS: actual library framing, initialized headers, ELF offsets, NAK, async ownership and restart");
}
