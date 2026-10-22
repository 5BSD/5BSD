/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <dttransport.h>
#include <thread>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"

using namespace dtraced;

class test_client_fd : public client_fd {
public:
    using client_fd::client_fd;
    void set_kq(int descriptor) { kq = descriptor; }
};

static void
transfer(int fd, void *data, size_t size, bool sending)
{
    auto *bytes = static_cast<unsigned char *>(data);
    for (size_t offset = 0; offset < size;) {
        ssize_t n = sending ? write(fd, bytes + offset, size - offset) :
            read(fd, bytes + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        offset += static_cast<size_t>(n);
    }
}

int main()
{
    alarm(15);
    char path[] = "/tmp/hypertrace-outbound-replay.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    outbound.state = &s;
    s.outbounddir = &outbound;
	int dtt[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, dtt) == 0);
	s.dtt_fd = dtt[0];
    const char name[] =
        "elf.aa000000000000000000000000000000.bb000000000000000000000000000000";
    const unsigned char elf[] = "\177ELFrecovered";
    int fd = openat(outbound.dirfd, name, O_CREAT | O_WRONLY, 0600);
    assert(fd >= 0 && write(fd, elf, sizeof(elf)) == sizeof(elf));
    assert(close(fd) == 0);
    durable_delivery record{};
    record.scope = 2;
    record.journal_version = 4;
    record.session_id[0] = 1; /* Previous local forwarder session. */
    record.delivery_id = 701;
	record.vmid = 42;
	record.epoch = 99;
    record.program_id[0] = 0xaa;
    record.source_id[0] = 0xbb;
    record.peer_uid = geteuid();
    record.peer_pid = getpid() + 1;
    assert(SHA256(elf, sizeof(elf), record.payload_digest.data()));
    assert(outbound.record_delivery(record, delivery_phase::pending, true));
    durable_delivery duplicate = record;
    duplicate.delivery_id = 703;
    assert(!outbound.record_delivery(duplicate,
        delivery_phase::pending, true) && errno == EBUSY);
    assert(outbound.queue_recovered_outbound(record, 42, 99) == 0);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    int kq = kqueue();
    assert(kq >= 0);
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_ELFWRITE;
    hello.session_id[0] = 2;
    snprintf(hello.ident, sizeof(hello.ident),
        "dtraced-dttransport-%d", getpid());
    {
        test_client_fd forwarder(kq, sv[0], hello);
        forwarder.peer_uid = geteuid();
        forwarder.peer_pid = getpid();
        assert(forwarder.enable_write(&forwarder));
        s.sockfds.insert(&forwarder);
        forwarder.set_kq(-1);
        assert(outbound.queue_recovered_outbound(record, 42, 99) == -1 &&
            errno == EBADF && s.joblist.empty());
        forwarder.set_kq(kq);
        assert(outbound.queue_recovered_outbound(record, 42, 99) == 1 &&
            s.joblist.size() == 1);
        job *replay = s.joblist.front();
        s.joblist.clear();
        assert(replay->notify_elfwrite_get().replay != nullptr &&
            replay->notify_elfwrite_get().replay->delivery_id == 701);
        std::thread receiver([&] {
            dtraced_hdr_t header{};
            transfer(sv[1], &header, sizeof(header), false);
            assert(header.msg_type == DTRACED_MSG_ELF &&
                header.elf.delivery_id == record.delivery_id &&
                header.elf.len == sizeof(elf) &&
                header.elf.program_id[0] == 0xaa &&
                header.elf.source_id[0] == 0xbb &&
			header.elf.vmid == 42 && header.elf.epoch == 99);
            unsigned char received[sizeof(elf)]{};
            transfer(sv[1], received, sizeof(received), false);
            assert(memcmp(received, elf, sizeof(elf)) == 0);
            dtraced_delivery_ack_t ack{};
            ack.delivery_id = header.elf.delivery_id;
            transfer(sv[1], &ack, sizeof(ack), true);
        });
		std::thread identity([&] {
			dtt_entry_t query{};
			transfer(dtt[1], &query, sizeof(query), false);
			assert(query.event_kind == DTT_VM_IDENTITY_QUERY &&
			    query.u.installed.query_id != 0);
			std::lock_guard lock(s.vm_identity_mtx);
			assert(s.vm_identity_query_id ==
			    query.u.installed.query_id);
			s.vm_identity_vmid = 42;
			s.vm_identity_epoch = 99;
			s.vm_identity_ready = true;
			s.vm_identity_cv.notify_all();
		});
        assert(replay->send_elf());
        identity.join();
        receiver.join();
        delete replay;
        assert(outbound.delivery_status(record) == 0);

        record.delivery_id = 702;
        assert(outbound.record_delivery(record, delivery_phase::pending, true));
        assert(outbound.queue_recovered_outbound(record, 42, 99) == 1 &&
            s.joblist.size() == 1);
        replay = s.joblist.front();
        s.joblist.clear();
        fd = openat(outbound.dirfd, name, O_WRONLY | O_NOFOLLOW);
        assert(fd >= 0 && pwrite(fd, "X", 1, 4) == 1);
        assert(close(fd) == 0);
        assert(!replay->send_elf() && errno == EPROTO);
        delete replay;
        assert(outbound.delivery_status(record) ==
            (int)delivery_phase::pending);
        s.sockfds.clear();
    }
    close(sv[1]); close(kq); close(dtt[0]); close(dtt[1]);
    DIR *scan = fdopendir(openat(outbound.dirfd, ".", O_RDONLY | O_DIRECTORY));
    assert(scan != nullptr);
    while (dirent *entry = readdir(scan))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            assert(unlinkat(outbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(scan) == 0 && rmdir(path) == 0);
    puts("PASS: recovered outbound replay preserves token and retires ACKed journal");
}
