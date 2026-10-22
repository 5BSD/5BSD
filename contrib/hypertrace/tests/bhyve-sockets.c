/* SPDX-License-Identifier: BSD-2-Clause */
/* Production configuration: Capsicum rights limits are compiled in and
 * applied to the test's descriptors (no capability-mode entry). */
#include "hypertrace.c"
#include <signal.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno %d)\n", \
    __FILE__, __LINE__, #x, errno); abort(); } } while (0)
uint16_t vm_get_vmid(struct vmctx *ctx __unused) { return (1); }
int vm_get_identity(struct vmctx *ctx __unused, uint16_t *id,
    uint64_t *epoch) { *id = 1; *epoch = 77; return (0); }
const char *vm_get_name(struct vmctx *ctx __unused) { return ("test"); }
int vm_export_attestation_fd(struct vmctx *ctx __unused) {
	return (open("/dev/null", O_RDONLY | O_CLOEXEC));
}

static void
pair(struct ht_channel *c, int *peer)
{
	int fds[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	c->fd = fds[0];
	atomic_store(&c->configured, true);
	*peer = fds[1];
}
static void
put(int fd, void *p, size_t length)
{
	size_t n;
	CHECK(dtraced_io_transfer(fd, p, length, true, dtraced_io_milliseconds() + 2000, &n) == 0);
}
static void
put_header(int fd, const dtraced_hdr_t *header)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];

	dtraced_wire_encode_header(wire, header);
	put(fd, wire, sizeof(wire));
}
static void
get(int fd, void *p, size_t length)
{
	size_t n;
	CHECK(dtraced_io_transfer(fd, p, length, false, dtraced_io_milliseconds() + 2000, &n) == 0);
}
static void *
fragmented(void *arg)
{
	int fd = *(int *)arg;
	dtraced_hdr_t hdr = { .msg_type = DTRACED_MSG_ELF };
	hdr.elf.len = 9;
	hdr.elf.delivery_id = 0x1234;
	hdr.elf.program_id[0] = 0x42;
	hdr.elf.source_id[0] = 0x55;
	unsigned char wire[DTRACED_MSGHDRSIZE];
	dtraced_wire_encode_header(wire, &hdr);
	for (size_t i = 0; i < sizeof(wire); i++)
		put(fd, wire + i, 1);
	put(fd, "fragment!", 9);
	dtraced_delivery_ack_t ack;
	get(fd, &ack, sizeof(ack));
	CHECK(ack.delivery_id == hdr.elf.delivery_id);
	return (NULL);
}
static void *
writer(void *arg)
{
	dtraced_hdr_t hdr = { .msg_type = (uintptr_t)arg };
	if (hdr.msg_type == DTRACED_MSG_KILL) {
		hdr.kill.pid = 123;
		hdr.kill.vmid = 42;
		hdr.kill.epoch = 99;
		hdr.kill.source_id[0] = 0x42;
	}
	CHECK(hypertrace_write(&hdr, NULL, 0) == 0);
	return (NULL);
}
static void *
receiver(void *arg)
{
	int fd = *(int *)arg;
	uint64_t length;
	dtraced_hdr_t hdr;
	unsigned char wire[DTRACED_MSGHDRSIZE];
	unsigned mask = 0;
	unsigned char ack = 1;
	for (int i = 0; i < 2; i++) {
		get(fd, wire, sizeof(uint64_t));
		length = dtraced_wire_get_u64(wire);
		CHECK(length == DTRACED_MSGHDRSIZE);
		get(fd, wire, sizeof(wire));
		CHECK(dtraced_wire_decode_header(&hdr, wire) == 0);
		CHECK(hdr.msg_type == 1 || hdr.msg_type == 2);
		mask |= 1U << hdr.msg_type;
		put(fd, &ack, 1);
	}
	CHECK(mask == 6);
	return (NULL);
}
static int status_case;
static void *
status_responder(void *arg)
{
	int fd = *(int *)arg;
	size_t length;
	dtraced_hdr_t request;
	unsigned char ack = 1;
	dtraced_delivery_status_t status = { 0 };
	get(fd, &length, sizeof(length));
	CHECK(length == sizeof(request));
	get(fd, &request, sizeof(request));
	CHECK(request.msg_type == DTRACED_MSG_STATUS &&
	    request.installed.delivery_id == 0x3456);
	status.delivery_id = request.installed.delivery_id + (status_case == 1);
	status.phase = status_case == 5 ? 'u' : 'i';
	status.revoked = status_case == 4 || status_case == 5 ||
	    status_case == 6 ? 0 : 1;
	status.replay = status_case == 2 || status_case == 4 ||
	    status_case == 6;
	status.digest[0] = status_case == 3 || status_case == 4 ? 0x42 : 0;
	put(fd, &ack, sizeof(ack));
	put(fd, &status, sizeof(status));
	return (NULL);
}
static int ingress_case;
static void *
ingress_responder(void *arg)
{
	int fd = *(int *)arg;
	size_t length;
	dtraced_hdr_t request;
	unsigned char ack = 1;
	dtraced_delivery_status_t status = { 0 };
	get(fd, &length, sizeof(length));
	CHECK(length == sizeof(request));
	get(fd, &request, sizeof(request));
	CHECK(request.msg_type == DTRACED_MSG_INGRESS_STATUS &&
	    request.installed.delivery_id == 0x3456);
	status.delivery_id = request.installed.delivery_id +
	    (ingress_case == 1);
	status.phase = ingress_case == 4 ? 'u' :
	    ingress_case == 5 || ingress_case == 6 ? 0 :
	    ingress_case == 7 ? 'p' : 'a';
	status.revoked = ingress_case == 8;
	status.replay = ingress_case == 3;
	if (ingress_case != 2 && ingress_case != 6)
		status.digest[0] = 0x42;
	put(fd, &ack, sizeof(ack));
	put(fd, &status, sizeof(status));
	return (NULL);
}
int
main(void)
{
	int fd, fds[2];
	void *buf;
	dtraced_hdr_t hdr, message = { .msg_type = DTRACED_MSG_CLEANUP };
	pthread_t thread, a, b;
	size_t n, length = 4;
	char scratch[16];
	int64_t start;
	uint64_t read_epoch, read_connection;

	pair(&rx, &fd);
	CHECK(pthread_create(&thread, NULL, fragmented, &fd) == 0);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == 0);
	CHECK(hdr.elf.len == 9 && memcmp(buf, "fragment!", 9) == 0);
	CHECK(hypertrace_ack_epoch(rx.generation, rx.connection_generation,
	    hdr.elf.delivery_id + 1) == -1 && errno == ESTALE);
	CHECK(hypertrace_ack_epoch(rx.generation, rx.connection_generation,
	    hdr.elf.delivery_id) == 0);
	CHECK(hypertrace_ack_epoch(rx.generation, rx.connection_generation,
	    hdr.elf.delivery_id) == -1 && errno == ESTALE);
	free(buf);
	CHECK(pthread_join(thread, NULL) == 0);
	/* Cleanup payload must not be mistaken for the next header. */
	message.cleanup.num_entries = 1;
	message.cleanup.vmid = 42;
	message.cleanup.epoch = 99;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(message) = 0x8899;
	put_header(fd, &message);
	put(fd, &length, sizeof(length));
	put(fd, "abc", length);
	message = (dtraced_hdr_t){ .msg_type = DTRACED_MSG_KILL };
	message.kill.pid = 123;
	message.kill.vmid = 42;
	message.kill.epoch = 99;
	message.kill.source_id[0] = 0x42;
	put_header(fd, &message);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == 0 && buf == NULL &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(hdr) == 0x8899);
	CHECK(hypertrace_ack_epoch(rx.generation, rx.connection_generation,
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(hdr)) == 0);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == 0 && hdr.kill.pid == 123);
	close(fd);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == -1 && rx.fd == -1);
	pair(&rx, &fd);
	message = (dtraced_hdr_t){ .msg_type = DTRACED_MSG_ELF };
	message.elf.len = HT_MAX_FRAME + 1UL;
	put_header(fd, &message);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == -1 && errno == EMSGSIZE);
	CHECK(buf == NULL && rx.fd == -1);
	close(fd);
	/* A truncated body is freed and its connection retired. */
	pair(&rx, &fd);
	message.elf.len = 100;
	message.elf.delivery_id = 1;
	message.elf.program_id[0] = 0x42;
	message.elf.source_id[0] = 0x55;
	put_header(fd, &message);
	put(fd, "abc", 3);
	close(fd);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == -1 && buf == NULL && rx.fd == -1);
	pair(&rx, &fd);
	message.elf.len = 4;
	message.elf.delivery_id = 0;
	put_header(fd, &message);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &read_epoch, &read_connection) == -1 && errno == EPROTO &&
	    buf == NULL && rx.fd == -1);
	close(fd);
	/* A replacement socket cannot ACK the old socket's completed ELF. */
	pair(&rx, &fd);
	message.elf.len = 4;
	message.elf.delivery_id = 0x4567;
	put_header(fd, &message);
	put(fd, "\177ELF", 4);
	uint64_t old_epoch, old_connection;
	CHECK(hypertrace_read_epoch(&buf, &hdr, &old_epoch,
	    &old_connection) == 0);
	CHECK(hdr.elf.delivery_id == 0x4567);
	free(buf);
	CHECK(hypertrace_read_epoch(&buf, &hdr, &old_epoch,
	    &old_connection) == -1 &&
	    errno == EBUSY);
	pthread_mutex_lock(&rx.mutex);
	ht_disconnect(&rx);
	pthread_mutex_unlock(&rx.mutex);
	close(fd);
	pair(&rx, &fd);
	put_header(fd, &message);
	put(fd, "\177ELF", 4);
	uint64_t new_epoch, new_connection;
	CHECK(hypertrace_read_epoch(&buf, &hdr, &new_epoch,
	    &new_connection) == 0);
	free(buf);
	CHECK(new_epoch == old_epoch && new_connection != old_connection);
	CHECK(hypertrace_ack_epoch(old_epoch, old_connection, 0x4567) == -1 &&
	    errno == ESTALE);
	CHECK(hypertrace_ack_epoch(new_epoch, new_connection, 0x4567) == 0);
	dtraced_delivery_ack_t replacement_ack;
	get(fd, &replacement_ack, sizeof(replacement_ack));
	CHECK(replacement_ack.delivery_id == 0x4567);
	pthread_mutex_lock(&rx.mutex);
	ht_disconnect(&rx);
	pthread_mutex_unlock(&rx.mutex);
	close(fd);
	pair(&wx, &fd);
	CHECK(pthread_create(&thread, NULL, receiver, &fd) == 0);
	CHECK(pthread_create(&a, NULL, writer, (void *)1) == 0);
	CHECK(pthread_create(&b, NULL, writer, (void *)2) == 0);
	CHECK(pthread_join(a, NULL) == 0);
	CHECK(pthread_join(b, NULL) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(fd);
	/* SIGPIPE is not ignored: the transport itself must suppress it. */
	CHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
	CHECK(hypertrace_write(&message, "\177ELF", 4) == -1 && wx.fd == -1);
	dtraced_hdr_t query = { .msg_type = DTRACED_MSG_STATUS };
	query.installed.delivery_id = 0x3456;
	query.installed.vmid = 7;
	query.installed.epoch = 11;
	query.installed.program_id[0] = 0x42;
	query.installed.source_id[0] = 0x55;
	dtraced_delivery_status_t status;
	CHECK(hypertrace_delivery_status(&query, &status) == -1 &&
	    errno == ENOTCONN);
	for (status_case = 0; status_case <= 6; status_case++) {
		pair(&wx, &fd);
		CHECK(pthread_create(&thread, NULL, status_responder, &fd) == 0);
		int result = hypertrace_delivery_status(&query, &status);
		int status_errno = errno;
		CHECK(pthread_join(thread, NULL) == 0);
		if (status_case == 0 || status_case == 4 || status_case == 5)
			CHECK(result == 0 && status.delivery_id == 0x3456 &&
			    status.phase == (status_case == 5 ? 'u' : 'i') &&
			    status.revoked ==
			    ((status_case == 4 || status_case == 5) ? 0 : 1) &&
			    status.replay == (status_case == 4));
		else
			CHECK(result == -1 && status_errno == EPROTO && wx.fd == -1);
		close(fd);
		if (status_case == 0 || status_case == 4 || status_case == 5) {
			pthread_mutex_lock(&wx.mutex);
			ht_disconnect(&wx);
			pthread_mutex_unlock(&wx.mutex);
		}
	}
	query.msg_type = DTRACED_MSG_INGRESS_STATUS;
	for (ingress_case = 0; ingress_case <= 8; ingress_case++) {
		pair(&wx, &fd);
		CHECK(pthread_create(&thread, NULL,
		    ingress_responder, &fd) == 0);
		int result = hypertrace_ingress_status(&query, &status);
		int status_errno = errno;
		CHECK(pthread_join(thread, NULL) == 0);
		if (ingress_case == 0 || ingress_case == 6 ||
		    ingress_case == 7 || ingress_case == 8)
			CHECK(result == 0 && status.delivery_id == 0x3456 &&
			    status.phase == (ingress_case == 6 ? 0 :
			    ingress_case == 7 ? 'p' : 'a') &&
			    status.digest[0] == (ingress_case == 6 ? 0 : 0x42) &&
			    status.revoked == (ingress_case == 8));
		else
			CHECK(result == -1 && status_errno == EPROTO &&
			    wx.fd == -1);
		close(fd);
		if (ingress_case == 0 || ingress_case == 6 ||
		    ingress_case == 7 || ingress_case == 8) {
			pthread_mutex_lock(&wx.mutex);
			ht_disconnect(&wx);
			pthread_mutex_unlock(&wx.mutex);
		}
	}
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	CHECK(dtraced_io_complete_connect(fds[0],
	    dtraced_io_milliseconds() + 100) == 0);
	start = dtraced_io_milliseconds();
	CHECK(dtraced_io_transfer(fds[0], scratch, 1, false, start + 30, &n) == -1);
	CHECK(errno == ETIMEDOUT && n == 0 && dtraced_io_milliseconds() - start < 1000);
	put(fds[1], "x", 1);
	CHECK(dtraced_io_transfer(fds[0], scratch, 2, false, dtraced_io_milliseconds() + 30,
	    &n) == -1 && errno == ETIMEDOUT && n == 1);
	close(fds[0]); close(fds[1]);
	/* Reset retires both directions and tags subsequent frames at receipt. */
	int write_peer;
	pair(&rx, &fd); pair(&wx, &write_peer);
	uint64_t epoch, reset_epoch = hypertrace_reset();
	CHECK(reset_epoch == 1 && rx.fd == -1 && wx.fd == -1);
	CHECK(hypertrace_ack_epoch(reset_epoch - 1,
	    rx.connection_generation, 1) == -1 && errno == ESTALE);
	CHECK(!hypertrace_configured());
	CHECK(read(fd, scratch, 1) == 0 && read(write_peer, scratch, 1) == 0);
	close(fd); close(write_peer);
	pair(&rx, &fd);
	message = (dtraced_hdr_t){ .msg_type = DTRACED_MSG_KILL };
	message.kill.pid = 456;
	message.kill.vmid = 42;
	message.kill.epoch = 99;
	message.kill.source_id[0] = 0x42;
	put_header(fd, &message);
	uint64_t connection;
	CHECK(hypertrace_read_epoch(&buf, &hdr, &epoch, &connection) == 0);
	CHECK(epoch == reset_epoch && hdr.kill.pid == 456 && buf == NULL);
	close(fd);
	hypertrace_destroy();
	hypertrace_destroy();
	puts("PASS: bhyve framing, cleanup, concurrent writers, EOF, bounds, deadlines, SIGPIPE");
	return (0);
}
