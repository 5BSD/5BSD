/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libdtrace's side of the dtraced protocol: framed messages and their
 * acknowledgements, program ELF delivery (including the HyperTrace VM
 * envelope for guest-bound programs), the asynchronous send queue and its
 * terminal discard fence, and the consumer session handshake.
 *
 * The peer decodes frames with the daemon's own wire decoder
 * (usr.sbin/dtraced/dtraced_wire.h) and the envelope decoder from
 * sys/sys/hypertrace_wire.h; program source identities are recomputed with
 * libmd's SHA-256.  open_dtraced_session() is exercised by interposing
 * connect() for the fixed daemon socket path only, redirecting it to a
 * socket in the test directory.  No daemon, device or VM is used.
 *
 * Each scenario runs in its own process: the async queue state is
 * process-global and the discard fence is terminal.
 */

#include <dt_impl.h>
#include <dt_program.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <assert.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/procdesc.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures, checks;

#define	CHECK(cond, ...) do {						\
	checks++;							\
	if (!(cond)) {							\
		failures++;						\
		printf("FAIL %s:%d: ", __func__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* ---------------------------------------------------------------- */
/* Peer: read one frame, then reply as instructed.                   */

enum reply { ACK_OK, ACK_BAD, CLOSE_NO_ACK };

struct frame {
	int fd;
	enum reply reply;
	int ok;
	dtraced_hdr_t hdr;
	unsigned char *payload;
	size_t payload_len;
};

static void *
peer(void *arg)
{
	struct frame *f = arg;
	unsigned char wire[DTRACED_MSGHDRSIZE], ack;
	size_t len, done;
	int64_t deadline = dtraced_io_deadline_after(5000);

	f->ok = 0;
	if (dtraced_io_read_size(f->fd, &len, deadline, &done) != 0 ||
	    len < DTRACED_MSGHDRSIZE) {
		printf("peer: size read failed (len %zu, errno %d)\n", len,
		    errno);
		return (NULL);
	}
	if (dtraced_io_transfer(f->fd, wire, sizeof (wire), false, deadline,
	    &done) != 0) {
		printf("peer: header read failed (errno %d)\n", errno);
		return (NULL);
	}
	if (dtraced_wire_decode_header(&f->hdr, wire) != 0) {
		printf("peer: header rejected by the daemon decoder: type %ju "
		    "ident_present %u filter %u vmid %u loc_canonical %d "
		    "ident_canonical %d installed_nonzero %d\n",
		    (uintmax_t)dtraced_wire_get_u64(wire),
		    dtraced_wire_get_u32(wire + 56),
		    dtraced_wire_get_u32(wire + 60),
		    dtraced_wire_get_u16(wire + 64),
		    dtraced_wire_canonical_name(wire + 80, DTRACED_LOCSIZE),
		    dtraced_wire_canonical_name(wire + 144,
		    DTRACED_PROGIDENTLEN), wire[336] | wire[344] | wire[392]);
		return (NULL);
	}
	f->payload_len = len - DTRACED_MSGHDRSIZE;
	f->payload = malloc(f->payload_len + 1);
	if (f->payload == NULL || (f->payload_len != 0 &&
	    dtraced_io_transfer(f->fd, f->payload, f->payload_len, false,
	    deadline, &done) != 0))
		return (NULL);
	f->ok = 1;
	if (f->reply == CLOSE_NO_ACK) {
		close(f->fd);
		f->fd = -1;
		return (NULL);
	}
	ack = f->reply == ACK_OK ? 1 : 0;
	(void)write(f->fd, &ack, 1);
	return (NULL);
}

static void
pair(int fds[2])
{
	int rc = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);

	assert(rc == 0);
}

/* ---------------------------------------------------------------- */

static void
scenario_message(void)
{
	static const enum reply replies[] = { ACK_OK, ACK_BAD, CLOSE_NO_ACK };
	static const char body[] = "payload-bytes";
	dtraced_hdr_t h;
	size_t i;

	for (i = 0; i < sizeof (replies) / sizeof (replies[0]); i++) {
		struct frame f = { .reply = replies[i] };
		pthread_t t;
		int fds[2], rc, err;

		pair(fds);
		f.fd = fds[1];
		memset(&h, 0, sizeof (h));
		h.msg_type = DTRACED_MSG_ELF;
		h.elf.len = sizeof (body);
		h.elf.delivery_id = 77;
		strlcpy(h.elf.location, "inbound", sizeof (h.elf.location));
		pthread_create(&t, NULL, peer, &f);
		rc = dtrace_send_message(fds[0], &h, body, sizeof (body));
		err = errno;
		pthread_join(t, NULL);
		CHECK(f.ok && f.hdr.msg_type == DTRACED_MSG_ELF &&
		    f.hdr.elf.delivery_id == 77 &&
		    strcmp(f.hdr.elf.location, "inbound") == 0 &&
		    f.payload_len == sizeof (body) &&
		    memcmp(f.payload, body, sizeof (body)) == 0,
		    "frame %zu decoded", i);
		if (replies[i] == ACK_OK)
			CHECK(rc == 0, "acknowledged send returns 0");
		else if (replies[i] == ACK_BAD)
			CHECK(rc == -1 && err == EPROTO, "nack: rc %d err %d",
			    rc, err);
		else
			CHECK(rc == -1 && err != 0, "no ack: rc %d", rc);
		/* Every failure shuts the connection down. */
		if (rc != 0)
			CHECK(write(fds[0], "x", 1) == -1, "socket shut down");
		free(f.payload);
		close(fds[0]);
		if (f.fd >= 0)
			close(f.fd);
	}

	/* Invalid arguments never reach the socket. */
	memset(&h, 0, sizeof (h));
	CHECK(dtrace_send_message(-1, &h, NULL, 0) == -1 && errno == EINVAL,
	    "negative fd");
	CHECK(dtrace_send_message(0, NULL, NULL, 0) == -1 && errno == EINVAL,
	    "NULL header");
	CHECK(dtrace_send_message(0, &h, NULL, 1) == -1 && errno == EINVAL,
	    "payload length without payload");
	CHECK(dtrace_send_message(0, &h, body, 64U * 1024U * 1024U) == -1 &&
	    errno == EINVAL, "oversized payload");
}

static dtrace_hdl_t *
open_handle(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);

	assert(dtp != NULL);
	return (dtp);
}

static dtrace_prog_t *
compile(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *p = dtrace_program_strcompile(dtp,
	    "BEGIN { trace(1); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL);

	assert(p != NULL);
	return (p);
}

static int
elf_file(dtrace_hdl_t *dtp, dtrace_prog_t *p, const char *path,
    unsigned char **content, size_t *len)
{
	char msg[512];
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	struct stat sb;

	assert(fd >= 0);
	assert(dtrace_elf_create(dtp, p, ELFDATA2LSB, fd, path, msg) == 0);
	assert(fstat(fd, &sb) == 0 && sb.st_size > 0);
	*len = sb.st_size;
	*content = malloc(*len);
	assert(pread(fd, *content, *len, 0) == (ssize_t)*len);
	return (fd);
}

/* Expected source id: SHA-256 of the 64-byte identity, first 16 bytes. */
static void
expected_source(const dtrace_prog_t *p, uint8_t out[16])
{
	static const char zero[DT_PROG_IDENTLEN];
	const char *ident = memcmp(p->dp_srcident, zero, sizeof (zero)) == 0 ?
	    p->dp_ident : p->dp_srcident;
	SHA256_CTX ctx;
	uint8_t d[32];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ident, DT_PROG_IDENTLEN);
	SHA256_Final(d, &ctx);
	memcpy(out, d, 16);
}

static void
scenario_elf(void)
{
	dtrace_hdl_t *dtp = open_handle();
	dtrace_prog_t *p = compile(dtp);
	unsigned char *content;
	size_t len;
	uint8_t source[16];
	int fd = elf_file(dtp, p, "program.elf", &content, &len);
	int send_ident;

	expected_source(p, source);
	for (send_ident = 0; send_ident <= 1; send_ident++) {
		struct frame f = { .reply = ACK_OK };
		pthread_t t;
		int fds[2], rc, err;

		pair(fds);
		f.fd = fds[1];
		pthread_create(&t, NULL, peer, &f);
		rc = dtrace_send_elf(p, fd, fds[0], "inbound", send_ident);
		err = errno;
		pthread_join(t, NULL);
		CHECK(rc == 0 && f.ok, "host program delivered: rc %d errno %d "
		    "peer %d", rc, err, f.ok);
		CHECK(f.hdr.msg_type == DTRACED_MSG_ELF &&
		    f.hdr.elf.len == len && f.payload_len == len &&
		    memcmp(f.payload, content, len) == 0,
		    "payload is the ELF file");
		CHECK(strcmp(f.hdr.elf.location, "inbound") == 0, "location");
		CHECK(memcmp(f.hdr.elf.source_id, source, 16) == 0,
		    "source id is SHA-256 of the program identity");
		CHECK(f.hdr.elf.ident_present == send_ident &&
		    (send_ident == 0 || memcmp(f.hdr.elf.ident, p->dp_ident,
		    DT_PROG_IDENTLEN) == 0), "identity present only on request");
		free(f.payload);
		close(fds[0]);
		close(f.fd);
	}

	/* A program-less forward carries no source id. */
	{
		struct frame f = { .reply = ACK_OK };
		static const uint8_t zero[16];
		pthread_t t;
		int fds[2];

		pair(fds);
		f.fd = fds[1];
		pthread_create(&t, NULL, peer, &f);
		CHECK(dtrace_send_elf(NULL, fd, fds[0], "inbound", 0) == 0,
		    "program-less send");
		pthread_join(t, NULL);
		CHECK(f.ok && memcmp(f.hdr.elf.source_id, zero, 16) == 0,
		    "no source id without a program");
		free(f.payload);
		close(fds[0]);
		close(f.fd);
	}

	/* Argument and file refusals happen before any write. */
	{
		char loc[DTRACED_LOCSIZE + 8];
		int fds[2], empty;

		pair(fds);
		CHECK(dtrace_send_elf(p, -1, fds[0], "inbound", 0) == -1 &&
		    errno == EINVAL, "bad fromfd");
		CHECK(dtrace_send_elf(p, fd, fds[0], NULL, 0) == -1 &&
		    errno == EINVAL, "NULL location");
		CHECK(dtrace_send_elf(p, fd, fds[0], "inbound", 2) == -1 &&
		    errno == EINVAL, "send_ident not boolean");
		CHECK(dtrace_send_elf(NULL, fd, fds[0], "inbound", 1) == -1 &&
		    errno == EINVAL, "identity without program");
		memset(loc, 'L', sizeof (loc) - 1);
		loc[sizeof (loc) - 1] = '\0';
		CHECK(dtrace_send_elf(p, fd, fds[0], loc, 0) == -1 &&
		    errno == ENAMETOOLONG, "location too long");
		empty = open("empty.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
		CHECK(dtrace_send_elf(p, empty, fds[0], "inbound", 0) == -1 &&
		    errno == EMSGSIZE, "empty file");
		CHECK(dtrace_send_elf(p, fds[1], fds[0], "inbound", 0) == -1 &&
		    errno == EMSGSIZE, "not a regular file");
		close(empty);
		close(fds[0]);
		close(fds[1]);
	}
	free(content);
	close(fd);
	dtrace_close(dtp);
}

/*
 * A program bound to a VM and sent "outbound" is prefixed with the
 * HyperTrace VM envelope; inbound delivery and host programs are not.
 * An out-of-range VM or a zero epoch is stale.
 */
static void
scenario_envelope(void)
{
	dtrace_hdl_t *dtp = open_handle();
	dtrace_prog_t *p = compile(dtp);
	unsigned char *content;
	size_t len;
	int fd = elf_file(dtp, p, "program.elf", &content, &len);
	struct frame f = { .reply = ACK_OK };
	struct hypertrace_vm_envelope env;
	pthread_t t;
	int fds[2];

	p->dp_vmid = 5;
	p->dp_vmepoch = 0x1234;
	pair(fds);
	f.fd = fds[1];
	pthread_create(&t, NULL, peer, &f);
	CHECK(dtrace_send_elf(p, fd, fds[0], "outbound", 0) == 0,
	    "guest-bound send");
	pthread_join(t, NULL);
	CHECK(f.ok && f.payload_len == HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + len &&
	    f.hdr.elf.len == f.payload_len, "envelope prefixes the ELF");
	if (f.ok && f.payload_len >= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE) {
		hypertrace_envelope_decode(&env, f.payload);
		CHECK(env.magic == HYPERTRACE_TARGET_MAGIC &&
		    env.version == HYPERTRACE_ENVELOPE_VERSION &&
		    env.vmid == 5 && env.epoch == 0x1234,
		    "envelope names VM 5 epoch 0x1234");
		CHECK(memcmp(f.payload + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    content, len) == 0, "ELF follows the envelope");
	}
	free(f.payload);
	close(fds[0]);
	close(f.fd);

	/* Inbound delivery of the same program carries no envelope. */
	{
		struct frame g = { .reply = ACK_OK };

		pair(fds);
		g.fd = fds[1];
		pthread_create(&t, NULL, peer, &g);
		CHECK(dtrace_send_elf(p, fd, fds[0], "inbound", 0) == 0,
		    "inbound send");
		pthread_join(t, NULL);
		CHECK(g.ok && g.payload_len == len, "no envelope inbound");
		free(g.payload);
		close(fds[0]);
		close(g.fd);
	}

	pair(fds);
	p->dp_vmid = HYPERTRACE_MAX_VMS;
	CHECK(dtrace_send_elf(p, fd, fds[0], "outbound", 0) == -1 &&
	    errno == ESTALE, "VM id out of range is stale");
	p->dp_vmid = 5;
	p->dp_vmepoch = 0;
	CHECK(dtrace_send_elf(p, fd, fds[0], "outbound", 0) == -1 &&
	    errno == ESTALE, "zero epoch is stale");
	close(fds[0]);
	close(fds[1]);
	free(content);
	close(fd);
	dtrace_close(dtp);
}

/* The async queue sends in order on a worker and owns the file it sends. */
static void
scenario_async(void)
{
	dtrace_hdl_t *dtp = open_handle();
	dtrace_prog_t *p = compile(dtp);
	unsigned char *content;
	size_t len;
	int fd = elf_file(dtp, p, "async.elf", &content, &len);
	struct frame f = { .reply = ACK_OK };
	pthread_t t;
	int fds[2];

	pair(fds);
	f.fd = fds[1];
	pthread_create(&t, NULL, peer, &f);
	CHECK(dtrace_send_elf_async(p, fd, fds[0], strdup("async.elf"),
	    "outbound", 1) == 0, "queued");
	pthread_join(t, NULL);
	CHECK(f.ok && f.payload_len == len && f.hdr.elf.ident_present == 1 &&
	    memcmp(f.payload, content, len) == 0, "worker delivered the ELF");
	free(f.payload);
	dtrace_async_teardown();
	/* The worker removed the temporary file it was given. */
	CHECK(access("async.elf", F_OK) == -1 && errno == ENOENT,
	    "temporary ELF unlinked");
	dtrace_async_teardown();	/* idempotent */

	CHECK(dtrace_send_elf_async(p, -1, fds[0], "x", "outbound", 0) ==
	    EINVAL, "bad fd refused");
	CHECK(dtrace_send_elf_async(NULL, 0, fds[0], "x", "outbound", 1) ==
	    EINVAL, "identity without program refused");
	CHECK(dtrace_send_elf_async(p, 0, fds[0], NULL, "outbound", 0) ==
	    EINVAL, "missing path refused");
	close(fds[0]);
	close(f.fd);
	free(content);
	dtrace_close(dtp);
}

/* After the terminal discard fence, nothing more can be queued. */
static void
scenario_discard(void)
{
	int fds[2], fd, rc, i;

	pair(fds);
	fd = open("discard.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0);
	/* Nothing active or queued: the first step reports completion. */
	CHECK(dtrace_async_discard_step() == 1, "idle discard completes");
	rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup("discard.elf"),
	    "inbound", 0);
	CHECK(rc == ESHUTDOWN, "queue refuses after discard: %d", rc);
	for (i = 0; i < 3; i++)
		CHECK(dtrace_async_discard_step() == 1, "discard is terminal");
	close(fd);
	unlink("discard.elf");
	close(fds[0]);
	close(fds[1]);
}

/* ---------------------------------------------------------------- */
/* Consumer session handshake with connect() redirected.            */

static char redirect_path[sizeof (((struct sockaddr_un *)0)->sun_path)];

int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	static int (*real)(int, const struct sockaddr *, socklen_t);
	struct sockaddr_un alt;

	if (real == NULL)
		real = (int (*)(int, const struct sockaddr *, socklen_t))
		    dlsym(RTLD_NEXT, "connect");
	if (name->sa_family == AF_UNIX && redirect_path[0] != '\0' &&
	    strcmp(((const struct sockaddr_un *)name)->sun_path,
	    DTRACED_SOCKPATH) == 0) {
		memset(&alt, 0, sizeof (alt));
		alt.sun_family = AF_UNIX;
		strlcpy(alt.sun_path, redirect_path, sizeof (alt.sun_path));
		alt.sun_len = SUN_LEN(&alt);
		return (real(s, (struct sockaddr *)&alt, alt.sun_len));
	}
	return (real(s, name, namelen));
}

/*
 * A real kernel cannot produce the malformed birth identities tested here, so
 * the process-descriptor birth identity is interposed by dtraced-client-shim.so
 * (preloaded): pdself() and pdopenpid(getpid()) (the ambient path; pdself is
 * capability-mode only) return a placeholder descriptor and only
 * PDIOC_GET_BIRTH_IDENTITY on it is answered with a scripted identity.
 */
enum birth { BIRTH_GOOD, BIRTH_PID, BIRTH_BADUSEC, BIRTH_ZERO, BIRTH_RESERVED };
#define	BIRTH_SEC	0x0102030405060708ULL
#define	BIRTH_USEC	123456ULL

static void
birth_set(int interposed, enum birth mode)
{
	void (*set)(int, int) = (void (*)(int, int))dlsym(RTLD_DEFAULT,
	    "dtc_birth_set");

	assert(set != NULL);
	set(interposed, (int)mode);
}

struct server {
	int lfd;
	int mode;		/* 0 valid hello, 1 wrong version, 2 close */
	dtd_initmsg_t client;
	int got_client;
};

static void *
serve(void *arg)
{
	struct server *sv = arg;
	dtd_initmsg_t hello = { 0 };
	size_t done;
	int fd = accept(sv->lfd, NULL, NULL);

	if (fd < 0)
		return (NULL);
	hello.kind = DTRACED_KIND_DTRACED;
	hello.protocol_version = DTRACED_PROTOCOL_VERSION + (sv->mode == 1);
	if (sv->mode != 2 && dtraced_wire_write_init(fd, &hello,
	    dtraced_io_deadline_after(5000), &done) == 0 && sv->mode == 0)
		sv->got_client = dtraced_wire_read_init(fd, &sv->client,
		    dtraced_io_deadline_after(5000), &done) == 0;
	close(fd);
	return (NULL);
}

static int
listen_at(const char *path)
{
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	unlink(path);
	strlcpy(a.sun_path, path, sizeof (a.sun_path));
	a.sun_len = SUN_LEN(&a);
	assert(fd >= 0 && bind(fd, (struct sockaddr *)&a, a.sun_len) == 0 &&
	    listen(fd, 4) == 0);
	return (fd);
}

/* "dtrace-<pid>-" then the little-endian bytes of start_sec, start_usec. */
static int
ident_exact(const char *ident)
{
	char want[DTRACED_FDIDENTLEN];
	size_t n;
	int i;

	n = snprintf(want, sizeof (want), "dtrace-%d-", (int)getpid());
	for (i = 0; i < 8; i++)
		n += snprintf(want + n, sizeof (want) - n, "%02x",
		    (unsigned)((BIRTH_SEC >> (8 * i)) & 0xff));
	for (i = 0; i < 8; i++)
		n += snprintf(want + n, sizeof (want) - n, "%02x",
		    (unsigned)((BIRTH_USEC >> (8 * i)) & 0xff));
	return (strcmp(ident, want) == 0);
}

static void
scenario_session(void)
{
	static const uint8_t zero[16];
	uint8_t session[16], kept[16];
	struct server sv = { 0 };
	pthread_t t;
	int fd, err;

	snprintf(redirect_path, sizeof (redirect_path), "%s/sub.sock",
	    getcwd(NULL, 0));
	birth_set(1, BIRTH_GOOD);

	/* A zero session id is replaced by a random nonzero one. */
	sv.lfd = listen_at(redirect_path);
	pthread_create(&t, NULL, serve, &sv);
	memset(session, 0, sizeof (session));
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	pthread_join(t, NULL);
	CHECK(fd >= 0 && sv.got_client, "handshake completes: fd %d errno %d "
	    "server saw client %d", fd, err, sv.got_client);
	CHECK(memcmp(session, zero, 16) != 0, "session id assigned");
	CHECK(sv.client.kind == DTRACED_KIND_CONSUMER &&
	    sv.client.protocol_version == DTRACED_PROTOCOL_VERSION &&
	    sv.client.subs == DTD_SUB_READDATA &&
	    memcmp(sv.client.session_id, session, 16) == 0 &&
	    ident_exact(sv.client.ident), "client hello: kind %d subs %ju "
	    "ident %.60s", sv.client.kind, (uintmax_t)sv.client.subs,
	    sv.client.ident);
	if (fd >= 0)
		close(fd);

	/* A caller's session id is kept across reconnects. */
	memcpy(kept, session, 16);
	memset(&sv.client, 0, sizeof (sv.client));
	sv.got_client = 0;
	pthread_create(&t, NULL, serve, &sv);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	pthread_join(t, NULL);
	CHECK(fd >= 0 && memcmp(session, kept, 16) == 0 &&
	    memcmp(sv.client.session_id, kept, 16) == 0, "session id kept");
	if (fd >= 0)
		close(fd);

	/* Malformed kernel birth identities are refused with EPROTO. */
	{
		static const enum birth bad[] = { BIRTH_PID, BIRTH_BADUSEC,
		    BIRTH_ZERO, BIRTH_RESERVED };
		size_t b;

		for (b = 0; b < sizeof (bad) / sizeof (bad[0]); b++) {
			birth_set(1, bad[b]);
			sv.got_client = 0;
			pthread_create(&t, NULL, serve, &sv);
			fd = open_dtraced_session(DTD_SUB_READDATA, session);
			err = errno;
			pthread_join(t, NULL);
			CHECK(fd == -1 && err == EPROTO && !sv.got_client,
			    "birth mode %d: fd %d err %d", (int)bad[b], fd,
			    err);
		}
		birth_set(1, BIRTH_GOOD);
	}

	/* A server hello with another protocol version is refused. */
	sv.mode = 1;
	pthread_create(&t, NULL, serve, &sv);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	pthread_join(t, NULL);
	CHECK(fd == -1 && err == EPROTO, "foreign hello: fd %d err %d", fd,
	    err);

	/* A server that closes before its hello. */
	sv.mode = 2;
	pthread_create(&t, NULL, serve, &sv);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	pthread_join(t, NULL);
	CHECK(fd == -1, "closed before hello");
	close(sv.lfd);
	unlink(redirect_path);

	/* No daemon listening. */
	CHECK(open_dtraced(DTD_SUB_READDATA) == -1 &&
	    (errno == ENOENT || errno == ECONNREFUSED), "no daemon");
	CHECK(open_dtraced_session(DTD_SUB_READDATA, NULL) == -1 &&
	    errno == EINVAL, "NULL session id");
}

int
main(int argc, char **argv)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} scenarios[] = {
		{ "message", scenario_message },
		{ "elf", scenario_elf },
		{ "envelope", scenario_envelope },
		{ "async", scenario_async },
		{ "discard", scenario_discard },
		{ "session", scenario_session },
	};
	size_t i;

	if (argc != 2)
		return (2);
	/* As in dtrace(1): a peer that vanishes must yield EPIPE, not a signal. */
	signal(SIGPIPE, SIG_IGN);
	for (i = 0; i < sizeof (scenarios) / sizeof (scenarios[0]); i++) {
		if (strcmp(argv[1], scenarios[i].name) != 0)
			continue;
		scenarios[i].fn();
		printf("%s: %d checks, %d failures\n", argv[1], checks,
		    failures);
		return (failures != 0 || checks == 0);
	}
	return (2);
}
