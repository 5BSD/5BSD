/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The GDB server's migration interface (original gdb.c, production flags):
 * the migration fence, unfence and retirement, connection admission under
 * the fence, and the dirty-page marking of every guest-memory write the
 * debugger makes (memory writes and software breakpoints).
 *
 * gdb.c is included so its connection state can be arranged directly; the
 * remote protocol is driven through the original handle_command() and
 * new_connection().  Guest memory is a host buffer (RAM at [0, 64 KiB) and
 * [1 MiB, 1 MiB + 64 KiB), MMIO elsewhere); address translation is the
 * identity except for a faulting and a failing range.
 *
 * Oracles: the fence is granted exactly when no client, breakpoint, held vCPU
 * or pending step/breakpoint event exists, and its reason names the first
 * blocker in the documented order; a fenced server refuses connections and a
 * retired one never unfences; after any debugger write the set of dirty-marked
 * guest-physical bytes equals exactly the set of RAM bytes written (MMIO
 * writes are not marked), and a marking failure is reported to the migration
 * layer.
 */
#include "gdb.c"

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)
static int checks;
#define OK(x) do { CHECK(x); checks++; } while (0)

/* ------------------------------------------------------------ fakes */
struct vmctx { int unused; };
struct vcpu { int id; };
static struct vmctx fake_ctx;
static struct vcpu fake_vcpus[2] = { { 0 }, { 1 } };
int guest_ncpus = 2;

#define RAM_LO 0x0UL
#define RAM_HI 0x100000UL
#define RAM_SIZE 0x10000UL
static uint8_t ram_lo[RAM_SIZE], ram_hi[RAM_SIZE];
static uint8_t dirty[2][RAM_SIZE];	/* bytes marked dirty per RAM range */
static int mark_calls, mark_error, fail_calls, fail_error;
static struct { uint64_t gpa; uint64_t val; int bytes; } mmio[64];
static int nmmio;
static int64_t mmio_fail_gpa = -1;
static int cap_fail, cap_calls_enable, cap_calls_disable;

void *
paddr_guest2host(struct vmctx *c, uintptr_t gpa, size_t len)
{
	(void)c;
	if (gpa >= RAM_LO && gpa + len <= RAM_LO + RAM_SIZE)
		return (ram_lo + (gpa - RAM_LO));
	if (gpa >= RAM_HI && gpa + len <= RAM_HI + RAM_SIZE)
		return (ram_hi + (gpa - RAM_HI));
	return (NULL);
}

int
migration_dirty_mark(struct vmctx *c, uint64_t gpa, uint64_t len)
{
	CHECK(c == &fake_ctx);
	mark_calls++;
	for (uint64_t i = 0; i < len; i++) {
		uint64_t a = gpa + i;
		CHECK(paddr_guest2host(c, a, 1) != NULL);	/* never MMIO */
		if (a < RAM_LO + RAM_SIZE)
			dirty[0][a - RAM_LO] = 1;
		else
			dirty[1][a - RAM_HI] = 1;
	}
	return (mark_error);
}

void
migration_dirty_fail(struct vmctx *c, int error)
{
	CHECK(c == &fake_ctx);
	fail_calls++;
	fail_error = error;
}

int
write_mem(struct vcpu *v, uint64_t gpa, uint64_t val, int bytes)
{
	(void)v;
	if ((int64_t)gpa == mmio_fail_gpa)
		return (EIO);
	CHECK(nmmio < 64);
	mmio[nmmio].gpa = gpa;
	mmio[nmmio].val = val;
	mmio[nmmio].bytes = bytes;
	nmmio++;
	return (0);
}

int
read_mem(struct vcpu *v, uint64_t gpa, uint64_t *val, int bytes)
{
	(void)v;
	(void)bytes;
	*val = gpa;
	return (0);
}

int
vm_get_register_set(struct vcpu *v, unsigned int count, const int *regnums, uint64_t *regvals)
{
	(void)v;
	for (unsigned int i = 0; i < count; i++) {
		switch (regnums[i]) {
		case VM_REG_GUEST_CR0: regvals[i] = CR0_PE | CR0_PG; break;
		case VM_REG_GUEST_CR4: regvals[i] = CR4_PAE; break;
		case VM_REG_GUEST_EFER: regvals[i] = EFER_LME | EFER_LMA; break;
		default: regvals[i] = 0x1000 * (uint64_t)regnums[i]; break;
		}
	}
	return (0);
}

/* Identity translation; [0x200000, 0x201000) faults; 0x300000 fails. */
int
vm_gla2gpa_nofault(struct vcpu *v, struct vm_guest_paging *p, uint64_t gla, int prot,
    uint64_t *gpa, int *fault)
{
	(void)v;
	(void)prot;
	CHECK(p->cpu_mode == CPU_MODE_64BIT && p->paging_mode == PAGING_MODE_64 && p->cpl == 0);
	if (gla >= 0x300000 && gla < 0x301000) {
		errno = EIO;
		return (-1);
	}
	*fault = gla >= 0x200000 && gla < 0x201000;
	*gpa = gla;
	return (0);
}

int vm_set_capability(struct vcpu *v, enum vm_cap_type c, int val)
{ (void)v; (void)c; if (val) cap_calls_enable++; else cap_calls_disable++;
  return (cap_fail ? (errno = ENOENT, -1) : 0); }
int vm_get_capability(struct vcpu *v, enum vm_cap_type c, int *val)
{ (void)v; (void)c; *val = 0; return (cap_fail ? (errno = ENOENT, -1) : 0); }
int vm_suspend_all_cpus(struct vmctx *c) { (void)c; return (0); }
int vm_resume_all_cpus(struct vmctx *c) { (void)c; return (0); }
int vm_suspend_cpu(struct vcpu *v) { (void)v; return (0); }
int vm_resume_cpu(struct vcpu *v) { (void)v; return (0); }

static int fake_event, mevent_fail_on;	/* fail the n-th mevent_add (1-based) */
struct mevent *mevent_add(int fd, enum ev_type t, void (*f)(int, enum ev_type, void *), void *a)
{
	(void)fd; (void)t; (void)f; (void)a;
	if (mevent_fail_on > 0 && --mevent_fail_on == 0)
		return (NULL);
	return ((struct mevent *)&fake_event);
}
static int setsockopt_fail;
int __real_setsockopt(int, int, int, const void *, socklen_t);
int __wrap_setsockopt(int s, int l, int n, const void *v, socklen_t len)
{
	if (setsockopt_fail) { errno = ENOPROTOOPT; return (-1); }
	return (__real_setsockopt(s, l, n, v, len));
}
int mevent_delete(struct mevent *e) { (void)e; return (0); }
int mevent_delete_close(struct mevent *e) { (void)e; return (0); }
int mevent_enable(struct mevent *e) { (void)e; return (0); }
int mevent_disable(struct mevent *e) { (void)e; return (0); }

/* Allocation failure injection (gdb.c is linked with --wrap=malloc,calloc). */
static int malloc_fail, calloc_fail;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *
__wrap_malloc(size_t n)
{
	if (malloc_fail > 0 && --malloc_fail == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(n));
}
void *
__wrap_calloc(size_t a, size_t b)
{
	if (calloc_fail > 0 && --calloc_fail == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(a, b));
}

static char gdb_port[16];
const char *
get_config_value(const char *path)
{
	if (strcmp(path, "gdb.port") == 0)
		return (gdb_port);
	return (NULL);
}
bool
get_config_bool_default(const char *path, bool def)
{
	(void)path;
	return (def);
}

/* ---------------------------------------------------------- helpers */
static char reply[4096];

/* Run one remote command and return the response payload. */
static const char *
command(const char *packet)
{
	const uint8_t *p;
	size_t len;
	char *hash;

	io_buffer_reset(&cur_resp);
	pthread_mutex_lock(&gdb_lock);
	handle_command((const uint8_t *)packet, strlen(packet));
	pthread_mutex_unlock(&gdb_lock);
	p = io_buffer_head(&cur_resp);
	len = cur_resp.len;
	reply[0] = '\0';
	if (len > 0) {
		const uint8_t *dollar = memchr(p, '$', len);
		CHECK(dollar != NULL);
		snprintf(reply, sizeof(reply), "%.*s", (int)(len - (size_t)(dollar + 1 - p)),
		    (const char *)dollar + 1);
		hash = strchr(reply, '#');
		CHECK(hash != NULL);
		*hash = '\0';
	}
	io_buffer_reset(&cur_resp);
	return (reply);
}

static void
clear_dirty(void)
{
	memset(dirty, 0, sizeof(dirty));
	mark_calls = 0;
	fail_calls = 0;
	nmmio = 0;
}

/* Dirty set equals exactly [gpa, gpa + len) intersected with RAM. */
static bool
dirty_is(uint64_t gpa, size_t len)
{
	for (int r = 0; r < 2; r++)
		for (uint64_t i = 0; i < RAM_SIZE; i++) {
			uint64_t a = (r == 0 ? RAM_LO : RAM_HI) + i;
			bool want = a >= gpa && a < gpa + len;
			if (dirty[r][i] != want)
				return (false);
		}
	return (true);
}

static void
hexify(char *out, const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", data[i]);
}

static void
setup(void)
{
	ctx = &fake_ctx;
	guest_ncpus = 2;
	vcpus = calloc(2, sizeof(*vcpus));
	vcpus[0] = &fake_vcpus[0];
	vcpus[1] = &fake_vcpus[1];
	vcpu_state = calloc(2, sizeof(*vcpu_state));
	TAILQ_INIT(&breakpoints);
	gdb_active = true;
	cur_fd = -1;
	CPU_SET(0, &vcpus_active);
	CPU_SET(1, &vcpus_active);
}

/* ------------------------------------------------------------ tests */
static void
test_fence(void)
{
	const char *reason;
	int before = checks;

	gdb_active = false;
	OK(gdb_migration_fence(&reason) == 0 && reason == NULL);
	gdb_migration_unfence();
	gdb_migration_retire();
	OK(!gdb_migration_fenced && !gdb_migration_retired);
	gdb_active = true;

	/* Each blocker in order. */
	cur_fd = 7;
	OK(gdb_migration_fence(&reason) == EBUSY && strcmp(reason, "a GDB client is attached") == 0);
	cur_fd = -1;
	{
		struct breakpoint bp = { .gpa = 0x10 };
		TAILQ_INSERT_TAIL(&breakpoints, &bp, link);
		OK(gdb_migration_fence(&reason) == EBUSY &&
		    strcmp(reason, "GDB software breakpoints are installed in guest memory") == 0);
		TAILQ_REMOVE(&breakpoints, &bp, link);
	}
	CPU_SET(1, &vcpus_suspended);
	OK(gdb_migration_fence(&reason) == EBUSY &&
	    strcmp(reason, "a vCPU is held by the GDB server") == 0);
	CPU_ZERO(&vcpus_suspended);
	CPU_SET(0, &vcpus_waiting);
	OK(gdb_migration_fence(&reason) == EBUSY &&
	    strcmp(reason, "a vCPU is held by the GDB server") == 0);
	CPU_ZERO(&vcpus_waiting);
	for (int field = 0; field < 3; field++) {
		memset(vcpu_state, 0, 2 * sizeof(*vcpu_state));
		if (field == 0) vcpu_state[1].stepping = true;
		if (field == 1) vcpu_state[1].stepped = true;
		if (field == 2) vcpu_state[0].hit_swbreak = true;
		OK(gdb_migration_fence(&reason) == EBUSY &&
		    strcmp(reason, "a GDB single-step or breakpoint event is pending") == 0);
		OK(!gdb_migration_fenced);
	}
	memset(vcpu_state, 0, 2 * sizeof(*vcpu_state));
	OK(gdb_migration_fence(&reason) == 0 && reason == NULL && gdb_migration_fenced);
	OK(gdb_migration_fence(&reason) == EBUSY &&
	    strcmp(reason, "the GDB server is already fenced by a migration") == 0);
	gdb_migration_unfence();
	OK(!gdb_migration_fenced);
	OK(gdb_migration_fence(&reason) == 0);
	gdb_migration_retire();
	OK(gdb_migration_retired && gdb_migration_fenced && ctx == NULL);
	gdb_migration_unfence();
	OK(gdb_migration_fenced);
	OK(gdb_migration_fence(&reason) == EBUSY &&
	    strcmp(reason, "the GDB server is already fenced by a migration") == 0);
	gdb_migration_retired = false;
	gdb_migration_fenced = false;
	ctx = &fake_ctx;
	printf("gdb fence: %d checks\n", checks - before);
}

static int
listener(void)
{
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_len = sizeof(sin),
	    .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int s = socket(AF_INET, SOCK_STREAM, 0);
	socklen_t len = sizeof(sin);

	CHECK(s >= 0 && bind(s, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
	    listen(s, 4) == 0 && getsockname(s, (struct sockaddr *)&sin, &len) == 0);
	return (s);
}

static int
client_of(int l)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int c = socket(AF_INET, SOCK_STREAM, 0);

	CHECK(getsockname(l, (struct sockaddr *)&sin, &len) == 0);
	CHECK(c >= 0 && connect(c, (struct sockaddr *)&sin, len) == 0);
	return (c);
}

static void
test_connections(void)
{
	const char *reason;
	int l = listener(), c, before = checks;
	char byte;

	/* Fenced: refused and closed; no client recorded. */
	OK(gdb_migration_fence(&reason) == 0);
	c = client_of(l);
	new_connection(l, EVF_READ, NULL);
	OK(cur_fd == -1 && read(c, &byte, 1) == 0);
	close(c);
	/* Unfenced: admitted, the guest is stopped for the debugger and a
	 * second client is ignored; the attached client blocks the fence. */
	gdb_migration_unfence();
	c = client_of(l);
	new_connection(l, EVF_READ, NULL);
	OK(cur_fd >= 0);
	{
		int c2 = client_of(l);
		int admitted = cur_fd;
		new_connection(l, EVF_READ, NULL);
		OK(cur_fd == admitted && read(c2, &byte, 1) == 0);
		close(c2);
	}
	OK(gdb_migration_fence(&reason) == EBUSY &&
	    strcmp(reason, "a GDB client is attached") == 0);
	close_connection();
	OK(cur_fd == -1);
	close(c);
	/* Accept failures after startup are silent; at startup they are fatal. */
	{
		int bad = open("/dev/null", O_RDONLY);
		new_connection(bad, EVF_READ, NULL);
		OK(cur_fd == -1);
		pid_t p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			new_connection(bad, EVF_READ, (void *)1);
			_exit(0);
		}
		int st;
		CHECK(waitpid(p, &st, 0) == p);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 1);
		close(bad);
	}
	/* A connection whose SIGPIPE cannot be disabled, or whose read or
	 * write event cannot be registered, is closed and not recorded; at
	 * startup the event failures are fatal (exit 1). */
	for (int k = 0; k < 3; k++) {
		c = client_of(l);
		if (k == 0)
			setsockopt_fail = 1;
		else
			mevent_fail_on = k;
		new_connection(l, EVF_READ, NULL);
		setsockopt_fail = 0;
		mevent_fail_on = 0;
		OK(cur_fd == -1);
		if (k == 0)
			OK(read(c, &byte, 1) == 0);
		close(c);
	}
	for (int k = 1; k <= 2; k++) {
		pid_t p;
		int st;
		c = client_of(l);
		fflush(stdout);
		p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			mevent_fail_on = k;
			new_connection(l, EVF_READ, (void *)1);
			_exit(0);
		}
		CHECK(waitpid(p, &st, 0) == p);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 1);
		close(c);
	}
	close(l);
	printf("gdb connection admission: %d checks\n", checks - before);
}

static void
test_memory_writes(void)
{
	char packet[8192], hex[4096];
	uint8_t data[1500];
	int before = checks;

	cur_fd = 99;	/* responses are read from the buffer */
	for (size_t i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 13 + 1);

	/* A write within one page. */
	clear_dirty();
	hexify(hex, data, 100);
	snprintf(packet, sizeof(packet), "M%x,%x:%s", 0x1234, 100, hex);
	OK(strcmp(command(packet), "OK") == 0);
	OK(memcmp(ram_lo + 0x1234, data, 100) == 0 && dirty_is(0x1234, 100) && mark_calls == 1);
	/* Across a page boundary: one marking per page piece. */
	clear_dirty();
	hexify(hex, data, 1500);
	snprintf(packet, sizeof(packet), "M%x,%x:%s", 0x2e00, 1500, hex);
	OK(strcmp(command(packet), "OK") == 0);
	OK(memcmp(ram_lo + 0x2e00, data, 1500) == 0 && dirty_is(0x2e00, 1500) && mark_calls == 2);
	/* High RAM. */
	clear_dirty();
	hexify(hex, data, 8);
	snprintf(packet, sizeof(packet), "M%lx,%x:%s", RAM_HI + 0xff8, 8, hex);
	OK(strcmp(command(packet), "OK") == 0 && dirty_is(RAM_HI + 0xff8, 8));
	/* MMIO: aligned word writes of the little-endian guest values the
	 * byte sequence encodes; nothing marked dirty. */
	clear_dirty();
	snprintf(packet, sizeof(packet), "M%lx,%x:%s", 0xfee00001UL, 7, "11223344556677");
	OK(strcmp(command(packet), "OK") == 0 && mark_calls == 0 && dirty_is(0, 0));
	OK(nmmio == 3 && mmio[0].bytes == 1 && mmio[0].val == 0x11 &&
	    mmio[1].bytes == 2 && mmio[1].val == 0x3322 &&
	    mmio[2].bytes == 4 && mmio[2].val == 0x77665544);
	/* A write running from RAM into MMIO marks only the RAM part. */
	clear_dirty();
	hexify(hex, data, 32);
	snprintf(packet, sizeof(packet), "M%lx,%x:%s", RAM_SIZE - 16, 32, hex);
	OK(strcmp(command(packet), "OK") == 0 && dirty_is(RAM_SIZE - 16, 16) && nmmio == 4);
	/* A failed dirty mark is reported to migration; the write stands. */
	clear_dirty();
	mark_error = ENOMEM;
	snprintf(packet, sizeof(packet), "M%x,%x:%s", 0x100, 2, "abcd");
	OK(strcmp(command(packet), "OK") == 0 && fail_calls == 1 && fail_error == ENOMEM &&
	    ram_lo[0x100] == 0xab);
	mark_error = 0;
	/* Malformed and failing writes change nothing. */
	clear_dirty();
	OK(strcmp(command("M100"), "E16") == 0);
	OK(strcmp(command("M,4:00000000"), "E16") == 0);
	OK(strcmp(command("M100,"), "E16") == 0);
	OK(strcmp(command("M100,:00"), "E16") == 0);
	OK(strcmp(command("M100,2:abc"), "E16") == 0);
	OK(strcmp(command("M100,3:abcd"), "E16") == 0);
	OK(strcmp(command("Mffffffffffffffff,ffffffffffffffff:00"), "E16") == 0);
	OK(strcmp(command("M200000,1:00"), "E0e") == 0);	/* translation fault */
	OK(strcmp(command("M300000,1:00"), "E05") == 0);	/* translation failure */
	/* A two-byte MMIO write at a four-byte-aligned address is one 16-bit
	 * access, in guest (big-endian hex) byte order. */
	nmmio = 0;
	OK(strcmp(command("Mfee00020,2:1234"), "OK") == 0 && nmmio == 1 &&
	    mmio[0].gpa == 0xfee00020 && mmio[0].bytes == 2 && mmio[0].val == 0x3412);
	mmio_fail_gpa = 0xfee00010;
	OK(strcmp(command("Mfee00010,1:00"), "E0e") == 0);
	mmio_fail_gpa = -1;
	OK(mark_calls == 0 && dirty_is(0, 0));
	printf("gdb memory writes and dirty marking: %d checks\n", checks - before);
}

static void
test_breakpoints(void)
{
	const char *reason;
	int before = checks;
	uint8_t original;

	clear_dirty();
	ram_lo[0x4000] = 0x90;
	original = ram_lo[0x4000];
	OK(strcmp(command("Z0,4000,1"), "OK") == 0);
	OK(ram_lo[0x4000] == 0xcc && dirty_is(0x4000, 1) && !TAILQ_EMPTY(&breakpoints));
	OK(gdb_migration_fence(&reason) == EBUSY);	/* client attached */
	clear_dirty();
	OK(strcmp(command("Z0,4000,1"), "OK") == 0 && mark_calls == 0);	/* idempotent */
	OK(strcmp(command("Z0,4000,2"), "E16") == 0);
	OK(strcmp(command("Z0,200000,1"), "E0e") == 0);
	OK(strcmp(command("Z0,300000,1"), "E05") == 0);
	OK(strcmp(command("Z0,fee00000,1"), "E0e") == 0);	/* MMIO refused */
	OK(strcmp(command("z0,4000,1"), "OK") == 0);
	OK(ram_lo[0x4000] == original && dirty_is(0x4000, 1) && TAILQ_EMPTY(&breakpoints));
	clear_dirty();
	OK(strcmp(command("z0,4000,1"), "OK") == 0 && mark_calls == 0);
	/* A failed dirty mark for a breakpoint write is reported to the
	 * migration layer; removing the first of two breakpoints keeps the
	 * second. */
	clear_dirty();
	mark_error = ENOMEM;
	OK(strcmp(command("Z0,4800,1"), "OK") == 0 && fail_calls == 1 && fail_error == ENOMEM);
	mark_error = 0;
	OK(strcmp(command("Z0,4900,1"), "OK") == 0);
	OK(strcmp(command("z0,4800,1"), "OK") == 0 && !TAILQ_EMPTY(&breakpoints) &&
	    TAILQ_FIRST(&breakpoints)->gpa == 0x4900);
	OK(strcmp(command("z0,4900,1"), "OK") == 0 && TAILQ_EMPTY(&breakpoints));
	/* Breakpoints are unsupported when the exit capability is missing. */
	cap_fail = 1;
	OK(strcmp(command("Z0,5000,1"), "") == 0 && TAILQ_EMPTY(&breakpoints));
	cap_fail = 0;
	/* Disconnecting removes every breakpoint and marks each restored
	 * instruction byte dirty. */
	OK(strcmp(command("Z0,5000,1"), "OK") == 0 && strcmp(command("Z0,100010,1"), "OK") == 0);
	clear_dirty();
	pthread_mutex_lock(&gdb_lock);
	close_connection_locked();
	pthread_mutex_unlock(&gdb_lock);
	OK(TAILQ_EMPTY(&breakpoints) && mark_calls == 2 && dirty[0][0x5000] && dirty[1][0x10] &&
	    ram_lo[0x5000] != 0xcc && ram_hi[0x10] != 0xcc);
	OK(gdb_migration_fence(&reason) == 0);
	gdb_migration_unfence();
	printf("gdb breakpoints and dirty marking: %d checks\n", checks - before);
}

/*
 * Allocation failures (regression: gdb.c used the results of malloc() and
 * calloc() unchecked).  A breakpoint whose record cannot be allocated is
 * refused with ENOMEM, leaves guest memory untouched and, being the first,
 * withdraws the breakpoint exits it enabled; a qSupported whose copy cannot
 * be allocated is answered ENOMEM; init_gdb() exits when it cannot allocate
 * its per-vCPU tables.
 */
static void
test_allocation_failures(void)
{
	int before = checks;

	clear_dirty();
	ram_lo[0x6000] = 0x90;
	cap_calls_enable = cap_calls_disable = 0;
	malloc_fail = 1;
	OK(strcmp(command("Z0,6000,1"), "E0c") == 0);
	OK(malloc_fail == 0 && ram_lo[0x6000] == 0x90 && mark_calls == 0 &&
	    TAILQ_EMPTY(&breakpoints));
	OK(cap_calls_enable == 2 && cap_calls_disable == 2);
	/* A later breakpoint failure leaves existing exits enabled. */
	OK(strcmp(command("Z0,6000,1"), "OK") == 0);
	cap_calls_enable = cap_calls_disable = 0;
	malloc_fail = 1;
	OK(strcmp(command("Z0,7000,1"), "E0c") == 0 && cap_calls_disable == 0);
	OK(strcmp(command("z0,6000,1"), "OK") == 0 && TAILQ_EMPTY(&breakpoints) &&
	    ram_lo[0x6000] == 0x90);
	malloc_fail = 1;
	OK(strcmp(command("qSupported:swbreak+;xmlRegisters=i386"), "E0c") == 0);
	OK(strncmp(command("qSupported:swbreak+"), "PacketSize=", 11) == 0);
	for (int which = 1; which <= 2; which++) {
		int pipefd[2], status;
		char text[256] = "";
		pid_t pid;

		CHECK(pipe(pipefd) == 0);
		pid = fork();
		CHECK(pid >= 0);
		if (pid == 0) {
			int listener = socket(AF_INET, SOCK_STREAM, 0);
			struct sockaddr_in sin = { .sin_family = AF_INET,
			    .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
			socklen_t sl = sizeof(sin);

			/* Pick a free loopback port for init_gdb() to bind. */
			CHECK(bind(listener, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
			    getsockname(listener, (struct sockaddr *)&sin, &sl) == 0);
			snprintf(gdb_port, sizeof(gdb_port), "%u", ntohs(sin.sin_port));
			close(listener);
			dup2(pipefd[1], STDERR_FILENO);
			calloc_fail = which;
			init_gdb(&fake_ctx);
			exit(0);	/* not reached */
		}
		close(pipefd[1]);
		{
			size_t got = 0;
			ssize_t n;
			while (got < sizeof(text) - 1 &&
			    (n = read(pipefd[0], text + got, sizeof(text) - 1 - got)) > 0)
				got += (size_t)n;
			text[got] = '\0';
		}
		close(pipefd[0]);
		CHECK(waitpid(pid, &status, 0) == pid);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 4 ||
		    strstr(text, "Failed to allocate memory") == NULL)
			fprintf(stderr, "init_gdb child %d: status %#x: %s\n", which, status, text);
		OK(WIFEXITED(status) && WEXITSTATUS(status) == 4 &&
		    strstr(text, "Failed to allocate memory") != NULL);
	}
	printf("gdb allocation failures: %d checks\n", checks - before);
}

int
main(void)
{
	signal(SIGPIPE, SIG_IGN);
	setup();
	test_fence();
	test_connections();
	test_memory_writes();
	test_breakpoints();
	test_allocation_failures();
	printf("PASS: %d gdb checks\n", checks);
	return (0);
}
