/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue jail-confinement test.  squeue is a local resource (like kqueue),
 * jailed via the kern_* primitives its opcodes delegate to.  This verifies a
 * process inside a jail can create and drive a ring (NOP, and a WRITE/READ
 * round-trip on a file within the jail root), i.e. the engine works and stays
 * confined.  jail_attach() is irreversible, so the ring work runs in a child.
 * Exit status = failing check number, 0 = ok.
 */
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/jail.h>
#include <sys/syscall.h>
#include <sys/io_uring.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	OP_NOP		0
#define	OP_WRITE	23
#define	OP_READ		22
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL

static int ring_fd;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi;

static int
ring_init(uint32_t entries)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
	r = syscall(SYS_squeue_setup, entries, &p);
	if (r < 0)
		return (-1);
	ring_fd = (int)r;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > ringsz)
		ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	sqbase = mmap(NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQ_RING);
	if (sqbase == MAP_FAILED)
		return (-1);
	sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	sqes = mmap(NULL, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQES);
	if (sqes == MAP_FAILED)
		return (-1);
	sq_tail = (volatile uint32_t *)(sqbase + p.sq_off.tail);
	sq_array = (volatile uint32_t *)(sqbase + p.sq_off.array);
	cq_head = (volatile uint32_t *)(sqbase + p.cq_off.head);
	cq_tail = (volatile uint32_t *)(sqbase + p.cq_off.tail);
	cqes = (struct io_uring_cqe *)(sqbase + p.cq_off.cqes);
	sqmask = p.sq_entries - 1;
	cqmask = p.cq_entries - 1;
	sqi = cqi = 0;
	return (0);
}

static int
one(uint8_t op, int fd, void *addr, uint32_t len, uint64_t off, uint64_t ud)
{
	uint32_t slot = sqi & sqmask;
	long r;

	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = op;
	sqes[slot].fd = fd;
	sqes[slot].addr = (uint64_t)(uintptr_t)addr;
	sqes[slot].len = len;
	sqes[slot].off = off;
	sqes[slot].user_data = ud;
	sq_array[sqi & sqmask] = slot;
	sqi++;
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_squeue_enter, ring_fd, 1, 1, 1 /*GETEVENTS*/, NULL, 0);
	if (r != 1)
		return (-100000);
	r = cqes[cqi & cqmask].res;
	cqi++;
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return ((int)r);
}

static int
mkiov(struct iovec *iov, const char *key, void *val, size_t vlen)
{
	iov[0].iov_base = (void *)(uintptr_t)key;
	iov[0].iov_len = strlen(key) + 1;
	iov[1].iov_base = val;
	iov[1].iov_len = vlen;
	return (2);
}

int
main(void)
{
	struct iovec iov[6];
	int jid, n;
	pid_t pid;
	char path[] = "/";
	char name[] = "squeuejail";

	/* create a persistent jail rooted at / */
	n = 0;
	n += mkiov(&iov[n], "path", path, sizeof(path));
	n += mkiov(&iov[n], "name", name, sizeof(name));
	n += mkiov(&iov[n], "persist", NULL, 0);
	jid = jail_set(iov, n, JAIL_CREATE);
	if (jid < 0)
		return (1);

	pid = fork();
	if (pid == 0) {
		char wbuf[8], rbuf[8];
		int fd;

		if (jail_attach(jid) != 0)
			_exit(11);
		/* the ring engine must work inside the jail */
		if (ring_init(8) != 0)
			_exit(12);
		if (one(OP_NOP, -1, NULL, 0, 0, 0x1) != 0)
			_exit(13);
		(void)unlink("/tmp/squeue_jail.tmp");
		fd = open("/tmp/squeue_jail.tmp", O_RDWR | O_CREAT | O_EXCL,
		    0600);
		if (fd < 0)
			_exit(14);
		memcpy(wbuf, "jailed!", 7);
		if (one(OP_WRITE, fd, wbuf, 7, 0, 0x2) != 7)
			_exit(15);
		memset(rbuf, 0, sizeof(rbuf));
		if (one(OP_READ, fd, rbuf, 7, 0, 0x3) != 7 ||
		    memcmp(rbuf, "jailed!", 7) != 0)
			_exit(16);
		(void)close(fd);
		(void)unlink("/tmp/squeue_jail.tmp");
		_exit(0);
	} else if (pid < 0) {
		(void)jail_remove(jid);
		return (2);
	} else {
		int st, rc = 0;

		if (waitpid(pid, &st, 0) != pid)
			rc = 3;
		else if (!WIFEXITED(st))
			rc = 4;
		else if (WEXITSTATUS(st) != 0)
			rc = WEXITSTATUS(st);
		(void)jail_remove(jid);
		return (rc);
	}
}
