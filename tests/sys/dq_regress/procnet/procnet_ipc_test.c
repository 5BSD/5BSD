/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Named IPC as processes that are NOT attached to a dq(4) controller see
 * it today (dq-boundary design, part b0, section 6.1 items 10, 14, 18).
 *
 * The boundary closes named IPC (POSIX shared memory, named semaphores,
 * message queues, the three System V families) between a confinement and
 * the rest of the system, by name and in every listing.  For processes
 * nothing is attached to, every name, id, listing and errno below must
 * stay what it is: the rows are what the kernel of commit f52f6da3d34
 * does, recorded by running this program on it.  The slices that touch
 * these paths are b6a (POSIX) and b6b (System V); no row here is expected
 * to change at any slice.
 *
 * Each case runs its rows in children that have dropped to an
 * unprivileged uid and are not each other's parent.  A row prints its
 * name, what it got and what is recorded; a child exits with the number
 * of rows that differ.
 */

/* The listing sysctls are arrays of the kernel's structures. */
#define	_WANT_SYSVSHM_INTERNALS
#define	_WANT_SYSVSEM_INTERNALS
#define	_WANT_SYSVMSG_INTERNALS

#include <sys/param.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dirent.h>
#include <mqueue.h>
#include <semaphore.h>
#include <time.h>

#include "procnet_common.h"

static int	nbad;

#define	R(name, got, want) do {						\
	long _g = (long)(got), _w = (long)(want);			\
	printf("%-58s got %ld want %ld%s\n", (name), _g, _w,		\
	    _g == _w ? "" : "  <== FAIL");				\
	if (_g != _w)							\
		nbad++;							\
} while (0)

/* Run fn in a child as PN_UID; its exit status is its count of bad rows. */
static void
rows_child(int (*fn)(void *), void *arg, const char *what)
{
	int e;

	(void)fflush(stdout);
	e = pn_child(fn, arg, PN_UID, PN_GID);
	ATF_CHECK_MSG(e == 0, "%s: %d (rows on stdout; from %d up a harness "
	    "failure)", what, e, PN_X_BASE);
}

#define	DONE()	do {							\
	(void)fflush(stdout);						\
	return (nbad > 100 ? 100 : nbad);				\
} while (0)

/* Names and keys unique to a run of a case. */
static char	nm_shm[64], nm_shm2[64], nm_sem[64], nm_mq[64];
static key_t	key_shm, key_sem, key_msg;

static void
names_of(const char *tag, int pid)
{

	(void)snprintf(nm_shm, sizeof(nm_shm), "/pn_%s_shm_%d", tag, pid);
	(void)snprintf(nm_shm2, sizeof(nm_shm2), "/pn_%s_shm2_%d", tag, pid);
	(void)snprintf(nm_sem, sizeof(nm_sem), "/pn_%s_sem_%d", tag, pid);
	(void)snprintf(nm_mq, sizeof(nm_mq), "/pn_%s_mq_%d", tag, pid);
	key_shm = 0x504e0000 | (pid & 0xffff);
	key_sem = 0x504f0000 | (pid & 0xffff);
	key_msg = 0x50500000 | (pid & 0xffff);
}

static void	sweep(void);

/* The names of this body, and a note of its pid for the cleanup. */
static void
names(const char *tag)
{
	FILE *f;

	names_of(tag, (int)getpid());
	f = fopen("names.pid", "w");
	ATF_REQUIRE(f != NULL);
	(void)fprintf(f, "%d\n", (int)getpid());
	ATF_REQUIRE_EQ(0, fclose(f));
}

/* The cleanup part: the names of the body that left the note. */
static void
names_cleanup(const char *tag)
{
	FILE *f;
	int pid;

	f = fopen("names.pid", "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d", &pid) == 1) {
		names_of(tag, pid);
		sweep();
	}
	(void)fclose(f);
}

/* Remove what a failed body may have left (as root; all best effort). */
static void
sweep(void)
{
	int id;

	(void)shm_unlink(nm_shm);
	(void)shm_unlink(nm_shm2);
	(void)sem_unlink(nm_sem);
	(void)mq_unlink(nm_mq);
	if ((id = shmget(key_shm, 0, 0)) != -1)
		(void)shmctl(id, IPC_RMID, NULL);
	if ((id = semget(key_sem, 0, 0)) != -1)
		(void)semctl(id, 0, IPC_RMID);
	if ((id = msgget(key_msg, 0)) != -1)
		(void)msgctl(id, IPC_RMID, NULL);
}

/* Is a POSIX shm object of this name in kern.ipc.posix_shm_list? */
static int
shm_listed(const char *name)
{
	struct kinfo_file *kf;
	char *buf;
	size_t len, off;
	int found;

	len = 0;
	if (sysctlbyname("kern.ipc.posix_shm_list", NULL, &len, NULL, 0) != 0)
		return (-errno);
	len += 64 * 1024;
	buf = malloc(len);
	if (buf == NULL)
		return (-ENOMEM);
	if (sysctlbyname("kern.ipc.posix_shm_list", buf, &len, NULL, 0) != 0) {
		free(buf);
		return (-errno);
	}
	found = 0;
	for (off = 0; off < len; off += (size_t)kf->kf_structsize) {
		kf = (struct kinfo_file *)(void *)(buf + off);
		if (kf->kf_structsize == 0)
			break;
		if (strcmp(kf->kf_path, name) == 0)
			found++;
	}
	free(buf);
	return (found);
}

/* The slot of the System V object with this key in a listing, or -1. */
static int
sysv_listed(const char *oid, size_t entsize, size_t keyoff, key_t key,
    size_t modeoff, int allocbit)
{
	char *buf;
	size_t i, len;
	key_t k;
	unsigned short mode;
	int found;

	len = 0;
	if (sysctlbyname(oid, NULL, &len, NULL, 0) != 0)
		return (-errno - 1000);
	buf = malloc(len);
	if (buf == NULL)
		return (-ENOMEM - 1000);
	if (sysctlbyname(oid, buf, &len, NULL, 0) != 0) {
		free(buf);
		return (-errno - 1000);
	}
	found = -1;
	if (len % entsize != 0)
		found = -2;		/* not an array of the structure */
	else
		for (i = 0; i < len / entsize; i++) {
			memcpy(&k, buf + i * entsize + keyoff, sizeof(k));
			memcpy(&mode, buf + i * entsize + modeoff,
			    sizeof(mode));
			if (k == key && (mode & allocbit) != 0) {
				found = (int)i;
				break;
			}
		}
	free(buf);
	return (found);
}

#define	SHM_SLOT(k_)	sysv_listed("kern.ipc.shmsegs",			\
	sizeof(struct shmid_kernel),					\
	offsetof(struct shmid_kernel, u.shm_perm.key), (k_),		\
	offsetof(struct shmid_kernel, u.shm_perm.mode), 0x0800)
#define	SEM_SLOT(k_)	sysv_listed("kern.ipc.sema",			\
	sizeof(struct semid_kernel),					\
	offsetof(struct semid_kernel, u.sem_perm.key), (k_),		\
	offsetof(struct semid_kernel, u.sem_perm.mode), 0x0200)
#define	MSG_SLOT(k_)	(sysv_listed("kern.ipc.msqids",			\
	sizeof(struct msqid_kernel),					\
	offsetof(struct msqid_kernel, u.msg_perm.key), (k_),		\
	offsetof(struct msqid_kernel, u.msg_perm.mode), 0xffff) >= 0)

/* --- item 10: two processes of one uid share an object by name ---------- */

static int
share_make(void *arg __unused)
{
	struct { long mtype; char mtext[8]; } m;
	sem_t *s;
	mqd_t mq;
	char *p;
	int fd, id;

	nbad = 0;
	fd = shm_open(nm_shm, O_RDWR | O_CREAT | O_EXCL, 0600);
	R("shm_open(O_CREAT|O_EXCL)", fd == -1 ? errno : 0, 0);
	R("ftruncate", PN_ERR(ftruncate(fd, 4096)), 0);
	R("write", pwrite(fd, "posix", 5, 0), 5);
	R("kern.ipc.posix_shm_list has the name (maker)", shm_listed(nm_shm),
	    1);

	s = sem_open(nm_sem, O_CREAT | O_EXCL, 0600, 0);
	R("sem_open(O_CREAT|O_EXCL)", s == SEM_FAILED ? errno : 0, 0);
	if (s != SEM_FAILED)
		R("sem_post", PN_ERR(sem_post(s)), 0);

	mq = mq_open(nm_mq, O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
	R("mq_open(O_CREAT|O_EXCL)", mq == (mqd_t)-1 ? errno : 0, 0);
	if (mq != (mqd_t)-1)
		R("mq_send", PN_ERR(mq_send(mq, "mq", 2, 0)), 0);

	id = shmget(key_shm, 4096, IPC_CREAT | IPC_EXCL | 0600);
	R("shmget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	p = shmat(id, NULL, 0);
	R("shmat", p == (char *)-1 ? errno : 0, 0);
	if (p != (char *)-1)
		memcpy(p, "sysv", 4);

	id = semget(key_sem, 1, IPC_CREAT | IPC_EXCL | 0600);
	R("semget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	id = msgget(key_msg, IPC_CREAT | IPC_EXCL | 0600);
	R("msgget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	m.mtype = 1;
	memcpy(m.mtext, "msg", 3);
	R("msgsnd", PN_ERR(msgsnd(id, &m, 3, 0)), 0);
	DONE();
}

static int
share_use(void *arg __unused)
{
	struct { long mtype; char mtext[8]; } m;
	struct mq_attr attr;
	struct timespec ts;
	sem_t *s;
	mqd_t mq;
	char buf[8192], *p;
	int fd, id;

	nbad = 0;
	fd = shm_open(nm_shm, O_RDWR, 0);
	R("shm_open by the other process", fd == -1 ? errno : 0, 0);
	memset(buf, 0, sizeof(buf));
	R("pread", pread(fd, buf, 5, 0), 5);
	R("the bytes are the maker's", memcmp(buf, "posix", 5), 0);
	R("kern.ipc.posix_shm_list has the name (user)", shm_listed(nm_shm),
	    1);
	R("shm_open(O_CREAT|O_EXCL) of the name",
	    PN_ERR(shm_open(nm_shm, O_RDWR | O_CREAT | O_EXCL, 0600)), EEXIST);

	s = sem_open(nm_sem, 0);
	R("sem_open by the other process", s == SEM_FAILED ? errno : 0, 0);
	if (s != SEM_FAILED) {
		R("sem_trywait takes the maker's post",
		    PN_ERR(sem_trywait(s)), 0);
		R("sem_trywait again", PN_ERR(sem_trywait(s)), EAGAIN);
	}
	R("sem_unlink by the other process", PN_ERR(sem_unlink(nm_sem)), 0);
	R("sem_open after", sem_open(nm_sem, 0) == SEM_FAILED ? errno : 0,
	    ENOENT);

	mq = mq_open(nm_mq, O_RDWR);
	R("mq_open by the other process", mq == (mqd_t)-1 ? errno : 0, 0);
	if (mq != (mqd_t)-1) {
		R("mq_getattr", PN_ERR(mq_getattr(mq, &attr)), 0);
		R("mq_curmsgs", attr.mq_curmsgs, 1);
		(void)clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 10;
		R("mq_timedreceive", mq_timedreceive(mq, buf, sizeof(buf),
		    NULL, &ts), 2);
		R("the message is the maker's", memcmp(buf, "mq", 2), 0);
	}

	id = shmget(key_shm, 0, 0);
	R("shmget(key) by the other process", id == -1 ? errno : 0, 0);
	R("shmget(key, IPC_CREAT|IPC_EXCL)",
	    PN_ERR(shmget(key_shm, 4096, IPC_CREAT | IPC_EXCL | 0600)),
	    EEXIST);
	p = shmat(id, NULL, 0);
	R("shmat", p == (char *)-1 ? errno : 0, 0);
	if (p != (char *)-1)
		R("the bytes are the maker's", memcmp(p, "sysv", 4), 0);
	R("kern.ipc.shmsegs has the key", SHM_SLOT(key_shm) >= 0, 1);

	id = semget(key_sem, 0, 0);
	R("semget(key) by the other process", id == -1 ? errno : 0, 0);
	R("kern.ipc.sema has the key", SEM_SLOT(key_sem) >= 0, 1);
	id = msgget(key_msg, 0);
	R("msgget(key) by the other process", id == -1 ? errno : 0, 0);
	R("kern.ipc.msqids has the key", MSG_SLOT(key_msg), 1);
	memset(&m, 0, sizeof(m));
	R("msgrcv", msgrcv(id, &m, sizeof(m.mtext), 0, IPC_NOWAIT), 3);
	R("the message is the maker's", memcmp(m.mtext, "msg", 3), 0);
	DONE();
}

/*
 * Item 10.  One process makes a POSIX shared memory object, a named
 * semaphore, a POSIX message queue and a System V segment, semaphore set
 * and message queue; another process of the same uid, not related to it
 * but through the test, finds each by name or key, reads what the first
 * left, and sees each in its listing sysctl.
 */
ATF_TC_WITH_CLEANUP(named_ipc_shared);
ATF_TC_HEAD(named_ipc_shared, tc)
{
	atf_tc_set_md_var(tc, "descr", "Two unattached processes of one uid "
	    "share named IPC objects of every kind");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(named_ipc_shared, tc)
{

	names("share");
	sweep();
	rows_child(share_make, NULL, "maker");
	rows_child(share_use, NULL, "user");
	sweep();
}
ATF_TC_CLEANUP(named_ipc_shared, tc)
{
	/* A body that died half way did not sweep. */
	names_cleanup("share");
}

/* --- item 14: names, listings and lifetime ------------------------------ */

static char	mqfs[PATH_MAX];

/*
 * One getdirentries(2) call with a buffer larger than the listing, and no
 * second call.  Not readdir(3): mqfs_readdir() never sets *a_eofflag, so
 * the call that finds the end of the directory (it consumes nothing)
 * trips the VOP_READDIR post-condition of an INVARIANTS kernel and
 * panics, "VOP_READDIR: eofflag not set" (commit f52f6da3d34).  That is a
 * defect of the base kernel, reported with these pins and not pinned.
 */
static int
dir_has(const char *dir, const char *name)
{
	static char buf[256 * 1024];
	struct dirent *de;
	ssize_t n, off;
	int fd, found;

	fd = open(dir, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		return (-errno);
	n = getdirentries(fd, buf, sizeof(buf), NULL);
	if (n == -1) {
		found = -errno;
		(void)close(fd);
		return (found);
	}
	(void)close(fd);
	found = 0;
	for (off = 0; off < n; off += de->d_reclen) {
		de = (struct dirent *)(void *)(buf + off);
		if (de->d_reclen == 0)
			return (-EIO);
		if (strcmp(de->d_name, name) == 0)
			found++;
	}
	return (found);
}

static int
life_make(void *arg __unused)
{
	mqd_t mq;
	int fd;

	nbad = 0;
	fd = shm_open(nm_shm, O_RDWR | O_CREAT | O_EXCL, 0600);
	R("shm_open(O_CREAT|O_EXCL)", fd == -1 ? errno : 0, 0);
	mq = mq_open(nm_mq, O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
	R("mq_open(O_CREAT|O_EXCL)", mq == (mqd_t)-1 ? errno : 0, 0);
	DONE();
}

static int
life_use(void *arg __unused)
{
	struct shmid_ds ds;
	pid_t pid;
	char *p;
	int id, status;

	nbad = 0;
	R("mqueuefs lists the queue", dir_has(mqfs, nm_mq + 1), 1);
	R("mq_unlink by the other process", PN_ERR(mq_unlink(nm_mq)), 0);
	R("mqueuefs lists it after", dir_has(mqfs, nm_mq + 1), 0);
	R("mq_open after", mq_open(nm_mq, O_RDWR) == (mqd_t)-1 ? errno : 0,
	    ENOENT);
	R("mq_unlink again", PN_ERR(mq_unlink(nm_mq)), ENOENT);

	R("posix_shm_list has the name", shm_listed(nm_shm), 1);
	R("shm_rename by the other process",
	    PN_ERR(shm_rename(nm_shm, nm_shm2, 0)), 0);
	R("posix_shm_list has the old name", shm_listed(nm_shm), 0);
	R("posix_shm_list has the new name", shm_listed(nm_shm2), 1);
	R("shm_open of the old name", PN_ERR(shm_open(nm_shm, O_RDWR, 0)),
	    ENOENT);
	R("shm_rename of the old name again",
	    PN_ERR(shm_rename(nm_shm, nm_shm2, 0)), ENOENT);
	R("shm_unlink by the other process", PN_ERR(shm_unlink(nm_shm2)), 0);
	R("posix_shm_list has the new name after", shm_listed(nm_shm2), 0);
	R("shm_unlink again", PN_ERR(shm_unlink(nm_shm2)), ENOENT);

	/* A segment attached before fork: inherited, detached at exit. */
	id = shmget(key_shm, 4096, IPC_CREAT | IPC_EXCL | 0600);
	R("shmget", id == -1 ? errno : 0, 0);
	p = shmat(id, NULL, 0);
	R("shmat", p == (char *)-1 ? errno : 0, 0);
	if (p == (char *)-1)
		DONE();
	memcpy(p, "before", 6);
	R("IPC_STAT", PN_ERR(shmctl(id, IPC_STAT, &ds)), 0);
	R("shm_nattch before fork", ds.shm_nattch, 1);
	pid = fork();
	if (pid == 0) {
		if (memcmp(p, "before", 6) != 0 ||
		    shmctl(id, IPC_STAT, &ds) != 0)
			_exit(99);
		memcpy(p, "child!", 6);
		_exit((int)ds.shm_nattch);
	}
	R("waitpid", waitpid(pid, &status, 0) == pid && WIFEXITED(status), 1);
	R("shm_nattch in the fork", WEXITSTATUS(status), 2);
	R("the fork's write shows in the parent", memcmp(p, "child!", 6), 0);
	R("IPC_STAT", PN_ERR(shmctl(id, IPC_STAT, &ds)), 0);
	R("shm_nattch after the fork exits", ds.shm_nattch, 1);
	R("shm_lpid is the parent (the attach)", ds.shm_lpid == getpid(), 1);
	R("kern.ipc.shmsegs has the key", SHM_SLOT(key_shm) >= 0, 1);
	R("IPC_RMID", PN_ERR(shmctl(id, IPC_RMID, NULL)), 0);
	R("kern.ipc.shmsegs has the key after", SHM_SLOT(key_shm) >= 0, 0);
	DONE();
}

/*
 * Item 14.  Names and lifetime: the mqueuefs directory lists a queue and
 * loses it at mq_unlink; kern.ipc.posix_shm_list follows shm_rename and
 * shm_unlink, each done by a process other than the maker; a System V
 * segment attached before fork is attached in the child (shm_nattch 2)
 * and detached when the child exits.
 */
ATF_TC_WITH_CLEANUP(named_ipc_lifetime);
ATF_TC_HEAD(named_ipc_lifetime, tc)
{
	atf_tc_set_md_var(tc, "descr", "Named IPC listings follow unlink and "
	    "rename; a System V segment follows fork and exit");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(named_ipc_lifetime, tc)
{
	struct iovec iov[4];

	names("life");
	sweep();
	pn_pubdir("ipc_mqfs", mqfs, sizeof(mqfs));
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "mqueuefs");
	iov[1].iov_len = sizeof("mqueuefs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = mqfs;
	iov[3].iov_len = strlen(mqfs) + 1;
	ATF_REQUIRE_MSG(nmount(iov, nitems(iov), 0) == 0, "mount mqueuefs on "
	    "%s: %s", mqfs, strerror(errno));
	rows_child(life_make, NULL, "maker");
	rows_child(life_use, NULL, "user");
	sweep();
	ATF_CHECK_EQ(0, unmount(mqfs, 0));
}
ATF_TC_CLEANUP(named_ipc_lifetime, tc)
{
	names_cleanup("life");
	(void)unmount("/tmp/procnet.ipc_mqfs", MNT_FORCE);
	pn_pubdir_remove("ipc_mqfs");
}

/* --- item 18: System V, family by family -------------------------------- */

/* Wait (bounded) until pid sleeps on wmesg; 1 if it does. */
static int
sleeps_on(pid_t pid, const char *wmesg)
{
	struct kinfo_proc kp;
	struct timespec ts = { 0, 10 * 1000 * 1000 };
	size_t len;
	int i, mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

	for (i = 0; i < 2000; i++) {
		len = sizeof(kp);
		if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) != 0)
			return (-errno);
		if (kp.ki_stat == SSLEEP && strcmp(kp.ki_wmesg, wmesg) == 0)
			return (1);
		(void)nanosleep(&ts, NULL);
	}
	return (0);
}

/* The other end of a socket pair uses an id it is sent. */
static int
id_over_socket(int (*use)(int))
{
	pid_t pid;
	int id, sv[2], status;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return (-1);
	pid = fork();
	if (pid == 0) {
		if (read(sv[1], &id, sizeof(id)) != (ssize_t)sizeof(id))
			_exit(98);
		_exit(use(id));
	}
	id = use(-1);		/* -1: tell me the id to send */
	(void)write(sv[0], &id, sizeof(id));
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	(void)close(sv[0]);
	(void)close(sv[1]);
	return (WEXITSTATUS(status));
}

static int	priv_id;

static int
shm_use(int id)
{
	char *p;

	if (id == -1)
		return (priv_id);
	p = shmat(id, NULL, 0);
	if (p == (char *)-1)
		return (errno);
	return (memcmp(p, "priv", 4) == 0 ? 0 : 97);
}

static int
sysv_shm(void *arg __unused)
{
	struct shmid_ds ds;
	struct shminfo info;
	struct shm_info sinfo;
	char *p, *p2;
	int id, slot;

	nbad = 0;
	id = shmget(key_shm, 8192, IPC_CREAT | IPC_EXCL | 0640);
	R("shmget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	R("shmget(key, IPC_CREAT|IPC_EXCL) again",
	    PN_ERR(shmget(key_shm, 8192, IPC_CREAT | IPC_EXCL | 0640)),
	    EEXIST);
	R("shmget(key) is the same id", shmget(key_shm, 0, 0) == id, 1);
	R("shmget(key) with a larger size", PN_ERR(shmget(key_shm, 1 << 20,
	    0)), EINVAL);
	R("shmget(unused key)", PN_ERR(shmget(key_shm + 1, 0, 0)), ENOENT);

	R("IPC_STAT", PN_ERR(shmctl(id, IPC_STAT, &ds)), 0);
	R("  shm_segsz", ds.shm_segsz, 8192);
	R("  mode", ds.shm_perm.mode & 0777, 0640);
	R("  uid", ds.shm_perm.uid, PN_UID);
	R("  cuid", ds.shm_perm.cuid, PN_UID);
	R("  key", ds.shm_perm.key, key_shm);
	R("  shm_cpid is the caller", ds.shm_cpid == getpid(), 1);
	R("  shm_nattch", ds.shm_nattch, 0);
	ds.shm_perm.mode = 0600;
	R("IPC_SET", PN_ERR(shmctl(id, IPC_SET, &ds)), 0);
	R("IPC_STAT", PN_ERR(shmctl(id, IPC_STAT, &ds)), 0);
	R("  mode after IPC_SET", ds.shm_perm.mode & 0777, 0600);
	slot = SHM_SLOT(key_shm);
	R("kern.ipc.shmsegs has the key", slot >= 0, 1);
	memset(&ds, 0, sizeof(ds));
	/*
	 * The native shmctl(2) refuses the three commands that exist for
	 * the Linux ABI (sys_shmctl); linux_boundary_test has their rows.
	 */
	R("SHM_STAT by the listing's slot", PN_ERR(shmctl(slot, SHM_STAT,
	    &ds)), EINVAL);
	R("IPC_INFO", PN_ERR(shmctl(0, IPC_INFO, (void *)&info)), EINVAL);
	R("SHM_INFO", PN_ERR(shmctl(0, SHM_INFO, (void *)&sinfo)), EINVAL);
	R("SHM_LOCK", PN_ERR(shmctl(id, SHM_LOCK, NULL)), EINVAL);
	R("shmctl with no such command", PN_ERR(shmctl(id, 999, &ds)),
	    EINVAL);

	/* IPC_PRIVATE: the id is all another process needs. */
	priv_id = shmget(IPC_PRIVATE, 4096, 0600);
	R("shmget(IPC_PRIVATE)", priv_id == -1 ? errno : 0, 0);
	p = shmat(priv_id, NULL, 0);
	R("shmat", p == (char *)-1 ? errno : 0, 0);
	if (p != (char *)-1)
		memcpy(p, "priv", 4);
	R("an IPC_PRIVATE id sent over a socket attaches there",
	    id_over_socket(shm_use), 0);
	R("IPC_RMID", PN_ERR(shmctl(priv_id, IPC_RMID, NULL)), 0);

	/*
	 * IPC_RMID of a mapped segment: the key is gone at once; the
	 * mapping and the id live until the last detach
	 * (kern.ipc.shm_allow_removed is 1).
	 */
	p = shmat(id, NULL, 0);
	R("shmat", p == (char *)-1 ? errno : 0, 0);
	if (p != (char *)-1)
		memcpy(p, "live", 4);
	R("IPC_RMID while mapped", PN_ERR(shmctl(id, IPC_RMID, NULL)), 0);
	if (p != (char *)-1)
		R("the mapping still reads", memcmp(p, "live", 4), 0);
	R("shmget(key) after", PN_ERR(shmget(key_shm, 0, 0)), ENOENT);
	p2 = shmat(id, NULL, 0);
	R("shmat by the id while it is mapped", p2 == (char *)-1 ? errno : 0,
	    0);
	R("IPC_STAT by the id while it is mapped", PN_ERR(shmctl(id, IPC_STAT,
	    &ds)), 0);
	if (p2 != (char *)-1)
		R("shmdt", PN_ERR(shmdt(p2)), 0);
	if (p != (char *)-1)
		R("shmdt, the last", PN_ERR(shmdt(p)), 0);
	R("shmat by the id after the last detach", shmat(id, NULL, 0) ==
	    (void *)-1 ? errno : 0, EINVAL);
	R("IPC_STAT by the id after the last detach", PN_ERR(shmctl(id,
	    IPC_STAT, &ds)), EINVAL);
	R("shmctl(invalid id)", PN_ERR(shmctl(0x7fffffff, IPC_STAT, &ds)),
	    EINVAL);
	R("shmat(invalid id)", shmat(0x7fffffff, NULL, 0) == (void *)-1 ?
	    errno : 0, EINVAL);
	DONE();
}

static int
sem_use(int id)
{

	if (id == -1)
		return (priv_id);
	return (semctl(id, 0, GETVAL) == 7 ? 0 : errno != 0 ? errno : 97);
}

union semun_arg {
	int		 val;
	struct semid_ds	*buf;
	unsigned short	*array;
};

static int
sysv_sem(void *arg __unused)
{
	struct semid_ds ds;
	struct sembuf op;
	union semun_arg u;
	unsigned short vals[3];
	pid_t pid;
	int id, slot, status;

	nbad = 0;
	id = semget(key_sem, 3, IPC_CREAT | IPC_EXCL | 0640);
	R("semget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	R("semget(key, IPC_CREAT|IPC_EXCL) again",
	    PN_ERR(semget(key_sem, 3, IPC_CREAT | IPC_EXCL | 0640)), EEXIST);
	R("semget(key) is the same id", semget(key_sem, 0, 0) == id, 1);
	R("semget(key) with more semaphores", PN_ERR(semget(key_sem, 4, 0)),
	    EINVAL);
	R("semget(unused key)", PN_ERR(semget(key_sem + 1, 0, 0)), ENOENT);

	u.buf = &ds;
	R("IPC_STAT", PN_ERR(semctl(id, 0, IPC_STAT, u)), 0);
	R("  sem_nsems", ds.sem_nsems, 3);
	R("  mode", ds.sem_perm.mode & 0777, 0640);
	R("  uid", ds.sem_perm.uid, PN_UID);
	R("  key", ds.sem_perm.key, key_sem);
	ds.sem_perm.mode = 0600;
	R("IPC_SET", PN_ERR(semctl(id, 0, IPC_SET, u)), 0);
	R("IPC_STAT", PN_ERR(semctl(id, 0, IPC_STAT, u)), 0);
	R("  mode after IPC_SET", ds.sem_perm.mode & 0777, 0600);
	slot = SEM_SLOT(key_sem);
	R("kern.ipc.sema has the key", slot >= 0, 1);
	memset(&ds, 0, sizeof(ds));
	/*
	 * semctl(3) passes the fourth argument on for five commands, and
	 * SEM_STAT is not one of them (lib/libc/gen/semctl.c): through libc
	 * the kernel gets no buffer.  The system call itself answers.
	 */
	R("SEM_STAT by the listing's slot, semctl(3)", PN_ERR(semctl(slot, 0,
	    SEM_STAT, u)), EFAULT);
	R("SEM_STAT by the listing's slot, __semctl is the id",
	    syscall(SYS___semctl, slot, 0, SEM_STAT, &u) == id, 1);
	R("  key", ds.sem_perm.key, key_sem);
	R("IPC_INFO", PN_ERR(semctl(0, 0, IPC_INFO, u)), EINVAL);
	R("SEM_INFO", PN_ERR(semctl(0, 0, SEM_INFO, u)), EINVAL);

	u.val = 5;
	R("SETVAL", PN_ERR(semctl(id, 1, SETVAL, u)), 0);
	R("GETVAL", semctl(id, 1, GETVAL), 5);
	/* sempid is the last semop(2) caller; SETVAL does not set it. */
	R("GETPID after SETVAL", semctl(id, 1, GETPID), 0);
	op.sem_num = 1;
	op.sem_op = 1;
	op.sem_flg = 0;
	R("semop(+1)", PN_ERR(semop(id, &op, 1)), 0);
	R("GETPID is the caller", semctl(id, 1, GETPID) == getpid(), 1);
	R("GETNCNT", semctl(id, 1, GETNCNT), 0);
	R("GETZCNT", semctl(id, 1, GETZCNT), 0);
	vals[0] = 1;
	vals[1] = 2;
	vals[2] = 3;
	u.array = vals;
	R("SETALL", PN_ERR(semctl(id, 0, SETALL, u)), 0);
	memset(vals, 0, sizeof(vals));
	R("GETALL", PN_ERR(semctl(id, 0, GETALL, u)), 0);
	R("  values", vals[0] * 100 + vals[1] * 10 + vals[2], 123);
	R("GETVAL of a semaphore past the set", PN_ERR(semctl(id, 3,
	    GETVAL)), EINVAL);
	R("semctl with no such command", PN_ERR(semctl(id, 0, 999, u)),
	    EINVAL);

	/* SEM_UNDO: an adjustment is taken back when its process exits. */
	u.val = 0;
	R("SETVAL 0", PN_ERR(semctl(id, 0, SETVAL, u)), 0);
	pid = fork();
	if (pid == 0) {
		op.sem_num = 0;
		op.sem_op = 2;
		op.sem_flg = SEM_UNDO;
		if (semop(id, &op, 1) != 0)
			_exit(99);
		_exit(semctl(id, 0, GETVAL));
	}
	R("waitpid", waitpid(pid, &status, 0) == pid && WIFEXITED(status), 1);
	R("value in the child after semop(+2, SEM_UNDO)",
	    WEXITSTATUS(status), 2);
	R("value after the child exits", semctl(id, 0, GETVAL), 0);

	/* IPC_PRIVATE over a socket. */
	priv_id = semget(IPC_PRIVATE, 1, 0600);
	R("semget(IPC_PRIVATE)", priv_id == -1 ? errno : 0, 0);
	u.val = 7;
	R("SETVAL", PN_ERR(semctl(priv_id, 0, SETVAL, u)), 0);
	R("an IPC_PRIVATE id sent over a socket is usable there",
	    id_over_socket(sem_use), 0);
	R("IPC_RMID", PN_ERR(semctl(priv_id, 0, IPC_RMID)), 0);

	/* Removal under a sleeper. */
	pid = fork();
	if (pid == 0) {
		(void)alarm(60);
		op.sem_num = 0;
		op.sem_op = -1;
		op.sem_flg = 0;
		_exit(semop(id, &op, 1) == -1 ? errno : 0);
	}
	R("a child sleeps in semop(-1)", sleeps_on(pid, "semwait"), 1);
	R("GETNCNT with the sleeper", semctl(id, 0, GETNCNT), 1);
	R("IPC_RMID under the sleeper", PN_ERR(semctl(id, 0, IPC_RMID)), 0);
	R("waitpid", waitpid(pid, &status, 0) == pid && WIFEXITED(status), 1);
	R("the sleeper's semop", WEXITSTATUS(status), EIDRM);
	R("semget(key) after", PN_ERR(semget(key_sem, 0, 0)), ENOENT);
	R("GETVAL by the id after", PN_ERR(semctl(id, 0, GETVAL)), EINVAL);
	R("semctl(invalid id)", PN_ERR(semctl(0x7fffffff, 0, GETVAL)),
	    EINVAL);
	op.sem_num = 0;
	op.sem_op = 1;
	op.sem_flg = 0;
	R("semop(invalid id)", PN_ERR(semop(0x7fffffff, &op, 1)), EINVAL);
	DONE();
}

struct pmsg {
	long	mtype;
	char	mtext[16];
};

static int
msg_use(int id)
{
	struct pmsg m;

	if (id == -1)
		return (priv_id);
	if (msgrcv(id, &m, sizeof(m.mtext), 0, IPC_NOWAIT) != 4)
		return (errno != 0 ? errno : 97);
	return (memcmp(m.mtext, "priv", 4) == 0 ? 0 : 97);
}

static int
sysv_msg(void *arg __unused)
{
	struct msqid_ds ds;
	struct pmsg m;
	pid_t pid;
	int id, status;

	nbad = 0;
	id = msgget(key_msg, IPC_CREAT | IPC_EXCL | 0640);
	R("msgget(key, IPC_CREAT|IPC_EXCL)", id == -1 ? errno : 0, 0);
	R("msgget(key, IPC_CREAT|IPC_EXCL) again",
	    PN_ERR(msgget(key_msg, IPC_CREAT | IPC_EXCL | 0640)), EEXIST);
	R("msgget(key) is the same id", msgget(key_msg, 0) == id, 1);
	R("msgget(unused key)", PN_ERR(msgget(key_msg + 1, 0)), ENOENT);

	R("IPC_STAT", PN_ERR(msgctl(id, IPC_STAT, &ds)), 0);
	R("  mode", ds.msg_perm.mode & 0777, 0640);
	R("  uid", ds.msg_perm.uid, PN_UID);
	R("  key", ds.msg_perm.key, key_msg);
	R("  msg_qnum", ds.msg_qnum, 0);
	ds.msg_perm.mode = 0600;
	R("IPC_SET", PN_ERR(msgctl(id, IPC_SET, &ds)), 0);
	R("IPC_STAT", PN_ERR(msgctl(id, IPC_STAT, &ds)), 0);
	R("  mode after IPC_SET", ds.msg_perm.mode & 0777, 0600);
	R("kern.ipc.msqids has the key", MSG_SLOT(key_msg), 1);
	R("IPC_INFO", PN_ERR(msgctl(0, IPC_INFO, &ds)), EINVAL);
	R("msgctl with no such command", PN_ERR(msgctl(id, 999, &ds)),
	    EINVAL);

	m.mtype = 3;
	memcpy(m.mtext, "abc", 3);
	R("msgsnd", PN_ERR(msgsnd(id, &m, 3, 0)), 0);
	R("IPC_STAT", PN_ERR(msgctl(id, IPC_STAT, &ds)), 0);
	R("  msg_qnum", ds.msg_qnum, 1);
	R("  msg_lspid is the caller", ds.msg_lspid == getpid(), 1);
	R("msgrcv of another type, IPC_NOWAIT", PN_ERR(msgrcv(id, &m,
	    sizeof(m.mtext), 4, IPC_NOWAIT)), ENOMSG);
	memset(&m, 0, sizeof(m));
	R("msgrcv", msgrcv(id, &m, sizeof(m.mtext), 3, 0), 3);
	R("  the message", memcmp(m.mtext, "abc", 3), 0);

	priv_id = msgget(IPC_PRIVATE, 0600);
	R("msgget(IPC_PRIVATE)", priv_id == -1 ? errno : 0, 0);
	m.mtype = 1;
	memcpy(m.mtext, "priv", 4);
	R("msgsnd", PN_ERR(msgsnd(priv_id, &m, 4, 0)), 0);
	R("an IPC_PRIVATE id sent over a socket is usable there",
	    id_over_socket(msg_use), 0);
	R("IPC_RMID", PN_ERR(msgctl(priv_id, IPC_RMID, NULL)), 0);

	pid = fork();
	if (pid == 0) {
		(void)alarm(60);
		_exit(msgrcv(id, &m, sizeof(m.mtext), 0, 0) == -1 ? errno :
		    0);
	}
	R("a child sleeps in msgrcv", sleeps_on(pid, "msgrcv"), 1);
	R("IPC_RMID under the sleeper", PN_ERR(msgctl(id, IPC_RMID, NULL)),
	    0);
	R("waitpid", waitpid(pid, &status, 0) == pid && WIFEXITED(status), 1);
	R("the sleeper's msgrcv", WEXITSTATUS(status), EIDRM);
	R("msgget(key) after", PN_ERR(msgget(key_msg, 0)), ENOENT);
	R("IPC_STAT by the id after", PN_ERR(msgctl(id, IPC_STAT, &ds)),
	    EINVAL);
	R("msgctl(invalid id)", PN_ERR(msgctl(0x7fffffff, IPC_STAT, &ds)),
	    EINVAL);
	R("msgsnd(invalid id)", PN_ERR(msgsnd(0x7fffffff, &m, 1, 0)),
	    EINVAL);
	DONE();
}

static int
sysv_sizes(void *arg __unused)
{
	size_t len;
	int n;

	nbad = 0;
	len = sizeof(n);
	(void)sysctlbyname("kern.ipc.shmmni", &n, &len, NULL, 0);
	len = 0;
	R("kern.ipc.shmsegs size", PN_ERR(sysctlbyname("kern.ipc.shmsegs",
	    NULL, &len, NULL, 0)), 0);
	R("  is shmmni * sizeof(struct shmid_kernel)", len ==
	    (size_t)n * sizeof(struct shmid_kernel), 1);
	len = sizeof(n);
	(void)sysctlbyname("kern.ipc.semmni", &n, &len, NULL, 0);
	len = 0;
	R("kern.ipc.sema size", PN_ERR(sysctlbyname("kern.ipc.sema", NULL,
	    &len, NULL, 0)), 0);
	R("  is semmni * sizeof(struct semid_kernel)", len ==
	    (size_t)n * sizeof(struct semid_kernel), 1);
	len = sizeof(n);
	(void)sysctlbyname("kern.ipc.msgmni", &n, &len, NULL, 0);
	len = 0;
	R("kern.ipc.msqids size", PN_ERR(sysctlbyname("kern.ipc.msqids",
	    NULL, &len, NULL, 0)), 0);
	R("  is msgmni * sizeof(struct msqid_kernel)", len ==
	    (size_t)n * sizeof(struct msqid_kernel), 1);
	R("sizeof(struct shmid_kernel)", sizeof(struct shmid_kernel), 104);
	R("sizeof(struct semid_kernel)", sizeof(struct semid_kernel), 80);
	R("sizeof(struct msqid_kernel)", sizeof(struct msqid_kernel), 120);
	DONE();
}

/*
 * Item 18, native.  Each System V family: get by key, IPC_CREAT|IPC_EXCL
 * on an existing key (EEXIST), an IPC_PRIVATE id handed to another
 * process, every control command, SEM_UNDO at exit, IPC_RMID of a mapped
 * segment, an invalid id (EINVAL), removal under a sleeper (EIDRM), and
 * the size and contents of the listing sysctls.  The Linux half and
 * ipcs(1) are linux_boundary_test and procnet_ipcs_test.
 */
#define	SYSV_CASE(name, fn, descr)					\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	names(#name);							\
	sweep();							\
	rows_child(fn, NULL, #name);					\
	sweep();							\
}

SYSV_CASE(sysv_shm_rows, sysv_shm, "System V shared memory, unattached")
SYSV_CASE(sysv_sem_rows, sysv_sem, "System V semaphores, unattached")
SYSV_CASE(sysv_msg_rows, sysv_msg, "System V message queues, unattached")
SYSV_CASE(sysv_listing_sizes, sysv_sizes, "The System V listing sysctls "
    "are arrays of the kernel structures")

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, named_ipc_shared);
	ATF_TP_ADD_TC(tp, named_ipc_lifetime);
	ATF_TP_ADD_TC(tp, sysv_shm_rows);
	ATF_TP_ADD_TC(tp, sysv_sem_rows);
	ATF_TP_ADD_TC(tp, sysv_msg_rows);
	ATF_TP_ADD_TC(tp, sysv_listing_sizes);
	return (atf_no_error());
}
