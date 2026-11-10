/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * flock(2) locks belong to the open file, not to a descriptor or a
 * process: every descriptor of the open file, in every process that shares
 * it, locks and unlocks the same lock, and the last close releases it.
 * These cases pin that behaviour where several holders of one open file
 * act on it, including a holder that unlocks while another sleeps for the
 * lock.  Which descriptor types take flock(2) at all is advlock_fd_test's
 * subject; conflicts between unrelated opens are flock_test's.
 *
 * Nothing here synchronises by sleeping: a request is known to be blocked
 * when its thread is seen asleep on the lock (wait message "lockf").
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	FILENAME	"lockfile"

/* The open file's "holds a flock(2) lock" flag as fcntl(F_GETFL) shows it. */
#define	GETFL_HASLOCK	0x4000

/*
 * What a new open of the file gets for a non-blocking request: 0 or the
 * errno.  The probe's own lock, if granted, goes with its close.
 */
static int
probe(int how)
{
	int error, fd;

	fd = open(FILENAME, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	error = flock(fd, how | LOCK_NB) == 0 ? 0 : errno;
	ATF_REQUIRE_EQ(0, close(fd));
	return (error);
}

#define	CHECK_FREE()	ATF_CHECK_EQ(0, probe(LOCK_EX))
#define	CHECK_HELD_EX()	ATF_CHECK_EQ(EWOULDBLOCK, probe(LOCK_SH))
#define	CHECK_HELD_SH()	do {						\
	ATF_CHECK_EQ(0, probe(LOCK_SH));				\
	ATF_CHECK_EQ(EWOULDBLOCK, probe(LOCK_EX));			\
} while (0)

static int
open_file(int flags)
{
	int fd;

	fd = open(FILENAME, O_RDWR | O_CREAT | flags, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	return (fd);
}

/* Whether the kernel reports the open file behind fd as holding a lock. */
static bool
has_lock_flag(int fd)
{
	struct kinfo_file *kf;
	bool kinfo;
	int cnt, fl, i;

	kf = kinfo_getfile(getpid(), &cnt);
	ATF_REQUIRE(kf != NULL);
	for (i = 0; i < cnt; i++)
		if (kf[i].kf_fd == fd)
			break;
	ATF_REQUIRE_MSG(i < cnt, "descriptor %d not listed", fd);
	kinfo = (kf[i].kf_flags & KF_FLAG_HASLOCK) != 0;
	free(kf);
	fl = fcntl(fd, F_GETFL);
	ATF_REQUIRE(fl != -1);
	ATF_REQUIRE_EQ_MSG(kinfo, (fl & GETFL_HASLOCK) != 0,
	    "kinfo and F_GETFL disagree on descriptor %d", fd);
	return (kinfo);
}

/* True once a thread of pid sleeps on an advisory lock. */
static bool
sleeps_on_lock(pid_t pid)
{
	struct kinfo_proc *kp;
	char *buf, *p;
	size_t len;
	int mib[4];
	bool found;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID | KERN_PROC_INC_THREAD;
	mib[3] = pid;
	len = 0;
	if (sysctl(mib, nitems(mib), NULL, &len, NULL, 0) != 0)
		return (false);
	len += len / 2 + sizeof(*kp);
	buf = malloc(len);
	ATF_REQUIRE(buf != NULL);
	found = false;
	if (sysctl(mib, nitems(mib), buf, &len, NULL, 0) == 0) {
		for (p = buf; p + sizeof(*kp) <= buf + len;
		    p += kp->ki_structsize) {
			kp = (struct kinfo_proc *)(void *)p;
			if (kp->ki_structsize < (int)sizeof(*kp))
				break;
			if (strcmp(kp->ki_wmesg, "lockf") == 0) {
				found = true;
				break;
			}
		}
	}
	free(buf);
	return (found);
}

/* Wait, bounded, until the request made by pid is asleep on the lock. */
static void
wait_blocked(pid_t pid)
{
	int i;

	for (i = 0; i < 30000; i++) {
		if (sleeps_on_lock(pid))
			return;
		usleep(1000);
	}
	if (pid != getpid())
		(void)kill(pid, SIGKILL);
	atf_tc_fail("the lock request of pid %d never blocked", (int)pid);
}

static void
on_signal(int sig __unused)
{
}

/*
 * A child sharing the caller's open files that asks for the lock and
 * exits with 0 or the errno.  With a signal number it first installs a
 * handler that interrupts system calls.
 */
static pid_t
fork_locker_closing(int fd, int how, int sig, int closefd)
{
	struct sigaction sa;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (sig != 0) {
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = on_signal;
			sigemptyset(&sa.sa_mask);
			if (sigaction(sig, &sa, NULL) != 0)
				_exit(255);
		}
		/* Leave the parent the only holder of that open file. */
		if (closefd != -1 && close(closefd) != 0)
			_exit(255);
		_exit(flock(fd, how) == 0 ? 0 : errno);
	}
	return (pid);
}

static pid_t
fork_locker(int fd, int how, int sig)
{

	return (fork_locker_closing(fd, how, sig, -1));
}

/* The child's exit status: its flock(2) result. */
static int
reap(pid_t pid)
{
	int status;

	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "child status %#x", status);
	return (WEXITSTATUS(status));
}

/*
 * Unlocking an open file that holds no lock succeeds, any number of
 * times, and takes nothing from another open file's lock.
 */
ATF_TC_WITHOUT_HEAD(unlock_without_lock);
ATF_TC_BODY(unlock_without_lock, tc)
{
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();

	ATF_REQUIRE_EQ(0, flock(y, LOCK_EX));
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK_EQ(0, flock(x, LOCK_UN | LOCK_NB));
	CHECK_HELD_EX();
	ATF_CHECK(has_lock_flag(y));
	ATF_CHECK_EQ(0, close(x));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, close(y));
	CHECK_FREE();
}

/* A second unlock is as good as the first; the flag follows the lock. */
ATF_TC_WITHOUT_HEAD(double_unlock);
ATF_TC_BODY(double_unlock, tc)
{
	int x;

	x = open_file(0);
	ATF_CHECK(!has_lock_flag(x));
	ATF_REQUIRE_EQ(0, flock(x, LOCK_EX));
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();
	/* And the open file locks again afterwards. */
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH));
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();
}

/* The operation bits: unlock wins over a lock type, exclusive over shared. */
ATF_TC_WITHOUT_HEAD(operation_bits);
ATF_TC_BODY(operation_bits, tc)
{
	int fds[2], x;

	x = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH | LOCK_EX));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN | LOCK_EX | LOCK_SH));
	CHECK_FREE();
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_NB));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK(!has_lock_flag(x));
	ATF_CHECK_EQ(0, close(x));
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_UN));
	ATF_CHECK_EQ(EBADF, errno);

	/* A descriptor that takes no flock(2) lock refuses the unlock too. */
	ATF_REQUIRE_EQ(0, pipe(fds));
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fds[0], LOCK_EX));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fds[0], LOCK_UN));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	ATF_CHECK(!has_lock_flag(fds[0]));
	ATF_CHECK_EQ(0, close(fds[0]));
	ATF_CHECK_EQ(0, close(fds[1]));
}

/* A lock taken by the parent is the child's to release, and the reverse. */
ATF_TC_WITHOUT_HEAD(fork_unlock_by_either);
ATF_TC_BODY(fork_unlock_by_either, tc)
{
	pid_t pid;
	int x;

	x = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_EX));
	pid = fork_locker(x, LOCK_UN, 0);
	ATF_CHECK_EQ(0, reap(pid));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();

	/* The child locks and exits: the open file still holds the lock. */
	pid = fork_locker(x, LOCK_EX, 0);
	ATF_CHECK_EQ(0, reap(pid));
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	CHECK_FREE();

	/* A request through the shared open file never conflicts with it. */
	ATF_REQUIRE_EQ(0, flock(x, LOCK_EX));
	pid = fork_locker(x, LOCK_EX | LOCK_NB, 0);
	ATF_CHECK_EQ(0, reap(pid));
	pid = fork_locker(x, LOCK_SH | LOCK_NB, 0);
	ATF_CHECK_EQ(0, reap(pid));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();
}

/* Duplicates are the same open file. */
ATF_TC_WITHOUT_HEAD(dup_shares_lock);
ATF_TC_BODY(dup_shares_lock, tc)
{
	int d, x;

	x = open_file(0);
	d = dup(x);
	ATF_REQUIRE(d >= 0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_EX));
	ATF_CHECK(has_lock_flag(d));
	ATF_CHECK_EQ(0, flock(d, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(0, flock(d, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();

	ATF_REQUIRE_EQ(0, flock(d, LOCK_SH));
	ATF_CHECK_EQ(0, close(d));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();
}

/*
 * Closing one of several descriptors of the open file keeps the lock,
 * whichever process closes; the last close releases it.
 */
ATF_TC_WITHOUT_HEAD(last_close_unlocks);
ATF_TC_BODY(last_close_unlocks, tc)
{
	pid_t pid;
	int d, p[2], x;
	char c;

	x = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_EX));
	d = dup(x);
	ATF_REQUIRE(d >= 0);
	/* The child's exit closes its two descriptors. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(close(x) == 0 ? 0 : errno);
	ATF_CHECK_EQ(0, reap(pid));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, close(x));
	CHECK_HELD_EX();
	ATF_CHECK(has_lock_flag(d));
	ATF_CHECK_EQ(0, close(d));
	CHECK_FREE();

	/* The child holds the last descriptor: its exit is the last close. */
	x = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH));
	ATF_REQUIRE_EQ(0, pipe(p));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		/* Stay until the parent has closed and looked. */
		(void)close(p[1]);
		_exit(read(p[0], &c, 1) == 0 ? 0 : 255);
	}
	ATF_REQUIRE_EQ(0, close(p[0]));
	ATF_CHECK_EQ(0, close(x));
	CHECK_HELD_SH();
	ATF_REQUIRE_EQ(0, close(p[1]));
	ATF_CHECK_EQ(0, reap(pid));
	CHECK_FREE();
}

/* open(2) with O_EXLOCK or O_SHLOCK takes the open file's lock. */
ATF_TC_WITHOUT_HEAD(open_with_lock);
ATF_TC_BODY(open_with_lock, tc)
{
	int x, y;

	x = open_file(O_EXLOCK);
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_EX();
	errno = 0;
	ATF_CHECK_EQ(-1, open(FILENAME, O_RDWR | O_SHLOCK | O_NONBLOCK));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, open(FILENAME, O_RDWR | O_EXLOCK | O_NONBLOCK));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(x));

	x = open_file(O_EXLOCK);
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();

	x = open_file(O_SHLOCK);
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_SH();
	y = open(FILENAME, O_RDWR | O_SHLOCK | O_NONBLOCK);
	ATF_REQUIRE(y >= 0);
	ATF_CHECK(has_lock_flag(y));
	ATF_CHECK_EQ(0, close(x));
	CHECK_HELD_SH();
	/* The lock taken at open upgrades like any other. */
	ATF_CHECK_EQ(0, flock(y, LOCK_EX | LOCK_NB));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, close(y));
	CHECK_FREE();
}

/* One open file converts its lock in place when nothing is in the way. */
ATF_TC_WITHOUT_HEAD(upgrade_downgrade);
ATF_TC_BODY(upgrade_downgrade, tc)
{
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, flock(x, LOCK_EX));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_SH));
	CHECK_HELD_SH();
	ATF_CHECK(has_lock_flag(x));

	/*
	 * A non-blocking upgrade that fails keeps the shared lock: with
	 * the other shared lock gone, the file is still not free.
	 */
	ATF_REQUIRE_EQ(0, flock(y, LOCK_SH | LOCK_NB));
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, flock(y, LOCK_UN));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, flock(x, LOCK_EX | LOCK_NB));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(x));
	ATF_CHECK_EQ(0, close(y));
}

/*
 * A refused non-blocking request returns EWOULDBLOCK and takes nothing,
 * and closing the refused open file releases nobody else's lock.
 */
ATF_TC_WITHOUT_HEAD(nonblocking_refusal);
ATF_TC_BODY(nonblocking_refusal, tc)
{
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(y, LOCK_EX));
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_SH | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, flock(y, LOCK_SH));
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	CHECK_HELD_SH();
	errno = 0;
	ATF_CHECK_EQ(-1, flock(x, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, close(x));
	CHECK_HELD_SH();
	ATF_CHECK_EQ(0, flock(y, LOCK_UN));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(y));
}

/*
 * A sleeping request is granted when the lock in its way goes, and the
 * shared open file then holds it: either holder unlocks it.
 */
ATF_TC_WITHOUT_HEAD(sleeper_granted);
ATF_TC_BODY(sleeper_granted, tc)
{
	pid_t pid;
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(y, LOCK_EX));
	pid = fork_locker(x, LOCK_EX, 0);
	wait_blocked(pid);
	CHECK_HELD_EX();
	ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
	ATF_CHECK_EQ(0, reap(pid));
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_EX();
	errno = 0;
	ATF_CHECK_EQ(-1, flock(y, LOCK_SH | LOCK_NB));
	ATF_CHECK_EQ(EWOULDBLOCK, errno);
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();

	/* Again, released by the last close instead. */
	ATF_REQUIRE_EQ(0, flock(y, LOCK_SH));
	pid = fork_locker_closing(x, LOCK_EX, 0, y);
	wait_blocked(pid);
	ATF_REQUIRE_EQ(0, close(y));
	ATF_CHECK_EQ(0, reap(pid));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();
}

/*
 * A blocking upgrade gives up the shared lock before it sleeps: the
 * other shared holder can take the file exclusively meanwhile.
 */
ATF_TC_WITHOUT_HEAD(blocking_upgrade_drops_shared);
ATF_TC_BODY(blocking_upgrade_drops_shared, tc)
{
	pid_t pid;
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH));
	ATF_REQUIRE_EQ(0, flock(y, LOCK_SH));
	pid = fork_locker(x, LOCK_EX, 0);
	wait_blocked(pid);
	ATF_CHECK_EQ(0, flock(y, LOCK_EX | LOCK_NB));
	ATF_CHECK(sleeps_on_lock(pid));
	ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
	ATF_CHECK_EQ(0, reap(pid));
	ATF_CHECK(has_lock_flag(x));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, close(x));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(y));
}

/*
 * A signal that interrupts the sleep fails the request with EINTR and
 * leaves no lock behind, whether or not another holder of the open file
 * unlocked it during the sleep.
 */
ATF_TC_WITHOUT_HEAD(interrupted_sleeper);
ATF_TC_BODY(interrupted_sleeper, tc)
{
	pid_t pid;
	int unlock, x, y;

	for (unlock = 0; unlock < 2; unlock++) {
		x = open_file(0);
		y = open_file(0);
		ATF_REQUIRE_EQ(0, flock(y, LOCK_EX));
		pid = fork_locker(x, LOCK_EX, SIGUSR1);
		wait_blocked(pid);
		if (unlock != 0)
			ATF_CHECK_EQ(0, flock(x, LOCK_UN));
		ATF_REQUIRE_EQ(0, kill(pid, SIGUSR1));
		ATF_CHECK_EQ(EINTR, reap(pid));
		CHECK_HELD_EX();
		ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
		/* x is still open; nothing was granted to it. */
		CHECK_FREE();
		ATF_CHECK_EQ(0, close(x));
		CHECK_FREE();
		ATF_CHECK_EQ(0, close(y));
	}
}

/*
 * An interrupted blocking upgrade has already given up its shared lock
 * and does not get it back.
 */
ATF_TC_WITHOUT_HEAD(interrupted_upgrade);
ATF_TC_BODY(interrupted_upgrade, tc)
{
	pid_t pid;
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_SH));
	ATF_REQUIRE_EQ(0, flock(y, LOCK_SH));
	pid = fork_locker(x, LOCK_EX, SIGUSR1);
	wait_blocked(pid);
	ATF_REQUIRE_EQ(0, kill(pid, SIGUSR1));
	ATF_CHECK_EQ(EINTR, reap(pid));
	CHECK_HELD_SH();
	ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(x));
	ATF_CHECK_EQ(0, close(y));
	CHECK_FREE();
}

static void *
thread_locker(void *arg)
{
	return ((void *)(intptr_t)(flock(*(int *)arg, LOCK_EX) == 0 ? 0 :
	    errno));
}

/*
 * A holder of the open file unlocks it while another holder's request
 * sleeps.  The request is granted later, and the lock it got must still
 * go with the last close of the open file: the unlock that came before
 * the grant must not make the open file forget the lock it then takes.
 */
static void
unlock_before_grant(int first, bool thread)
{
	pthread_t td;
	pid_t pid;
	void *res;
	int p, x, y;

	x = open_file(0);
	y = open_file(0);
	if (first != 0)
		ATF_REQUIRE_EQ(0, flock(x, first));
	ATF_REQUIRE_EQ(0, flock(y, first != 0 ? first : LOCK_EX));
	if (thread) {
		pid = getpid();
		ATF_REQUIRE_EQ(0, pthread_create(&td, NULL, thread_locker, &x));
	} else
		pid = fork_locker(x, LOCK_EX, 0);
	wait_blocked(pid);
	/* x holds nothing now: a blocking upgrade gave its lock up. */
	ATF_REQUIRE_EQ(0, flock(x, LOCK_UN));
	ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
	if (thread) {
		ATF_REQUIRE_EQ(0, pthread_join(td, &res));
		ATF_CHECK_EQ(0, (int)(intptr_t)res);
	} else
		ATF_CHECK_EQ(0, reap(pid));
	CHECK_HELD_EX();
	ATF_CHECK(has_lock_flag(x));
	/*
	 * Probe through an open file that exists before x goes away.  A lock
	 * left behind is owned by the freed struct file of x, and an open file
	 * created afterwards may be given the same address and pass for the
	 * owner.
	 */
	p = open_file(0);
	ATF_CHECK_EQ(0, close(x));
	ATF_CHECK_EQ_MSG(0, flock(p, LOCK_EX | LOCK_NB),
	    "the lock outlived the last close of its open file: %s",
	    strerror(errno));
	ATF_CHECK_EQ(0, close(p));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(y));
}

ATF_TC_WITHOUT_HEAD(unlock_before_grant_process);
ATF_TC_BODY(unlock_before_grant_process, tc)
{
	unlock_before_grant(0, false);
}

ATF_TC_WITHOUT_HEAD(unlock_before_grant_thread);
ATF_TC_BODY(unlock_before_grant_thread, tc)
{
	unlock_before_grant(0, true);
}

ATF_TC_WITHOUT_HEAD(unlock_before_grant_upgrade);
ATF_TC_BODY(unlock_before_grant_upgrade, tc)
{
	unlock_before_grant(LOCK_SH, false);
}

/* The grant survives the early unlock: an explicit unlock still works. */
ATF_TC_WITHOUT_HEAD(unlock_before_grant_then_unlock);
ATF_TC_BODY(unlock_before_grant_then_unlock, tc)
{
	pid_t pid;
	int x, y;

	x = open_file(0);
	y = open_file(0);
	ATF_REQUIRE_EQ(0, flock(y, LOCK_EX));
	pid = fork_locker(x, LOCK_EX, 0);
	wait_blocked(pid);
	ATF_REQUIRE_EQ(0, flock(x, LOCK_UN));
	ATF_REQUIRE_EQ(0, flock(y, LOCK_UN));
	ATF_CHECK_EQ(0, reap(pid));
	CHECK_HELD_EX();
	ATF_CHECK_EQ(0, flock(x, LOCK_UN));
	ATF_CHECK(!has_lock_flag(x));
	CHECK_FREE();
	ATF_CHECK_EQ(0, close(x));
	ATF_CHECK_EQ(0, close(y));
	CHECK_FREE();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unlock_without_lock);
	ATF_TP_ADD_TC(tp, double_unlock);
	ATF_TP_ADD_TC(tp, operation_bits);
	ATF_TP_ADD_TC(tp, fork_unlock_by_either);
	ATF_TP_ADD_TC(tp, dup_shares_lock);
	ATF_TP_ADD_TC(tp, last_close_unlocks);
	ATF_TP_ADD_TC(tp, open_with_lock);
	ATF_TP_ADD_TC(tp, upgrade_downgrade);
	ATF_TP_ADD_TC(tp, nonblocking_refusal);
	ATF_TP_ADD_TC(tp, sleeper_granted);
	ATF_TP_ADD_TC(tp, blocking_upgrade_drops_shared);
	ATF_TP_ADD_TC(tp, interrupted_sleeper);
	ATF_TP_ADD_TC(tp, interrupted_upgrade);
	ATF_TP_ADD_TC(tp, unlock_before_grant_process);
	ATF_TP_ADD_TC(tp, unlock_before_grant_thread);
	ATF_TP_ADD_TC(tp, unlock_before_grant_upgrade);
	ATF_TP_ADD_TC(tp, unlock_before_grant_then_unlock);
	return (atf_no_error());
}
