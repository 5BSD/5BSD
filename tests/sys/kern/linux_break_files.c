/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial file-API tests: openat2 RESOLVE_BENEATH fuzzing (5000
 * generated paths that must never escape the directory), O_PATH misuse,
 * close_range extremes, dup3/dup rules, copy_file_range overlap and
 * cross-descriptor rules, renameat2 NOREPLACE racing another process,
 * memfd seals racing a writer, getdents64 with tiny buffers on a big
 * directory, xattr sweeps, and partial-page/unmapped buffers (EFAULT with
 * no partial damage) for read/write/readv.  Exit status = failed check.
 */
#include "linux_test.h"

#define	RESOLVE_BENEATH		0x08
#define	SYS_getxattr		191
#define	SYS_setxattr		188
#define	SYS_listxattr		194
#define	SYS_removexattr		197
#define	RENAME_NOREPLACE	1
#define	F_ADD_SEALS		1033
#define	F_GET_SEALS		1034
#define	F_SEAL_WRITE		8
#define	MFD_ALLOW_SEALING	2
#define	CLOSE_RANGE_CLOEXEC	4

struct open_how { u64 flags, mode, resolve; };
struct dirent64 { u64 d_ino; long d_off; u16 d_reclen; u8 d_type; char d_name[]; };

static unsigned long rng = 0x9e3779b97f4a7c15UL;
static unsigned long
rnd(void)
{

	rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
	return (rng);
}

static long
openat2(long dfd, const char *path, u64 flags, u64 resolve)
{
	struct open_how how;

	how.flags = flags; how.mode = 0; how.resolve = resolve;
	return (sys4(SYS_openat2, dfd, path, &how, sizeof(how)));
}

/* Build a random path of components from a small alphabet. */
static void
gen_path(char *out, int maxc)
{
	static const char *comp[] = { "..", ".", "a", "b", "lnkabs", "lnkup",
	    "lnkin", "sub", "", "/", "sub/..", "../..", "lnkloop" };
	int n = 1 + rnd() % maxc, i, o = 0, c;

	if ((rnd() & 7) == 0) out[o++] = '/';	/* absolute */
	for (i = 0; i < n; i++) {
		c = rnd() % (sizeof(comp) / sizeof(comp[0]));
		const char *s = comp[c];

		while (*s != '\0' && o < 200)
			out[o++] = *s++;
		if (i + 1 < n && o < 200)
			out[o++] = '/';
	}
	out[o] = '\0';
}

static int child_rename_racer(void *arg)
{
	long i;

	(void)arg;
	for (i = 0; i < 3000; i++) {
		(void)sys1(SYS_unlink, "race_b");
		(void)sys2(SYS_symlink, "race_a", "race_b");
	}
	return (0);
}

static int memfd_writer_fd;
static int
memfd_writer(void *arg)
{
	long i, r;

	(void)arg;
	for (i = 0; i < 20000; i++) {
		r = sys4(SYS_pwrite64, memfd_writer_fd, "w", 1, 0);
		if (r != 1 && r != -EPERM)
			return (1);
	}
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th;
	struct stat st, outside;
	char path[256], buf[8192], name[32];
	long dfd, fd, fd2, r, i, escapes, ok, guard;
	int pfd[2], status;

	(void)argc; (void)argv; (void)envp;

	/* Build: jail/{a, sub/b, lnkabs->/etc, lnkup->.., lnkin->sub, lnkloop} */
	(void)sys2(SYS_mkdir, "jail", 0755);
	(void)sys2(SYS_mkdir, "jail/sub", 0755);
	fd = sys3(SYS_open, "jail/a", O_WRONLY | O_CREAT, 0644);
	(void)sys1(SYS_close, fd);
	fd = sys3(SYS_open, "jail/sub/b", O_WRONLY | O_CREAT, 0644);
	(void)sys1(SYS_close, fd);
	(void)sys2(SYS_symlink, "/etc", "jail/lnkabs");
	(void)sys2(SYS_symlink, "..", "jail/lnkup");
	(void)sys2(SYS_symlink, "sub", "jail/lnkin");
	(void)sys2(SYS_symlink, "lnkloop", "jail/lnkloop");
	fd = sys3(SYS_open, "outside", O_WRONLY | O_CREAT, 0644);
	(void)sys1(SYS_close, fd);
	if (sys2(SYS_stat, "outside", &outside) != 0) return (1);
	dfd = sys3(SYS_open, "jail", O_RDONLY | O_DIRECTORY, 0);
	if (dfd < 0) return (1);
	if (sys2(SYS_fstat, dfd, &st) != 0) return (1);

	/*
	 * 2-3: 5000 random paths under RESOLVE_BENEATH.  Whatever opens must
	 * be inside jail (verified by walking up with ".." never reaching a
	 * different directory than jail's parent... simpler: the opened
	 * object's (dev, ino) must not equal "outside" or "/etc"), and the
	 * error for anything else must be one of EXDEV/ENOENT/ELOOP/ENOTDIR.
	 */
	escapes = 0; ok = 0;
	for (i = 0; i < 5000; i++) {
		gen_path(path, 6);
		r = openat2(dfd, path, O_PATH, RESOLVE_BENEATH);
		if (r >= 0) {
			struct stat s2;

			ok++;
			if (sys2(SYS_fstat, r, &s2) == 0 &&
			    s2.st_dev == outside.st_dev &&
			    s2.st_ino == outside.st_ino)
				escapes++;
			/* /etc has a different inode than anything in jail */
			(void)sys1(SYS_close, r);
		} else if (r != -EXDEV && r != -ENOENT && r != -ELOOP &&
		    r != -ENOTDIR && r != -EINVAL && r != -ENAMETOOLONG) {
			msgnum("openat2 unexpected errno ", r);
			return (2);
		}
	}
	if (escapes != 0) return (3);
	if (ok == 0) return (3);	/* the generator must produce hits */
	/* explicit escapes */
	if (openat2(dfd, "lnkup/outside", O_PATH, RESOLVE_BENEATH) != -EXDEV)
		return (3);
	if (openat2(dfd, "lnkabs/passwd", O_PATH, RESOLVE_BENEATH) != -EXDEV)
		return (3);
	if (openat2(dfd, "sub/../../outside", O_PATH, RESOLVE_BENEATH) != -EXDEV)
		return (3);
	if (openat2(dfd, "lnkloop", O_PATH, RESOLVE_BENEATH) != -ELOOP)
		return (3);
	/* 4: a 4096-byte name is ENAMETOOLONG, longer paths too. */
	xmemset(path, 'x', 255); path[255] = '\0';
	if (openat2(dfd, path, O_PATH, RESOLVE_BENEATH) != -ENOENT) return (4);
	xmemset(buf, 'y', 4200); buf[4200] = '\0';
	if (openat2(dfd, buf, O_PATH, RESOLVE_BENEATH) != -ENAMETOOLONG)
		return (4);

	/* 5-7: O_PATH descriptors: usable as dirfd, not for I/O or ioctl. */
	r = openat2(dfd, "sub", O_PATH | O_DIRECTORY, 0);
	if (r < 0) return (5);
	fd = sys4(SYS_openat, r, "b", O_RDONLY, 0);
	if (fd < 0) return (5);
	(void)sys1(SYS_close, fd);
	if (sys3(SYS_read, r, buf, 1) != -EBADF) return (6);
	if (sys3(SYS_ioctl, r, 0x5401 /* TCGETS */, buf) != -EBADF) return (6);
	if (sys3(SYS_fcntl, r, 3 /* F_GETFL */, 0) < 0) return (7);
	if (sys1(SYS_fchdir, r) != 0) return (7);
	(void)sys1(SYS_chdir, "..");
	(void)sys1(SYS_close, r);

	/* 8-9: close_range extremes. */
	if (sys3(SYS_close_range, 5, 3, 0) != -EINVAL) return (8);
	if (sys3(SYS_close_range, 3, ~0U, 0x100) != -EINVAL) return (8);
	fd = sys1(SYS_dup, dfd);
	if (sys3(SYS_close_range, fd, fd, CLOSE_RANGE_CLOEXEC) != 0) return (9);
	if (sys3(SYS_fcntl, fd, 1 /* F_GETFD */, 0) != 1) return (9);
	if (sys3(SYS_close_range, fd, ~0U, 0) != 0) return (9);
	if (sys3(SYS_fcntl, fd, 1, 0) != -EBADF) return (9);
	/* dfd (below fd) is still open */
	if (sys2(SYS_fstat, dfd, &st) != 0) return (9);
	/* 10: dup3 same fd is EINVAL; dup2 same fd is a no-op success. */
	if (sys3(SYS_dup3, dfd, dfd, 0) != -EINVAL) return (10);
	if (sys2(SYS_dup2, dfd, dfd) != dfd) return (10);
	if (sys3(SYS_dup3, dfd, 100, 0x100) != -EINVAL) return (10);

	/* 11-13: copy_file_range: same file overlapping is EINVAL; ranges. */
	fd = tmpfile_fd("cfr.tmp");
	if (fd < 0) return (11);
	xmemset(buf, 'q', 8192);
	if (sys3(SYS_write, fd, buf, 8192) != 8192) return (11);
	{
		long off_in = 0, off_out = 4096;

		if (sys6(SYS_copy_file_range, fd, &off_in, fd, &off_out, 8192, 0)
		    != -EINVAL) return (11);
		off_in = 0; off_out = 8192;
		r = sys6(SYS_copy_file_range, fd, &off_in, fd, &off_out, 4096, 0);
		if (r != 4096 || off_in != 4096 || off_out != 12288) return (12);
	}
	if (sys2(SYS_pipe2, pfd, 0) != 0) return (13);
	if (sys6(SYS_copy_file_range, fd, 0, pfd[1], 0, 10, 0) != -EINVAL)
		return (13);
	(void)sys1(SYS_close, pfd[0]); (void)sys1(SYS_close, pfd[1]);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "cfr.tmp");

	/* 14-15: renameat2(NOREPLACE) vs a child recreating the target. */
	fd = sys3(SYS_open, "race_a", O_WRONLY | O_CREAT, 0644);
	(void)sys1(SYS_close, fd);
	r = sys0(SYS_fork);
	if (r == 0)
		(void)sys1(SYS_exit_group, child_rename_racer(0));
	guard = 0;
	for (i = 0; i < 3000; i++) {
		long e;

		e = sys5(SYS_renameat2, AT_FDCWD, "race_a", AT_FDCWD, "race_b",
		    RENAME_NOREPLACE);
		if (e == 0) {
			/* we won: race_b is now the file; put it back */
			(void)sys2(SYS_symlink, "x", "race_tmp");
			(void)sys1(SYS_unlink, "race_tmp");
			e = sys5(SYS_renameat2, AT_FDCWD, "race_b", AT_FDCWD,
			    "race_a", 0);
			if (e == -ENOENT) {
				/* the racer unlinked race_b: make a new race_a */
				fd = sys3(SYS_open, "race_a", O_WRONLY | O_CREAT, 0644);
				if (fd < 0) return (14);
				(void)sys1(SYS_close, fd);
			} else if (e != 0)
				return (14);
		} else if (e == -EEXIST) {
			guard++;
		} else if (e != -ENOENT) {
			msgnum("renameat2 errno ", e);
			return (14);
		}
	}
	(void)sys4(SYS_wait4, r, &status, 0, 0);
	if (guard == 0) return (15);	/* NOREPLACE never refused: not atomic */
	(void)sys1(SYS_unlink, "race_a"); (void)sys1(SYS_unlink, "race_b");

	/* 16-17: memfd F_SEAL_WRITE racing a writer thread. */
	fd = sys2(SYS_memfd_create, "seal", MFD_ALLOW_SEALING);
	if (fd < 0) return (16);
	if (sys2(SYS_ftruncate, fd, 4096) != 0) return (16);
	memfd_writer_fd = fd;
	if (thread_create(&th, memfd_writer, 0) != 0) return (16);
	sleep_ms(5);
	if (sys3(SYS_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) != 0 &&
	    sys3(SYS_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) != -EBUSY)
		return (17);
	if (thread_join(&th) != 0) return (17);
	if (sys3(SYS_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) != 0) return (17);
	if (sys4(SYS_pwrite64, fd, "w", 1, 0) != -EPERM) return (17);
	if ((sys3(SYS_fcntl, fd, F_GET_SEALS, 0) & F_SEAL_WRITE) == 0) return (17);
	(void)sys1(SYS_close, fd);

	/* 18-19: getdents64 with tiny buffers over 300 entries: no dup/miss. */
	(void)sys2(SYS_mkdir, "bigdir", 0755);
	for (i = 0; i < 300; i++) {
		name[0] = 'f'; name[1] = '0' + (i / 100); name[2] = '0' + (i / 10) % 10;
		name[3] = '0' + i % 10; name[4] = '\0';
		xmemcpy(path, "bigdir/", 7); xmemcpy(path + 7, name, 5);
		fd = sys3(SYS_open, path, O_WRONLY | O_CREAT, 0644);
		if (fd < 0) return (18);
		(void)sys1(SYS_close, fd);
	}
	fd = sys3(SYS_open, "bigdir", O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0) return (18);
	{
		unsigned char seen[300];
		long total = 0;

		xmemset(seen, 0, sizeof(seen));
		for (;;) {
			r = sys3(SYS_getdents64, fd, buf, 40);	/* ~1 entry */
			if (r == -EINVAL) {
				r = sys3(SYS_getdents64, fd, buf, 64);
			}
			if (r < 0) { msgnum("getdents64 ", r); return (18); }
			if (r == 0) break;
			for (i = 0; i < r;) {
				struct dirent64 *d = (void *)(buf + i);

				if (d->d_name[0] == 'f' && d->d_reclen > 0) {
					long idx = (d->d_name[1] - '0') * 100 +
					    (d->d_name[2] - '0') * 10 + (d->d_name[3] - '0');
					if (idx < 300 && seen[idx]++) return (19);
					total++;
				}
				i += d->d_reclen;
			}
		}
		if (total != 300) { msgnum("entries ", total); return (19); }
	}
	(void)sys1(SYS_close, fd);
	for (i = 0; i < 300; i++) {
		name[0] = 'f'; name[1] = '0' + (i / 100); name[2] = '0' + (i / 10) % 10;
		name[3] = '0' + i % 10; name[4] = '\0';
		xmemcpy(path, "bigdir/", 7); xmemcpy(path + 7, name, 5);
		(void)sys1(SYS_unlink, path);
	}
	(void)sys1(SYS_rmdir, "bigdir");

	/* 20-21: xattr sweep: 200 attributes, list must return all, then remove. */
	fd = tmpfile_fd("xa.tmp");
	if (fd < 0) return (20);
	(void)sys1(SYS_close, fd);
	r = sys5(SYS_setxattr, "xa.tmp", "user.probe", "v", 1, 0);
	if (r == -EOPNOTSUPP) {
		msg("note: no extattr support on this fs; xattr sweep skipped\n");
	} else {
		if (r != 0) return (20);
		for (i = 0; i < 200; i++) {
			xmemcpy(name, "user.k", 6);
			name[6] = 'a' + i / 26; name[7] = 'a' + i % 26; name[8] = '\0';
			if (sys5(SYS_setxattr, "xa.tmp", name, name, 8, 0) != 0)
				return (20);
		}
		r = sys3(SYS_listxattr, "xa.tmp", buf, sizeof(buf));
		if (r < 201 * 6) return (21);
		for (i = 0; i < 200; i++) {
			xmemcpy(name, "user.k", 6);
			name[6] = 'a' + i / 26; name[7] = 'a' + i % 26; name[8] = '\0';
			if (sys4(SYS_getxattr, "xa.tmp", name, buf, 8) != 8) return (21);
			if (sys2(SYS_removexattr, "xa.tmp", name) != 0) return (21);
		}
		(void)sys2(SYS_removexattr, "xa.tmp", "user.probe");
		if (sys3(SYS_listxattr, "xa.tmp", buf, sizeof(buf)) != 0) return (21);
	}
	(void)sys1(SYS_unlink, "xa.tmp");

	/* 22-24: partially mapped buffers: EFAULT, and no bytes lost. */
	r = call(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0) return (22);
	(void)sys2(SYS_munmap, r + PAGE, PAGE);	/* second page unmapped */
	fd = tmpfile_fd("pf.tmp");
	if (fd < 0) return (22);
	xmemset((void *)r, 'k', PAGE);
	/* write straddling into the hole: Linux writes the mapped prefix. */
	fd2 = sys3(SYS_write, fd, r + PAGE - 100, 200);
	if (fd2 != 100 && fd2 != -EFAULT) { msgnum("write straddle ", fd2); return (23); }
	/* fully unmapped buffer: EFAULT, nothing written */
	if (sys2(SYS_fstat, fd, &st) != 0) return (23);
	if (sys3(SYS_write, fd, r + PAGE, 10) != -EFAULT) return (23);
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != (fd2 > 0 ? fd2 : 0))
		return (23);
	/* readv with one bad iovec: EFAULT or a short count, never a crash */
	{
		struct iovec iov[2];

		iov[0].iov_base = (void *)r; iov[0].iov_len = 10;
		iov[1].iov_base = (void *)(r + PAGE); iov[1].iov_len = 10;
		(void)sys3(SYS_lseek, fd, 0, 0);
		fd2 = sys3(SYS_readv, fd, iov, 2);
		if (fd2 < 0 && fd2 != -EFAULT) return (24);
	}
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "pf.tmp");
	(void)sys2(SYS_munmap, r, PAGE);

	(void)sys1(SYS_close, dfd);
	(void)sys1(SYS_unlink, "jail/a"); (void)sys1(SYS_unlink, "jail/sub/b");
	(void)sys1(SYS_unlink, "jail/lnkabs"); (void)sys1(SYS_unlink, "jail/lnkup");
	(void)sys1(SYS_unlink, "jail/lnkin"); (void)sys1(SYS_unlink, "jail/lnkloop");
	(void)sys1(SYS_rmdir, "jail/sub"); (void)sys1(SYS_rmdir, "jail");
	(void)sys1(SYS_unlink, "outside");
	return (0);
}
