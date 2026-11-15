/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The presented identity: everything fstat(2), fstatfs(2), fpathconf(2),
 * F_KINFO, procstat and the /dev/fd links answer about a served file comes
 * from the identity the controller minted, and must equal what the real
 * file whose identity it is answered when the identity was taken.  None of
 * these operations posts an event, so they run in the controller process
 * itself (plan section 3 rule 7: the EDEADLK scan is only in operations
 * that post).
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mac.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/user.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	DQ_WANT_PC_NAMES
#include "dq_test.h"

#define	DATA_LEN	8192

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

/* The snapshot the identity was built from: the served answers must equal it. */
struct snapshot {
	struct stat	 st;
	struct statfs	 sfs;
	long		 pc_value[DQ_PC_NCOUNT];
	int		 pc_errno[DQ_PC_NCOUNT];
};

static void
take_snapshot(int fd, struct snapshot *snap)
{
	int i;

	ATF_REQUIRE_EQ(0, fstat(fd, &snap->st));
	ATF_REQUIRE_EQ(0, fstatfs(fd, &snap->sfs));
	for (i = 0; i < DQ_PC_NCOUNT; i++) {
		errno = 0;
		snap->pc_value[i] = fpathconf(fd, dq_pc_names[i]);
		snap->pc_errno[i] = snap->pc_value[i] == -1 ? errno : 0;
	}
}

/*
 * The identity is built from the same stat/statfs/pathconf calls the
 * snapshot records, in the same order, so the two agree exactly.
 */
static struct dqt_object *
mint_snapshot(struct dqt_ctl *c, int oracle, struct snapshot *snap,
    const struct dq_policy *pol)
{
	struct dq_ident_file *ident;
	struct dq_policy defpol;
	struct dqt_object *o;

	take_snapshot(oracle, snap);
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	ATF_REQUIRE_EQ(0, dq_ident_from_stat(ident, oracle_path, &snap->st,
	    &snap->sfs, oracle));
	if (pol == NULL) {
		dq_policy_default(&defpol);
		pol = &defpol;
	}
	o = dqt_mint_ident(c, ident, pol, data, sizeof(data));
	free(ident);
	return (o);
}

ATF_TC(fstat_fields);
ATF_TC_HEAD(fstat_fields, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstat(2) of a served file answers "
	    "every field of the presented identity");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fstat_fields, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	struct stat st;
	int oracle;

	dqt_fill(data, sizeof(data), 1);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	ATF_REQUIRE_EQ(0, fstat(o->fd, &st));
	dqt_check_stat_eq(&st, &snap.st);
	ATF_CHECK(S_ISREG(st.st_mode));
	/* No GETATTR event was asked for: the identity answered locally. */
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.events[DQ_OP_GETATTR]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(fstatfs_fields);
ATF_TC_HEAD(fstatfs_fields, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstatfs(2) of a served file answers "
	    "the presented statfs, f_version forced, unfiltered (D87)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fstatfs_fields, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	struct statfs sfs;
	int oracle;

	dqt_fill(data, sizeof(data), 2);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	ATF_REQUIRE_EQ(0, fstatfs(o->fd, &sfs));
	/*
	 * D87: the identity's statfs is presented as minted; no mount exists
	 * for prison_enforce_statfs to filter, so a jailed requester would
	 * see the controller's view.  Outside a jail the two are the same.
	 */
	dqt_check_statfs_eq(&sfs, &snap.sfs);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(fpathconf_names);
ATF_TC_HEAD(fpathconf_names, tc)
{
	atf_tc_set_md_var(tc, "descr", "fpathconf(2) answers every name the "
	    "real file answered and refuses the rest with EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fpathconf_names, tc)
{
	/* Names a regular file never answers: outside dq_pc_names[]. */
	static const int unknown_names[] = { 11, 13, 19, 20, 22, 52, 56, 58,
	    71, 100 };
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	long value;
	size_t j;
	int err, i, oracle;

	dqt_fill(data, sizeof(data), 3);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	for (i = 0; i < DQ_PC_NCOUNT; i++) {
		errno = 0;
		value = fpathconf(o->fd, dq_pc_names[i]);
		err = value == -1 ? errno : 0;
		ATF_CHECK_EQ_MSG(snap.pc_value[i], value,
		    "_PC_ %d: served %ld oracle %ld", dq_pc_names[i], value,
		    snap.pc_value[i]);
		ATF_CHECK_EQ_MSG(snap.pc_errno[i], err,
		    "_PC_ %d: served errno %d oracle errno %d",
		    dq_pc_names[i], err, snap.pc_errno[i]);
	}
	/* _PC_ASYNC_IO is answered before dispatch for every descriptor. */
	ATF_CHECK_EQ(_POSIX_ASYNCHRONOUS_IO, fpathconf(o->fd, _PC_ASYNC_IO));
	for (j = 0; j < nitems(unknown_names); j++) {
		errno = 0;
		ATF_CHECK_EQ(-1, fpathconf(o->fd, unknown_names[j]));
		ATF_CHECK_EQ_MSG(EINVAL, errno, "name %d: errno %d",
		    unknown_names[j], errno);
	}
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(kinfo_file);
ATF_TC_HEAD(kinfo_file, tc)
{
	atf_tc_set_md_var(tc, "descr", "F_KINFO and kinfo_getfile(3) (what "
	    "procstat -f reads) describe a served file as the presented vnode");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kinfo_file, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	struct kinfo_file kif, *files;
	int cnt, i, oracle;
	bool found;

	dqt_fill(data, sizeof(data), 4);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	ATF_REQUIRE_EQ(0, fcntl(o->fd, F_KINFO, &kif));
	ATF_CHECK_EQ(KF_TYPE_VNODE, kif.kf_type);
	ATF_CHECK_EQ(KF_VTYPE_VREG, kif.kf_un.kf_file.kf_file_type);
	ATF_CHECK_STREQ(oracle_path, kif.kf_path);
	ATF_CHECK_EQ(snap.st.st_dev, kif.kf_un.kf_file.kf_file_fsid);
	ATF_CHECK_EQ((uint32_t)snap.st.st_dev,
	    kif.kf_un.kf_file.kf_file_fsid_freebsd11);
	ATF_CHECK_EQ(snap.st.st_ino, kif.kf_un.kf_file.kf_file_fileid);
	ATF_CHECK_EQ(snap.st.st_mode, kif.kf_un.kf_file.kf_file_mode);
	ATF_CHECK_EQ((uint64_t)snap.st.st_size, kif.kf_un.kf_file.kf_file_size);
	ATF_CHECK_EQ(snap.st.st_rdev, kif.kf_un.kf_file.kf_file_rdev);
	ATF_CHECK_EQ(snap.st.st_nlink, kif.kf_un.kf_file.kf_file_nlink);
	/* The generic layer reports the open mode: read-only. */
	ATF_CHECK((kif.kf_flags & KF_FLAG_READ) != 0);
	ATF_CHECK((kif.kf_flags & KF_FLAG_WRITE) == 0);

	/* The process-wide table procstat -f prints lists the same path. */
	files = kinfo_getfile(getpid(), &cnt);
	ATF_REQUIRE(files != NULL);
	found = false;
	for (i = 0; i < cnt; i++) {
		if (files[i].kf_fd == o->fd) {
			found = true;
			ATF_CHECK_EQ(KF_TYPE_VNODE, files[i].kf_type);
			ATF_CHECK_STREQ(oracle_path, files[i].kf_path);
			ATF_CHECK_EQ(snap.st.st_ino,
			    files[i].kf_un.kf_file.kf_file_fileid);
		}
	}
	ATF_CHECK(found);
	free(files);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC_WITH_CLEANUP(devfd_links);
ATF_TC_HEAD(devfd_links, tc)
{
	atf_tc_set_md_var(tc, "descr", "readlink and realpath of an fdescfs "
	    "fd link name the presented path (fdescfs asks fo_fill_kinfo)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(devfd_links, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	char link[PATH_MAX], target[PATH_MAX], resolved[PATH_MAX];
	ssize_t n;
	int oracle;

	/*
	 * A private fdescfs instance in the work directory (the guest may not
	 * mount one on /dev/fd).  A plain mount presents VCHR nodes, which
	 * readlink(2) refuses (kern_readlink_vp: VLNK or VV_READLINK); the
	 * rdlnk option makes them VLNK, so readlink answers and namei follows
	 * the link, which is what realpath(3) relies on.
	 */
	dqt_mount_fdesc("rdlnk");
	dqt_fill(data, sizeof(data), 5);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	snprintf(link, sizeof(link), "%s/%d", DQT_FDESC_DIR, o->fd);
	n = readlink(link, target, sizeof(target) - 1);
	ATF_REQUIRE_MSG(n > 0, "readlink %s: %s", link, strerror(errno));
	target[n] = '\0';
	ATF_CHECK_STREQ(oracle_path, target);
	/* namei follows the link to the real file the identity names. */
	ATF_REQUIRE_MSG(realpath(link, resolved) != NULL, "realpath %s: %s",
	    link, strerror(errno));
	ATF_CHECK_STREQ(oracle_path, resolved);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(devfd_links, tc)
{
	dqt_umount_fdesc();
}

ATF_TC(mac_get_fd);
ATF_TC_HEAD(mac_get_fd, tc)
{
	atf_tc_set_md_var(tc, "descr", "__mac_get_fd on a served file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mac_get_fd, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	mac_t label;
	int oracle;

	dqt_fill(data, sizeof(data), 6);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	if (mac_prepare_file_label(&label) != 0)
		atf_tc_skip("mac_prepare_file_label: %s", strerror(errno));
	/*
	 * Stage 1a: __mac_get_fd dispatches on f_type and has no DTYPE_DQ
	 * arm (mac_syscalls.c), so a served file answers the default EINVAL
	 * where a real file answers its vnode label (design D22 asks for an
	 * empty label; recorded as a stage 1a difference).
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, mac_get_fd(o->fd, label));
	ATF_CHECK_EQ(EINVAL, errno);
	mac_free(label);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(getfl_no_served_bit);
ATF_TC_HEAD(getfl_no_served_bit, tc)
{
	atf_tc_set_md_var(tc, "descr", "F_GETFL of a served file equals a "
	    "read-only real file's: no served bit exists in f_flag (I13)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(getfl_no_served_bit, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	int oflags, sflags, oracle;

	dqt_fill(data, sizeof(data), 7);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	sflags = fcntl(o->fd, F_GETFL);
	oflags = fcntl(oracle, F_GETFL);
	ATF_REQUIRE(sflags != -1 && oflags != -1);
	ATF_CHECK_EQ(oflags, sflags);
	ATF_CHECK_EQ(O_RDONLY, sflags & O_ACCMODE);
	/* The minted descriptor is close-on-exec and not close-on-fork. */
	ATF_CHECK_EQ(FD_CLOEXEC, fcntl(o->fd, F_GETFD) & (FD_CLOEXEC | FD_CLOFORK));
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(setident_changes_stat);
ATF_TC_HEAD(setident_changes_stat, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_SETIDENT replaces what fstat "
	    "answers and fires NOTE_ATTRIB");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setident_changes_stat, tc)
{
	struct dqt_ctl c;
	struct snapshot snap;
	struct dqt_object *o;
	struct dq_ident_file *ident;
	struct kevent kev;
	struct timespec zero = { 0, 0 };
	struct stat st;
	int kq, oracle;

	dqt_fill(data, sizeof(data), 8);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = mint_snapshot(&c, oracle, &snap, NULL);

	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev, o->fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_ATTRIB | NOTE_REVOKE, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_CHECK_EQ(0, kevent(kq, NULL, 0, &kev, 1, &zero));

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	*ident = o->ident;
	ident->di_size = 12345;
	ident->di_mtime.tv_sec += 1000;
	ident->di_mtime.tv_nsec = 7;
	ident->di_mode = S_IFREG | 0600;
	ident->di_nlink = 3;
	ATF_REQUIRE_MSG(dq_set_ident(c.q, o->id, ident) == 0,
	    "DQ_IOC_SETIDENT: %s", strerror(errno));

	ATF_REQUIRE_EQ(0, fstat(o->fd, &st));
	ATF_CHECK_EQ(12345, st.st_size);
	ATF_CHECK_EQ(snap.st.st_mtim.tv_sec + 1000, st.st_mtim.tv_sec);
	ATF_CHECK_EQ(7, st.st_mtim.tv_nsec);
	ATF_CHECK_EQ(S_IFREG | 0600, st.st_mode);
	ATF_CHECK_EQ(3, st.st_nlink);
	/* The rest is unchanged. */
	ATF_CHECK_EQ(snap.st.st_ino, st.st_ino);
	ATF_CHECK_EQ(snap.st.st_dev, st.st_dev);

	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &zero));
	ATF_CHECK_EQ(EVFILT_VNODE, kev.filter);
	ATF_CHECK((kev.fflags & NOTE_ATTRIB) != 0);
	ATF_CHECK((kev.fflags & NOTE_REVOKE) == 0);
	ATF_CHECK((kev.flags & EV_EOF) == 0);

	/* A refused identity leaves the presented one in place. */
	ident->di_mode = S_IFDIR | 0755;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_ident(c.q, o->id, ident));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(0, fstat(o->fd, &st));
	ATF_CHECK_EQ(S_IFREG | 0600, st.st_mode);

	free(ident);
	(void)close(kq);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fstat_fields);
	ATF_TP_ADD_TC(tp, fstatfs_fields);
	ATF_TP_ADD_TC(tp, fpathconf_names);
	ATF_TP_ADD_TC(tp, kinfo_file);
	ATF_TP_ADD_TC(tp, devfd_links);
	ATF_TP_ADD_TC(tp, mac_get_fd);
	ATF_TP_ADD_TC(tp, getfl_no_served_bit);
	ATF_TP_ADD_TC(tp, setident_changes_stat);
	return (atf_no_error());
}
