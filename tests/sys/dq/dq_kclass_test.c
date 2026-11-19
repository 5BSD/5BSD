/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-c, D175 (B5): a kernel consumer's lookup
 * (class 2) whose start would be a served cwd or root is EXDEV with no
 * event; the linker's search (an exempt region, kernel-computed paths)
 * keeps working.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/ktrace.h>
#include <sys/linker.h>
#include <sys/mdioctl.h>

#include "dqt_tree.h"

struct kres {
	int	err[16];
};

static void
kclass_cwd_fn(void *arg __unused, void *out)
{
	struct kres *r = out;

	/* Relative names under the served cwd. */
	r->err[0] = DQT_ERRNO_OF(ktrace("ktr.out", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	r->err[1] = DQT_ERRNO_OF(acct("acct.out"));
	r->err[2] = DQT_ERRNO_OF(kldload("./m.ko"));
	r->err[3] = DQT_ERRNO_OF(swapon("./swapfile"));
	/* The linker's search is exempt: the real ENOENT. */
	r->err[4] = DQT_ERRNO_OF(kldload("dq_kclass_no_such_module"));
}

static void
kclass_root_fn(void *arg __unused, void *out)
{
	struct kres *r = out;

	/* Absolute names under the served root. */
	r->err[0] = DQT_ERRNO_OF(ktrace("/ktr.out", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	r->err[1] = DQT_ERRNO_OF(acct("/acct.out"));
	r->err[2] = DQT_ERRNO_OF(kldload("/m.ko"));
	r->err[3] = DQT_ERRNO_OF(swapon("/swapfile"));
}

static void
run(void (*fn)(void *, void *), bool cwd_only)
{
	struct dqt_tree s;
	struct kres r;
	struct dq_stats2 a, b;
	int n0, status;

	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	ATF_REQUIRE(dq_get_stats2(s.q, &a) == 0);
	n0 = dqt_tree_nev(&s);
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child(&s, cwd_only ? -1 : s.sroot, s.sroot, fn, NULL,
	    &r, sizeof(r));
	dqt_require_exit0(status, "child");
	DQT_CHECK_ERRNO(EXDEV, r.err[0], "ktrace");
	DQT_CHECK_ERRNO(EXDEV, r.err[1], "acct");
	DQT_CHECK_ERRNO(EXDEV, r.err[2], "kldload");
	DQT_CHECK_ERRNO(EXDEV, r.err[3], "swapon");
	if (fn == kclass_cwd_fn)
		DQT_CHECK_ERRNO(ENOENT, r.err[4], "kldload by name (exempt)");
	ATF_REQUIRE(dq_get_stats2(s.q, &b) == 0);
	printf("ds2_resolve_exdev rose by %ju\n",
	    (uintmax_t)(b.ds2_resolve_exdev - a.ds2_resolve_exdev));
	/* One refusal per call: ktrace, acct, kldload, swapon. */
	ATF_CHECK_MSG(b.ds2_resolve_exdev - a.ds2_resolve_exdev == 4,
	    "ds2_resolve_exdev rose by %ju",
	    (uintmax_t)(b.ds2_resolve_exdev - a.ds2_resolve_exdev));
	ATF_CHECK_EQ(a.ds2_resolve_unmarked, b.ds2_resolve_unmarked);
	/* No event was posted for any of them. */
	ATF_CHECK_EQ_MSG(n0, dqt_tree_nev(&s), "%d events posted",
	    dqt_tree_nev(&s) - n0);
	dqt_tree_stop(&s);
}

DQT_TREE_TC(kconsumer_served_cwd);
ATF_TC_BODY(kconsumer_served_cwd, tc)
{

	run(kclass_cwd_fn, true);
}

DQT_TREE_TC(kconsumer_served_root);
ATF_TC_BODY(kconsumer_served_root, tc)
{

	run(kclass_root_fn, false);
}

/*
 * A kernel-space path an attached process hands a subsystem that looks it
 * up where it cannot be consulted (here md(4)'s vnode backing file,
 * looked up under md's locks) is refused EPERM before the lookup
 * (dqres_kpath_refused); an unmarked kernel-space lookup outside an
 * exempt region is refused the same way by namei.  No event is posted.
 */
static void
kpath_fn(void *arg __unused, void *out)
{
	struct kres *r = out;
	struct md_ioctl mdio;
	int fd;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	if (fd < 0) {
		r->err[0] = -1;
		return;
	}
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_VNODE;
	mdio.md_file = __DECONST(char *, "/nonexistent-dq-kclass");
	/*
	 * kern_mdattach_locked() refuses a media size below one sector
	 * (EINVAL) before mdcreate_vnode() is reached; mdconfig(8) fills it
	 * in from the file's size.
	 */
	mdio.md_mediasize = DEV_BSIZE;
	mdio.md_options = MD_AUTOUNIT | MD_READONLY;
	r->err[1] = DQT_ERRNO_OF(ioctl(fd, MDIOCATTACH, &mdio));
	close(fd);
}

DQT_TREE_TC(kernel_path_refused);
ATF_TC_BODY(kernel_path_refused, tc)
{
	struct dqt_tree s;
	struct kres r;
	int n0, status;

	if (access("/dev/" MDCTL_NAME, F_OK) != 0)
		atf_tc_fail("md(4) is not loaded");
	dqt_tree_make("t");
	dqt_tree_start(&s, "t", 0);
	memset(&r, 0, sizeof(r));
	n0 = dqt_tree_nev(&s);
	status = dqt_tree_child(&s, -1, -1, kpath_fn, NULL, &r, sizeof(r));
	dqt_require_exit0(status, "child");
	ATF_REQUIRE_MSG(r.err[0] == 0, "cannot open /dev/mdctl");
	DQT_CHECK_ERRNO(EPERM, r.err[1], "MDIOCATTACH of a vnode");
	/* Only the open of /dev/mdctl was posted. */
	ATF_CHECK_EQ(n0 + 1, dqt_tree_nev(&s));
	dqt_tree_stop(&s);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kernel_path_refused);
	ATF_TP_ADD_TC(tp, kconsumer_served_cwd);
	ATF_TP_ADD_TC(tp, kconsumer_served_root);
	return (atf_no_error());
}
