/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The offset of every struct kinfo_proc field, as it was before the audit
 * token took spare longs for ki_uniqueid, ki_execgen and ki_imageid: new
 * fields come out of the spare arrays, and nothing that existed moves or
 * changes the structure's size (KINFO_PROC_SIZE).  The table was taken on
 * amd64 with the dev tree's <sys/user.h>; every 5BSD platform is LP64 and
 * lays the structure out the same way.
 */

#include <sys/param.h>
#include <sys/user.h>

#include <atf-c.h>
#include <stddef.h>

#define	F(f, off)	{ #f, offsetof(struct kinfo_proc, f), (off) }

static const struct {
	const char	*name;
	size_t		 now;
	size_t		 then;
} fields[] = {
	F(ki_structsize, 0),
	F(ki_layout, 4),
	F(ki_args, 8),
	F(ki_paddr, 16),
	F(ki_addr, 24),
	F(ki_tracep, 32),
	F(ki_textvp, 40),
	F(ki_fd, 48),
	F(ki_vmspace, 56),
	F(ki_wchan, 64),
	F(ki_pid, 72),
	F(ki_ppid, 76),
	F(ki_pgid, 80),
	F(ki_tpgid, 84),
	F(ki_sid, 88),
	F(ki_tsid, 92),
	F(ki_jobc, 96),
	F(ki_spare_short1, 98),
	F(ki_tdev_freebsd11, 100),
	F(ki_siglist, 104),
	F(ki_sigmask, 120),
	F(ki_sigignore, 136),
	F(ki_sigcatch, 152),
	F(ki_uid, 168),
	F(ki_ruid, 172),
	F(ki_svuid, 176),
	F(ki_rgid, 180),
	F(ki_svgid, 184),
	F(ki_ngroups, 188),
	F(ki_spare_short2, 190),
	F(ki_groups, 192),
	F(ki_size, 256),
	F(ki_rssize, 264),
	F(ki_swrss, 272),
	F(ki_tsize, 280),
	F(ki_dsize, 288),
	F(ki_ssize, 296),
	F(ki_xstat, 304),
	F(ki_acflag, 306),
	F(ki_pctcpu, 308),
	F(ki_estcpu, 312),
	F(ki_slptime, 316),
	F(ki_swtime, 320),
	F(ki_cow, 324),
	F(ki_runtime, 328),
	F(ki_start, 336),
	F(ki_childtime, 352),
	F(ki_flag, 368),
	F(ki_kiflag, 376),
	F(ki_traceflag, 384),
	F(ki_stat, 388),
	F(ki_nice, 389),
	F(ki_lock, 390),
	F(ki_rqindex, 391),
	F(ki_oncpu_old, 392),
	F(ki_lastcpu_old, 393),
	F(ki_tdname, 394),
	F(ki_wmesg, 411),
	F(ki_login, 420),
	F(ki_lockname, 438),
	F(ki_comm, 447),
	F(ki_emul, 467),
	F(ki_loginclass, 484),
	F(ki_moretdname, 502),
	F(ki_sparestrings, 506),
	F(ki_spareints, 540),
	F(ki_rpid, 548),
	F(ki_reaper, 552),
	F(ki_reapsubtree, 556),
	F(ki_tdev, 560),
	F(ki_oncpu, 568),
	F(ki_lastcpu, 572),
	F(ki_tracer, 576),
	F(ki_flag2, 580),
	F(ki_fibnum, 584),
	F(ki_cr_flags, 588),
	F(ki_jid, 592),
	F(ki_numthreads, 596),
	F(ki_tid, 600),
	F(ki_pri, 604),
	F(ki_rusage, 608),
	F(ki_rusage_ch, 752),
	F(ki_pcb, 896),
	F(ki_kstack, 904),
	F(ki_udata, 912),
	F(ki_tdaddr, 920),
	F(ki_pd, 928),
	F(ki_uerrmsg, 936),
	F(ki_spareptrs, 944),
	F(ki_sparelongs, 976),
	F(ki_coalition, 1056),
	F(ki_rcoalition, 1064),
	F(ki_sflag, 1072),
	F(ki_tdflags, 1080),
};

ATF_TC_WITHOUT_HEAD(offsets_unchanged);
ATF_TC_BODY(offsets_unchanged, tc)
{
	size_t i;

	for (i = 0; i < nitems(fields); i++)
		ATF_CHECK_EQ_MSG(fields[i].then, fields[i].now,
		    "%s moved from %zu to %zu", fields[i].name, fields[i].then,
		    fields[i].now);
}

ATF_TC_WITHOUT_HEAD(size_unchanged);
ATF_TC_BODY(size_unchanged, tc)
{
	ATF_CHECK_EQ(1088, sizeof(struct kinfo_proc));
	ATF_CHECK_EQ(KINFO_PROC_SIZE, sizeof(struct kinfo_proc));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, offsets_unchanged);
	ATF_TP_ADD_TC(tp, size_unchanged);
	return (atf_no_error());
}
