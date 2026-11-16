/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The lockless (SMR) lookup is still used for unattached processes.
 *
 * What it tries to break: cache_can_fplookup declines the fast path for a
 * process attached to a dq controller (DQRES_ATTACHED_TD).  An unattached
 * process must keep using it exactly as at 3f330ee172d.
 *
 * Which counters exist: at 3f330ee172d vfs_cache.c has no counter that is
 * specific to the lockless lookup.  vfs.cache.param.fast_lookup is the
 * administrative switch; vfs.cache.stats.{poshits,neghits,miss,...} are
 * counted by both the lockless and the locked lookup (numposhits is bumped
 * per component in cache_fplookup_next and in cache_lookup), so they show
 * that the name cache serves the burst but not which walk did.  The only
 * direct witness is the SDT probe vfs:fplookup:lookup:done, whose arg2 is
 * the enum cache_fpl_status (HANDLED = 3, PARTIAL = 2, ABORTED = 1) and
 * arg1 the vfs_cache.c line that decided it.  The probe test needs root
 * and dtrace; it skips when either is missing.
 *
 * A kernel may disable the lockless lookup for everyone (a MAC policy with
 * a vnode_check_lookup or _readlink hook, e.g. MAC_ABAC compiled in, or the
 * sysctl).  Then the test cannot observe it and skips; it tells that case
 * from a decline aimed at this process by comparing the decline site with
 * that of a capability-mode burst (cache_can_fplookup declines capability
 * mode after the global switch): the same site means the global switch.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

#define	BURST		2000
#define	FPL_ABORTED	1
#define	FPL_PARTIAL	2
#define	FPL_HANDLED	3
#define	MAXSITES	64

struct fpl_counts {
	long	 status[5];	/* by enum cache_fpl_status */
	long	 total;
	int	 nsites;
	struct {
		int	 status;
		int	 line;
		long	 n;
	} sites[MAXSITES];
};

static void
deep_file(void)
{

	pc_mkdir("d1");
	pc_mkdir("d1/d2");
	pc_mkdir("d1/d2/d3");
	pc_mkfile("d1/d2/d3/f", NULL);
}

static uint64_t
counter(const char *name)
{
	uint64_t v;
	size_t len;

	v = 0;
	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "%s: %s", name, strerror(errno));
	return (v);
}

ATF_TC_WITHOUT_HEAD(cache_sysctls);
ATF_TC_BODY(cache_sysctls, tc)
{
	struct stat sb;
	uint64_t before, after;
	int i, on;

	/* The administrative switch exists (3f330ee172d vfs_cache.c). */
	ATF_REQUIRE(pc_sysctl_get("vfs.cache.param.fast_lookup", &on));
	deep_file();
	ATF_REQUIRE(stat("d1/d2/d3/f", &sb) == 0);
	/* Positive hits grow with a burst of lookups of a cached path. */
	before = counter("vfs.cache.stats.poshits");
	for (i = 0; i < BURST; i++)
		ATF_REQUIRE(stat("d1/d2/d3/f", &sb) == 0);
	after = counter("vfs.cache.stats.poshits");
	ATF_CHECK_MSG(after - before >= BURST,
	    "vfs.cache.stats.poshits grew by %ju for %d lookups of 4 "
	    "components", (uintmax_t)(after - before), BURST);
	/* Negative hits grow with a burst of lookups of a missing name. */
	(void)stat("d1/d2/d3/missing", &sb);
	before = counter("vfs.cache.stats.neghits");
	for (i = 0; i < BURST; i++)
		ATF_REQUIRE(stat("d1/d2/d3/missing", &sb) == -1);
	after = counter("vfs.cache.stats.neghits");
	/*
	 * TBC: a file system may not enter negative entries (e.g. with
	 * vfs.cache.param.negmin effects); require growth only if any.
	 */
	printf("neghits grew by %ju\n", (uintmax_t)(after - before));
}

/* Run the burst under dtrace; false when dtrace is not usable. */
static bool
trace_burst(const atf_tc_t *tc, bool capmode, struct fpl_counts *c)
{
	char cmd[2048], line[256];
	const char *srcdir;
	FILE *p;
	int st, ln, status;
	long n;

	memset(c, 0, sizeof(*c));
	srcdir = atf_tc_get_config_var_wd(tc, "srcdir", ".");
	snprintf(cmd, sizeof(cmd),
	    "dtrace -q -x bufsize=4m -x aggsize=4m "
	    "-n 'vfs:fplookup:lookup:done /pid == $target/ "
	    "{ @s[arg2] = count(); @l[arg2, arg1] = count(); }' "
	    "-n 'END { printa(\"S %%d %%@d\\n\", @s); "
	    "printa(\"L %%d %%d %%@d\\n\", @l); }' "
	    "-c '%s/paths_statburst d1/d2/d3/f %d%s' 2>&1",
	    srcdir, BURST, capmode ? " capmode" : "");
	p = popen(cmd, "r");
	if (p == NULL)
		return (false);
	while (fgets(line, sizeof(line), p) != NULL) {
		if (sscanf(line, "S %d %ld", &st, &n) == 2) {
			if (st >= 0 && st < 5)
				c->status[st] += n;
			c->total += n;
		} else if (sscanf(line, "L %d %d %ld", &st, &ln, &n) == 3) {
			if (c->nsites < MAXSITES) {
				c->sites[c->nsites].status = st;
				c->sites[c->nsites].line = ln;
				c->sites[c->nsites].n = n;
				c->nsites++;
			}
		} else
			printf("dtrace: %s", line);
	}
	status = pclose(p);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || c->total == 0)
		return (false);
	return (true);
}

/* The vfs_cache.c line that declined most lookups (status ABORTED). */
static int
main_decline_site(const struct fpl_counts *c)
{
	long best;
	int i, line;

	best = 0;
	line = -1;
	for (i = 0; i < c->nsites; i++) {
		if (c->sites[i].status == FPL_ABORTED && c->sites[i].n > best) {
			best = c->sites[i].n;
			line = c->sites[i].line;
		}
	}
	return (line);
}

ATF_TC(lockless_lookup_used);
ATF_TC_HEAD(lockless_lookup_used, tc)
{

	atf_tc_set_md_var(tc, "descr", "a burst of stats by an unattached "
	    "process is answered by the lockless lookup");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "dtrace");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(lockless_lookup_used, tc)
{
	struct fpl_counts plain, capm;
	long used;
	int on, lp, lc;

	if (!pc_sysctl_get("vfs.cache.param.fast_lookup", &on))
		atf_tc_fail("vfs.cache.param.fast_lookup is absent");
	if (on == 0)
		atf_tc_skip("vfs.cache.param.fast_lookup=0 (administratively "
		    "disabled)");
	deep_file();
	if (!trace_burst(tc, false, &plain))
		atf_tc_skip("dtrace or the vfs:fplookup provider is unusable");
	used = plain.status[FPL_HANDLED] + plain.status[FPL_PARTIAL];
	printf("plain: %ld lookups, %ld handled, %ld partial, %ld aborted\n",
	    plain.total, plain.status[FPL_HANDLED],
	    plain.status[FPL_PARTIAL], plain.status[FPL_ABORTED]);
	if (used >= BURST / 2)
		return;
	/* Mostly declined: by the global switch, or for this process? */
	if (!trace_burst(tc, true, &capm))
		atf_tc_skip("dtrace failed on the capability-mode burst");
	lp = main_decline_site(&plain);
	lc = main_decline_site(&capm);
	printf("decline site: plain line %d, capability mode line %d\n", lp,
	    lc);
	if (lp == lc && lp != -1)
		atf_tc_skip("lockless lookup is disabled for every process "
		    "(global switch at vfs_cache.c:%d, e.g. a MAC policy with "
		    "a lookup hook): not observable here", lp);
	/*
	 * TBC: an audited process (AUDITING_TD) is also declined, after
	 * capability mode; a host running auditd with file-system classes
	 * preselected for root would fail here on any kernel.
	 */
	atf_tc_fail("an unattached process's lookups were declined by the "
	    "lockless path at vfs_cache.c:%d (%ld of %ld used it), while "
	    "capability mode declines at line %d (if auditd preselects this "
	    "process, that is the reason)", lp, used, plain.total, lc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cache_sysctls);
	ATF_TP_ADD_TC(tp, lockless_lookup_used);
	return (atf_no_error());
}
