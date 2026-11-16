/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The root-load path of the running broker (bsdextension(8), endpoint
 * system.SystemExtension.RootLoad), plane-on tier.  Planning a root load
 * parses the module's metadata in a forked reader that confines itself with
 * the broker's capprotect descriptor before it reads a byte
 * (rootload.c child_confine()).  rootload_test replaces that step; this
 * case runs it for real: a load request for a module in /boot/kernel must
 * get past the metadata reader to the package checks (or load it), not
 * fail there.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <extensioncmp.h>
#include <libservice.h>

#include "sysext_proto.h"

/* A base module in /boot/kernel that nothing in the test image loads. */
#define	MODULE	"ext2fs"

ATF_TC(root_load_reader_confines_itself);
ATF_TC_HEAD(root_load_reader_confines_itself, tc)
{
	atf_tc_set_md_var(tc, "descr", "A root load of a module in "
	    "/boot/kernel runs the broker's confined metadata reader and "
	    "reaches the package checks");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(root_load_reader_confines_itself, tc)
{
	struct service_extension_root_outcome outcome;
	struct extensioncmp_session *session;
	struct stat st;

	if (stat("/boot/kernel/" MODULE ".ko", &st) != 0)
		atf_tc_fail("/boot/kernel/%s.ko: %s", MODULE, strerror(errno));
	ATF_REQUIRE_MSG(kldfind(MODULE ".ko") == -1,
	    "%s.ko is already loaded; the reader would not run", MODULE);
	ATF_REQUIRE_MSG(extensioncmp_session_open_rootload(&session) == 0,
	    "system.SystemExtension.RootLoad: %s", strerror(errno));
	memset(&outcome, 0, sizeof(outcome));
	ATF_REQUIRE_MSG(extensioncmp_root_load(session, MODULE, &outcome) == 0,
	    "root load: %s", strerror(errno));
	/*
	 * A reader that cannot confine itself reads nothing and the load is
	 * refused as FAILED with its errno (ENOTSUP without the capprotect
	 * descriptor).  Past the reader, a test image without a package
	 * database or package record refuses later, or the module loads.
	 */
	ATF_CHECK_MSG(outcome.result == SYSEXT_DECISION_LOADED ||
	    outcome.result == SYSEXT_DECISION_PKGDB ||
	    outcome.result == SYSEXT_DECISION_NOT_PACKAGED ||
	    outcome.result == SYSEXT_DECISION_CHECKSUM,
	    "decision %d, error %d (%s): the metadata reader did not report",
	    outcome.result, outcome.error, strerror(outcome.error));
	if (outcome.result == SYSEXT_DECISION_LOADED)
		ATF_CHECK(extensioncmp_root_unload(session, MODULE,
		    &outcome) == 0 &&
		    outcome.result == SYSEXT_DECISION_UNLOADED);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, root_load_reader_confines_itself);
	return (atf_no_error());
}
