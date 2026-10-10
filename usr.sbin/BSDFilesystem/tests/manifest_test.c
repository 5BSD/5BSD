/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <atf-c.h>
#include <stdio.h>
#include <string.h>
#include <libcapbundle_internal.h>

ATF_TC_WITHOUT_HEAD(shipped_oes_admission);
ATF_TC_BODY(shipped_oes_admission, tc)
{
	struct capbundle bundle = { 0 };
	struct capbundle_service service;
	char path[MAXPATHLEN], error[512] = { 0 };
	unsigned oes = 0, filesystem = 0;
	const char *source = atf_tc_get_config_var(tc, "srcdir");

	strlcpy(bundle.bundle_id, "system.Filesystem", sizeof(bundle.bundle_id));
	snprintf(path, sizeof(path), "%s/bsdfilesystem.ucl", source);
	ATF_REQUIRE_EQ_MSG(0, capbundle_parse_unit_ucl(path, source, &bundle,
	    "bsdfilesystem", &service, error, sizeof(error)), "%s", error);
	for (unsigned i = 0; i < service.nprovides; i++) {
		if (strcmp(service.provides[i], "system.OES") == 0) {
			oes++;
			ATF_REQUIRE_EQ(1, service.nrequires[i]);
			ATF_CHECK_STREQ("system.oes", service.requires[i][0]);
		}
		if (strcmp(service.provides[i], "system.Filesystem") == 0) {
			filesystem++;
			ATF_CHECK_EQ(0, service.nrequires[i]);
		}
	}
	ATF_CHECK_EQ(1, oes);
	ATF_CHECK_EQ(1, filesystem);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shipped_oes_admission);
	return (atf_no_error());
}
