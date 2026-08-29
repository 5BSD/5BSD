/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libcapbundle_internal.h"

static int
unused_scan_cb(struct capbundle *bundle, void *arg)
{

	(void)bundle;
	(void)arg;
	return (0);
}

ATF_TC_WITHOUT_HEAD(null_inputs);
ATF_TC_BODY(null_inputs, tc)
{
	struct capbundle *bundle;
	struct svc_manifest manifest;
	char error[64];

	(void)tc;
	bundle = (struct capbundle *)(uintptr_t)1;
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_open(NULL, &bundle, error,
	    sizeof(error)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(NULL, bundle);
	ATF_CHECK_MATCH("required", error);

	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_open(".", NULL, error, sizeof(error)));
	ATF_CHECK_EQ(EINVAL, errno);

	ATF_CHECK_EQ(NULL, capbundle_id(NULL));
	ATF_CHECK_EQ(NULL, capbundle_version(NULL));
	ATF_CHECK_EQ(NULL, capbundle_author(NULL));
	ATF_CHECK_EQ(NULL, capbundle_path(NULL));
	ATF_CHECK_EQ(NULL, capbundle_name(NULL));
	ATF_CHECK_EQ(0, capbundle_nservices(NULL));
	ATF_CHECK_EQ(NULL, capbundle_service(NULL, 0));
	ATF_CHECK_EQ(NULL, capbundle_svc_program(NULL));
	ATF_CHECK_EQ(NULL, capbundle_svc_label(NULL));
	ATF_CHECK_EQ(0, capbundle_svc_nprovides(NULL));
	ATF_CHECK_EQ(NULL, capbundle_svc_provides(NULL, 0));
	ATF_CHECK_EQ(0, capbundle_svc_narguments(NULL));
	ATF_CHECK_EQ(NULL, capbundle_svc_argument(NULL, 0));
	ATF_CHECK_EQ(0, capbundle_svc_nenvironment(NULL));
	ATF_CHECK_EQ(NULL, capbundle_svc_environment(NULL, 0));

	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_svc_fill_manifest(NULL, &manifest));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_svc_fill_manifest(
	    (const struct capbundle_service *)(uintptr_t)1, NULL));
	ATF_CHECK_EQ(EINVAL, errno);

	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_verify(NULL, error, sizeof(error)));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_scan_dir(NULL, unused_scan_cb, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_scan_dir(".", NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, null_inputs);
	return (atf_no_error());
}
