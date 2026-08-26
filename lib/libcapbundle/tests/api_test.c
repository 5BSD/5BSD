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
	ATF_CHECK(!capbundle_descriptor_factory_name(NULL));

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
	ATF_CHECK_EQ(0, capbundle_check_startup_cycles(NULL, 0, error,
	    sizeof(error)));
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_check_startup_cycles(NULL, 1, error,
	    sizeof(error)));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC_WITHOUT_HEAD(graph_service_limit);
ATF_TC_BODY(graph_service_limit, tc)
{
	struct capbundle *bundles[9];
	char error[256];
	unsigned i;

	(void)tc;
	for (i = 0; i < 9; i++) {
		bundles[i] = calloc(1, sizeof(*bundles[i]));
		ATF_REQUIRE(bundles[i] != NULL);
		bundles[i]->nservices = CAPBUNDLE_MAX_SERVICES;
	}

	/* 8 * 32 = 256 services is exactly the registry bound. */
	ATF_CHECK_EQ(0, capbundle_check_startup_cycles(bundles, 8, error,
	    sizeof(error)));

	/* 9 * 32 = 288 exceeds SERVICED_MAX_SERVICES. */
	errno = 0;
	error[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_check_startup_cycles(bundles, 9, error,
	    sizeof(error)));
	ATF_CHECK_EQ(E2BIG, errno);
	ATF_CHECK(strstr(error, "services") != NULL);

	/* A corrupt count must not wrap the allocation arithmetic. */
	bundles[0]->nservices = UINT_MAX;
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_check_startup_cycles(bundles, 2, error,
	    sizeof(error)));
	ATF_CHECK_EQ(E2BIG, errno);

	for (i = 0; i < 9; i++)
		free(bundles[i]);
}

ATF_TC_WITHOUT_HEAD(graph_duplicate_edges);
ATF_TC_BODY(graph_duplicate_edges, tc)
{
	struct capbundle *bundle;
	struct capbundle *bundles[1];
	struct capbundle_service *provider, *consumer;
	char error[256];

	(void)tc;
	bundle = calloc(1, sizeof(*bundle));
	ATF_REQUIRE(bundle != NULL);
	bundle->nservices = 2;
	provider = &bundle->services[0];
	consumer = &bundle->services[1];
	strlcpy(provider->label, "provider", sizeof(provider->label));
	strlcpy(provider->provides[0], "svc.a", sizeof(provider->provides[0]));
	provider->nprovides = 1;
	strlcpy(consumer->label, "consumer", sizeof(consumer->label));
	strlcpy(consumer->startup_after[0], "svc.a",
	    sizeof(consumer->startup_after[0]));
	strlcpy(consumer->startup_after[1], "svc.a",
	    sizeof(consumer->startup_after[1]));
	consumer->nstartup_after = 2;
	bundles[0] = bundle;

	/* Repeated identical requirements collapse to one edge. */
	ATF_CHECK_EQ(0, capbundle_check_startup_cycles(bundles, 1, error,
	    sizeof(error)));

	/* Deduplication must not hide a genuine cycle. */
	strlcpy(consumer->provides[0], "svc.b", sizeof(consumer->provides[0]));
	consumer->nprovides = 1;
	strlcpy(provider->startup_after[0], "svc.b",
	    sizeof(provider->startup_after[0]));
	provider->nstartup_after = 1;
	error[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_check_startup_cycles(bundles, 1, error,
	    sizeof(error)));
	ATF_CHECK(strstr(error, "circular") != NULL);

	free(bundle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, null_inputs);
	ATF_TP_ADD_TC(tp, graph_service_limit);
	ATF_TP_ADD_TC(tp, graph_duplicate_edges);
	return (atf_no_error());
}
