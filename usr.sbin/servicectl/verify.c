/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl verify/bundles — validate .cap bundle integrity and
 * list installed bundles.
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcapbundle.h>

#include "servicectl.h"

int
cmd_verify(const char *bundle_path)
{
	struct capbundle *b;
	char errbuf[512];
	unsigned i, j;

	/* Open and parse. */
	if (capbundle_open(bundle_path, &b, errbuf, sizeof(errbuf)) == -1) {
		warnx("verify: %s", errbuf);
		return (1);
	}

	/* Structural validation. */
	if (capbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		warnx("verify: FAILED — %s", errbuf);
		capbundle_close(b);
		return (1);
	}

	/* Report contents. */
	printf("Bundle: %s\n", capbundle_name(b));
	printf("  ID:      %s\n", capbundle_id(b));
	printf("  Version: %s\n", capbundle_version(b));
	printf("  Author:  %s\n", capbundle_author(b));
	printf("  Path:    %s\n", capbundle_path(b));
	printf("  Services: %u\n", capbundle_nservices(b));
	printf("\n");

	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);

		printf("  [%u] %s\n", i, capbundle_svc_label(svc));
		printf("      program:   %s\n", capbundle_svc_program(svc));
		printf("      on_demand: %s\n",
		    capbundle_svc_on_demand(svc) ? "yes" : "no");

		printf("      provides:");
		for (j = 0; j < capbundle_svc_nprovides(svc); j++)
			printf(" %s", capbundle_svc_provides(svc, j));
		printf("\n");

		if (capbundle_svc_nrequires(svc) > 0) {
			printf("      requires:");
			for (j = 0; j < capbundle_svc_nrequires(svc); j++)
				printf(" %s", capbundle_svc_requires(svc, j));
			printf("\n");
		}
	}

	/* Self-contained cycle check. */
	struct capbundle *arr[1] = { b };
	if (capbundle_check_cycles(arr, 1, errbuf, sizeof(errbuf)) == -1) {
		printf("\nCycle check: FAILED — %s\n", errbuf);
		capbundle_close(b);
		return (1);
	}

	printf("\nVerification: PASSED\n");
	capbundle_close(b);
	return (0);
}

/* Callback for bundle scanning. */
struct scan_ctx {
	unsigned count;
};

static int
bundles_print_cb(struct capbundle *b, void *arg)
{
	struct scan_ctx *ctx = arg;
	unsigned i;

	printf("  %s (%s v%s)\n",
	    capbundle_name(b), capbundle_id(b), capbundle_version(b));
	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);
		printf("    - %s%s\n", capbundle_svc_label(svc),
		    capbundle_svc_on_demand(svc) ? " (on-demand)" : "");
	}
	ctx->count++;
	capbundle_close(b);
	return (0);
}

int
cmd_bundles(void)
{
	struct scan_ctx ctx;
	const char *system_dir, *user_dir;

	system_dir = getenv("SERVICED_BUNDLE_DIR_SYSTEM");
	if (system_dir == NULL || system_dir[0] == '\0')
		system_dir = "/Capabilities/System";
	user_dir = getenv("SERVICED_BUNDLE_DIR_USER");
	if (user_dir == NULL || user_dir[0] == '\0')
		user_dir = "/Capabilities";

	printf("System bundles (%s):\n", system_dir);
	ctx.count = 0;
	if (capbundle_scan_dir(system_dir, bundles_print_cb, &ctx) == -1)
		printf("  (directory not found)\n");
	else if (ctx.count == 0)
		printf("  (none)\n");

	printf("\nUser bundles (%s):\n", user_dir);
	ctx.count = 0;
	if (capbundle_scan_dir(user_dir, bundles_print_cb, &ctx) == -1)
		printf("  (directory not found)\n");
	else if (ctx.count == 0)
		printf("  (none)\n");

	return (0);
}
