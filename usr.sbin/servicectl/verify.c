/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl verify/bundles — validate .app bundle integrity and
 * list installed bundles.
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libappbundle.h>

#include "servicectl.h"

int
cmd_verify(const char *bundle_path)
{
	struct appbundle *b;
	char errbuf[512];
	unsigned i, j;

	/* Open and parse. */
	if (appbundle_open(bundle_path, &b, errbuf, sizeof(errbuf)) == -1) {
		warnx("verify: %s", errbuf);
		return (1);
	}

	/* Structural validation. */
	if (appbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		warnx("verify: FAILED — %s", errbuf);
		appbundle_close(b);
		return (1);
	}

	/* Report contents. */
	printf("Bundle: %s\n", appbundle_name(b));
	printf("  ID:      %s\n", appbundle_id(b));
	printf("  Version: %s\n", appbundle_version(b));
	printf("  Author:  %s\n", appbundle_author(b));
	printf("  Path:    %s\n", appbundle_path(b));
	printf("  Services: %u\n", appbundle_nservices(b));
	printf("\n");

	for (i = 0; i < appbundle_nservices(b); i++) {
		struct appbundle_service *svc = appbundle_service(b, i);

		printf("  [%u] %s\n", i, appbundle_svc_label(svc));
		printf("      program:   %s\n", appbundle_svc_program(svc));
		printf("      on_demand: %s\n",
		    appbundle_svc_on_demand(svc) ? "yes" : "no");

		printf("      provides:");
		for (j = 0; j < appbundle_svc_nprovides(svc); j++)
			printf(" %s", appbundle_svc_provides(svc, j));
		printf("\n");

		if (appbundle_svc_nrequires(svc) > 0) {
			printf("      requires:");
			for (j = 0; j < appbundle_svc_nrequires(svc); j++)
				printf(" %s", appbundle_svc_requires(svc, j));
			printf("\n");
		}
	}

	/* Self-contained cycle check. */
	struct appbundle *arr[1] = { b };
	if (appbundle_check_cycles(arr, 1, errbuf, sizeof(errbuf)) == -1) {
		printf("\nCycle check: FAILED — %s\n", errbuf);
		appbundle_close(b);
		return (1);
	}

	printf("\nVerification: PASSED\n");
	appbundle_close(b);
	return (0);
}

/* Callback for bundle scanning. */
struct scan_ctx {
	unsigned count;
};

static int
bundles_print_cb(struct appbundle *b, void *arg)
{
	struct scan_ctx *ctx = arg;
	unsigned i;

	printf("  %s (%s v%s)\n",
	    appbundle_name(b), appbundle_id(b), appbundle_version(b));
	for (i = 0; i < appbundle_nservices(b); i++) {
		struct appbundle_service *svc = appbundle_service(b, i);
		printf("    - %s%s\n", appbundle_svc_label(svc),
		    appbundle_svc_on_demand(svc) ? " (on-demand)" : "");
	}
	ctx->count++;
	appbundle_close(b);
	return (0);
}

int
cmd_bundles(void)
{
	struct scan_ctx ctx;
	const char *system_dir, *user_dir;

	system_dir = getenv("SERVICED_BUNDLE_DIR_SYSTEM");
	if (system_dir == NULL || system_dir[0] == '\0')
		system_dir = "/System/Applications";
	user_dir = getenv("SERVICED_BUNDLE_DIR_USER");
	if (user_dir == NULL || user_dir[0] == '\0')
		user_dir = "/Applications";

	printf("System bundles (%s):\n", system_dir);
	ctx.count = 0;
	if (appbundle_scan_dir(system_dir, bundles_print_cb, &ctx) == -1)
		printf("  (directory not found)\n");
	else if (ctx.count == 0)
		printf("  (none)\n");

	printf("\nUser bundles (%s):\n", user_dir);
	ctx.count = 0;
	if (appbundle_scan_dir(user_dir, bundles_print_cb, &ctx) == -1)
		printf("  (directory not found)\n");
	else if (ctx.count == 0)
		printf("  (none)\n");

	return (0);
}
