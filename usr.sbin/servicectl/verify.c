/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl verify/bundles — validate .cap bundle integrity and
 * list installed bundles.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcapbundle.h>
#include <serviced_manifest.h>

#include "servicectl.h"

static void
print_bundle(const struct capbundle *b)
{
	unsigned i, j;

	/* Report contents. */
	printf("Bundle: %s\n", capbundle_name(b));
	printf("  ID:      %s\n", capbundle_id(b));
	printf("  Version: %s\n", capbundle_version(b));
	printf("  Author:  %s\n", capbundle_author(b));
	printf("  Publisher: %s\n", capbundle_publisher(b)[0] != '\0' ?
	    capbundle_publisher(b) : "(unspecified)");
	printf("  Sequence: %ju\n", (uintmax_t)capbundle_sequence(b));
	printf("  Path:    %s\n", capbundle_path(b));
	printf("  Services: %u\n", capbundle_nservices(b));
	printf("\n");

	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);
		struct svc_manifest m;
		const char *restart;
		const char *management;

		if (capbundle_svc_fill_manifest(svc, &m) == -1)
			err(1, "capbundle_svc_fill_manifest");
		switch (m.restart) {
		case SVC_RESTART_ALWAYS:
			restart = "always";
			break;
		case SVC_RESTART_ON_FAILURE:
			restart = "on-failure";
			break;
		default:
			restart = "never";
			break;
		}
		switch (m.management) {
		case SVC_MGMT_CORE:
			management = "core";
			break;
		case SVC_MGMT_USER:
			management = "user";
			break;
		default:
			management = "system";
			break;
		}

		printf("  [%u] %s\n", i, capbundle_svc_label(svc));
		printf("      program:   %s\n", capbundle_svc_program(svc));

		/*
		 * A unit may declare several activation sources; report each.
		 * boot launches at boot; an IPC name, a timer, or a path each
		 * create demand while the unit is stopped.
		 */
		printf("      activation:");
		if (capbundle_svc_activates_at_boot(svc))
			printf(" boot");
		if (capbundle_svc_nprovides(svc) != 0)
			printf(" ipc");
		if (capbundle_svc_timer_interval(svc) != 0)
			printf(" timer=%us", capbundle_svc_timer_interval(svc));
		if (capbundle_svc_activation_path(svc)[0] != '\0')
			printf(" path=%s", capbundle_svc_activation_path(svc));
		printf("\n");
		printf("      restart:   %s\n", restart);
		printf("      management: %s\n", management);
		printf("      stop_timeout: %d\n", m.stop_timeout);
		printf("      max_failures: %u\n", m.max_failures);
		printf("      user: %s\n", m.user[0] != '\0' ? m.user : "(default)");
		printf("      group: %s\n",
		    m.group[0] != '\0' ? m.group : "(default)");
		printf("      arguments:");
		for (j = 0; j < capbundle_svc_narguments(svc); j++)
			printf(" [%s]", capbundle_svc_argument(svc, j));
		printf("\n");
		printf("      environment:");
		for (j = 0; j < capbundle_svc_nenvironment(svc); j++)
			printf(" [%s]", capbundle_svc_environment(svc, j));
		printf("\n");

		printf("      provides:");
		for (j = 0; j < capbundle_svc_nprovides(svc); j++)
			printf(" %s", capbundle_svc_provides(svc, j));
		printf("\n");

		printf("      capabilities: system=0x%x\n", m.cap_system);
		if (m.protect_flags != 0)
			printf("      protect: 0x%x\n", m.protect_flags);
	}

}

int
cmd_verify(int argc, char *argv[])
{
	struct capbundle **bundles;
	char errbuf[512];
	int i, j, opened, result;

	if (argc == 0)
		errx(1, "verify requires at least one bundle");
	bundles = calloc((size_t)argc, sizeof(*bundles));
	if (bundles == NULL)
		err(1, "calloc");
	opened = 0;
	result = 1;
	for (i = 0; i < argc; i++) {
		if (capbundle_open(argv[i], &bundles[i], errbuf,
		    sizeof(errbuf)) == -1) {
			warnx("verify: %s", errbuf);
			goto out;
		}
		opened++;
		if (capbundle_verify(bundles[i], errbuf, sizeof(errbuf)) == -1) {
			warnx("verify: FAILED — %s", errbuf);
			goto out;
		}
		for (j = 0; j < i; j++) {
			if (strcmp(capbundle_id(bundles[i]),
			    capbundle_id(bundles[j])) == 0) {
				warnx("verify: duplicate bundle_id '%s'",
				    capbundle_id(bundles[i]));
				goto out;
			}
		}
	}
	printf("Effective configuration:\n\n");
	for (i = 0; i < argc; i++)
		print_bundle(bundles[i]);
	printf("\nVerification: PASSED\n");
	result = 0;
out:
	for (i = 0; i < opened; i++)
		capbundle_close(bundles[i]);
	free(bundles);
	return (result);
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
		    capbundle_svc_nprovides(svc) != 0 ?
		    " (global provider)" : " (boot task)");
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
