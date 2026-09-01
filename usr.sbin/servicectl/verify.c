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
format_net_address(const struct ort_net_claim *nc, char *buf, size_t bufsz)
{
	static const uint8_t zero[16];

	if (memcmp(nc->addr, zero, sizeof(zero)) == 0) {
		strlcpy(buf, "any", bufsz);
		return;
	}
	if (nc->domain == AF_INET) {
		if (inet_ntop(AF_INET, nc->addr, buf, bufsz) != NULL)
			return;
	} else if (nc->domain == AF_INET6) {
		if (inet_ntop(AF_INET6, nc->addr, buf, bufsz) != NULL)
			return;
	} else if (nc->domain == AF_BLUETOOTH) {
		snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
		    nc->addr[5], nc->addr[4], nc->addr[3], nc->addr[2],
		    nc->addr[1], nc->addr[0]);
		return;
	}
	strlcpy(buf, "invalid", bufsz);
}

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

		printf("      capabilities: paths=%u files=%u network=%u "
		    "vsock=%u services=%u open=%u "
		    "system=0x%x\n",
		    m.ncap_paths, m.ncap_files, m.ncap_net,
		    m.ncap_vsock, m.ncap_services, m.ncap_open,
		    m.cap_system);
		if (m.protect_flags != 0)
			printf("      protect: 0x%x\n", m.protect_flags);
		for (j = 0; j < m.ncap_paths; j++)
			printf("        path: %s\n", m.cap_paths[j]);
		for (j = 0; j < m.ncap_files; j++)
			printf("        file: %s actions=0x%jx\n",
			    m.cap_files[j].path,
			    (uintmax_t)m.cap_files[j].actions);
		for (j = 0; j < m.ncap_net; j++)
		{
			char address[INET6_ADDRSTRLEN];

			format_net_address(&m.cap_net[j], address, sizeof(address));
			printf("        network: domain=%s protocol=%s "
			    "ports=%u-%u direction=%s address=%s prefix=%u\n",
			    ort_net_domain_name(m.cap_net[j].domain),
			    ort_net_protocol_name(m.cap_net[j].protocol),
			    m.cap_net[j].port_min, m.cap_net[j].port_max,
			    ort_net_direction_name(m.cap_net[j].direction), address,
			    m.cap_net[j].prefix);
		}
		for (j = 0; j < m.ncap_vsock; j++)
			printf("        vsock: cid=%ju ports=%u-%u "
			    "direction=%s\n", (uintmax_t)m.cap_vsock[j].cid,
			    m.cap_vsock[j].port_min, m.cap_vsock[j].port_max,
			    ort_net_direction_name(m.cap_vsock[j].direction));
		for (j = 0; j < m.ncap_services; j++)
			printf("        service: %s\n", m.cap_services[j]);
		for (j = 0; j < m.ncap_open; j++) {
			char r[5];
			unsigned k = 0;

			if (m.cap_open[j].rights & SVC_OPEN_READ)
				r[k++] = 'r';
			if (m.cap_open[j].rights & SVC_OPEN_WRITE)
				r[k++] = 'w';
			if (m.cap_open[j].rights & SVC_OPEN_EXEC)
				r[k++] = 'x';
			if (m.cap_open[j].rights & SVC_OPEN_LOOKUP)
				r[k++] = 'l';
			r[k] = '\0';
			/* Non-exclusive: a delivered descriptor, not a claim. */
			printf("        open: %s name=%s type=%s rights=%s\n",
			    m.cap_open[j].path, m.cap_open[j].name,
			    m.cap_open[j].is_dir ? "dir" : "file", r);
		}
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
