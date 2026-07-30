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

static const char *
component_lifetime(uint32_t scope)
{

	switch (scope) {
	case SVC_COMPONENT_JAIL:
		return ("jail");
	case SVC_COMPONENT_SERVICE:
		return ("job");
	case SVC_COMPONENT_SYSTEM:
		return ("system");
	default:
		return ("process");
	}
}

static void
implementation_features(const struct serviced_interface *implementation,
    char *lifetimes, size_t lifetimes_size, char *sharing,
    size_t sharing_size)
{
	static const struct {
		uint32_t bit;
		const char *name;
	} lifetime_names[] = {
		{ SVC_COMPONENT_LIFETIME_BIT(SVC_COMPONENT_PRIVATE), "process" },
		{ SVC_COMPONENT_LIFETIME_BIT(SVC_COMPONENT_SERVICE), "job" },
		{ SVC_COMPONENT_LIFETIME_BIT(SVC_COMPONENT_JAIL), "jail" },
		{ SVC_COMPONENT_LIFETIME_BIT(SVC_COMPONENT_SYSTEM), "system" }
	};
	size_t i;

	lifetimes[0] = '\0';
	for (i = 0; i < nitems(lifetime_names); i++) {
		if ((implementation->lifetimes & lifetime_names[i].bit) == 0)
			continue;
		if (lifetimes[0] != '\0')
			strlcat(lifetimes, ",", lifetimes_size);
		strlcat(lifetimes, lifetime_names[i].name, lifetimes_size);
	}
	sharing[0] = '\0';
	if ((implementation->sharing &
	    SVC_COMPONENT_SHARING_EXCLUSIVE) != 0)
		strlcat(sharing, "exclusive", sharing_size);
	if ((implementation->sharing & SVC_COMPONENT_SHARING_SHARED) != 0) {
		if (sharing[0] != '\0')
			strlcat(sharing, ",", sharing_size);
		strlcat(sharing, "shared", sharing_size);
	}
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
	printf("  Path:    %s\n", capbundle_path(b));
	printf("  Services: %u\n", capbundle_nservices(b));
	printf("\n");

	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);
		struct svc_manifest m;
		const char *restart;

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

		printf("  [%u] %s\n", i, capbundle_svc_label(svc));
		printf("      program:   %s\n", capbundle_svc_program(svc));
		printf("      on_demand: %s\n",
		    capbundle_svc_on_demand(svc) ? "yes" : "no");
		printf("      restart:   %s\n", restart);
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

		if (capbundle_svc_nrequires(svc) > 0) {
			printf("      requires:");
			for (j = 0; j < capbundle_svc_nrequires(svc); j++)
				printf(" %s", capbundle_svc_requires(svc, j));
			printf("\n");
		}
		printf("      kmod_requires:");
		for (j = 0; j < m.nkmod_requires; j++)
			printf(" [%s]", m.kmod_requires[j]);
		printf("\n");
		printf("      capabilities: paths=%u files=%u network=%u "
		    "jails=%u vsock=%u services=%u system=0x%x\n", m.ncap_paths,
		    m.ncap_files, m.ncap_net, m.ncap_jail, m.ncap_vsock,
		    m.ncap_services, m.cap_system);
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
		for (j = 0; j < m.ncap_jail; j++)
			printf("        jail: jid=%d name=%s actions=0x%x\n",
			    m.cap_jail[j].jid, m.cap_jail[j].name,
			    m.cap_jail[j].actions);
		for (j = 0; j < m.ncap_vsock; j++)
			printf("        vsock: cid=%ju ports=%u-%u "
			    "direction=%s\n", (uintmax_t)m.cap_vsock[j].cid,
			    m.cap_vsock[j].port_min, m.cap_vsock[j].port_max,
			    ort_net_direction_name(m.cap_vsock[j].direction));
		for (j = 0; j < m.ncap_services; j++)
			printf("        service: %s\n", m.cap_services[j]);
		for (j = 0; j < m.nimplements; j++) {
			char lifetimes[32], sharing[32];

			implementation_features(&m.implements[j], lifetimes,
			    sizeof(lifetimes), sharing, sizeof(sharing));
			printf("      implements: %s version=%s lifetimes=%s "
			    "sharing=%s\n", m.implements[j].name,
			    m.implements[j].version, lifetimes, sharing);
		}
		for (j = 0; j < m.ncomponents; j++)
			printf("      component: %s interface=%s version=%s "
			    "provider=%s lifetime=%s sharing=%s required=%s "
			    "options=%s\n",
			    m.components[j].name, m.components[j].interface,
			    m.components[j].version,
			    m.components[j].provider,
			    component_lifetime(m.components[j].scope),
			    m.components[j].shared ? "shared" : "exclusive",
			    m.components[j].required ? "yes" : "no",
			    m.components[j].options);
		if (m.has_jail)
			printf("      jail: name=%s path=%s hostname=%s "
			    "ip4_addr=%s persistent=yes\n",
			    m.jail_name, m.jail_path,
			    m.jail_hostname[0] != '\0' ?
			    m.jail_hostname : m.jail_name,
			    m.jail_ip4_addr[0] != '\0' ?
			    m.jail_ip4_addr : "inherit");
	}

}

int
cmd_verify(int argc, char *argv[])
{
	struct capbundle **bundles;
	struct capbundle_policy *policy;
	const char *policy_path;
	char errbuf[512];
	int i, j, opened, result, first;

	policy = NULL;
	policy_path = NULL;
	first = 0;
	while (first < argc && argv[first][0] == '-') {
		if (strcmp(argv[first], "--effective") == 0) {
			first++;
			continue;
		}
		if (strcmp(argv[first], "--policy") == 0) {
			if (++first >= argc)
				errx(1, "--policy requires a path");
			policy_path = argv[first++];
			continue;
		}
		errx(1, "unknown verify option: %s", argv[first]);
	}
	if (first == argc)
		errx(1, "verify requires at least one bundle");
	argc -= first;
	argv += first;
	if (policy_path != NULL &&
	    capbundle_policy_open(policy_path, &policy, errbuf,
	    sizeof(errbuf)) == -1) {
		warnx("verify: policy FAILED — %s", errbuf);
		return (1);
	}
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
	if (capbundle_resolve_components_policy(bundles, (unsigned)argc,
	    policy, errbuf, sizeof(errbuf)) == -1) {
		warnx("verify: component resolution FAILED — %s", errbuf);
		goto out;
	}
	if (capbundle_check_cycles(bundles, (unsigned)argc, errbuf,
	    sizeof(errbuf)) == -1) {
		warnx("verify: dependency graph FAILED — %s", errbuf);
		goto out;
	}
	printf("Effective configuration%s%s%s:\n\n",
	    policy_path != NULL ? " (policy " : "",
	    policy_path != NULL ? policy_path : "",
	    policy_path != NULL ? ")" : "");
	for (i = 0; i < argc; i++)
		print_bundle(bundles[i]);
	printf("\nVerification: PASSED\n");
	result = 0;
out:
	for (i = 0; i < opened; i++)
		capbundle_close(bundles[i]);
	free(bundles);
	capbundle_policy_close(policy);
	return (result);
}

int
cmd_policy_check(const char *path)
{
	struct capbundle_policy *policy;
	char errbuf[512];

	policy = NULL;
	if (capbundle_policy_open(path, &policy, errbuf, sizeof(errbuf)) == -1) {
		warnx("policy-check: FAILED — %s", errbuf);
		return (1);
	}
	capbundle_policy_close(policy);
	printf("Policy: %s\nValidation: PASSED\n", path);
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
