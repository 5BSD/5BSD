/* SPDX-License-Identifier: BSD-2-Clause */
/* Read installed policy with the same public parser used by the manager. */
#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <libcapbundle.h>

static void
json_string(const char *value)
{
	const unsigned char *p;

	putchar('"');
	for (p = (const unsigned char *)value; *p != '\0'; p++) {
		if (*p == '"' || *p == '\\') {
			putchar('\\');
			putchar(*p);
		} else if (*p < 32)
			printf("\\u%04x", *p);
		else
			putchar(*p);
	}
	putchar('"');
}

static int
bundle_inventory(struct capbundle *bundle, void *arg)
{
	const struct capbundle_service *service;
	unsigned i, j;
	int *first = arg;

	if (!*first)
		putchar(',');
	*first = 0;
	printf("{\"path\":");
	json_string(capbundle_path(bundle));
	printf(",\"id\":");
	json_string(capbundle_id(bundle));
	printf(",\"services\":[");
	for (i = 0; i < capbundle_nservices(bundle); i++) {
		service = capbundle_service(bundle, i);
		if (i != 0)
			putchar(',');
		printf("{\"label\":");
		json_string(capbundle_svc_label(service));
		printf(",\"program\":");
		json_string(capbundle_svc_program(service));
		printf(",\"boot\":%s,\"endpoints\":[",
		    capbundle_svc_activates_at_boot(service) ? "true" : "false");
		for (j = 0; j < capbundle_svc_nprovides(service); j++) {
			if (j != 0)
				putchar(',');
			json_string(capbundle_svc_provides(service, j));
		}
		printf("]}");
	}
	printf("]}");
	return (ferror(stdout) ? -1 : 0);
}

int
main(int argc, char **argv)
{
	int first = 1, i;

	if (argc < 2)
		errx(64, "usage: service_inventory bundle-root ...");
	printf("{\"format\":1,\"bundles\":[");
	for (i = 1; i < argc; i++) {
		if (capbundle_scan_dir(argv[i], bundle_inventory, &first) != 0)
			err(1, "cannot inventory bundle root %s", argv[i]);
	}
	printf("]}\n");
	return (fflush(stdout) == EOF ? 1 : 0);
}
