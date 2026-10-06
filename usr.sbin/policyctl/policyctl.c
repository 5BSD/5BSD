/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcapbundle.h>

static void
usage(void)
{
	fprintf(stderr, "usage: policyctl init PROGRAM [ATTRIBUTE ...]\n"
	    "       policyctl validate|explain BUNDLE.cap\n");
	exit(64);
}

/* A single portable filename, printed as a quoted UCL string. */
static bool
program_name(const char *name)
{
	if (name[0] == '\0' || name[0] == '.' || name[0] == '-' ||
	    strlen(name) >= CAPBUNDLE_NAME_MAX)
		return (false);
	for (const char *p = name; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-'))
			return (false);
	return (true);
}

static void
explain(const struct capbundle *bundle)
{
	printf("{\"units\":[");
	for (unsigned i = 0; i < capbundle_nservices(bundle); i++) {
		const struct capbundle_service *svc = capbundle_service(bundle, i);
		/* Labels and attribute names use the parser's restricted alphabet. */
		printf("%s{\"label\":\"%s\",\"exec\":%s,\"attributes\":[",
		    i == 0 ? "" : ",", capbundle_svc_label(svc),
		    capbundle_svc_activates_on_exec(svc) ? "true" : "false");
		for (unsigned j = 0; j < capbundle_svc_nattributes(svc); j++)
			printf("%s\"%s\"", j == 0 ? "" : ",",
			    capbundle_svc_attribute(svc, j));
		printf("],\"endpoints\":[");
		for (unsigned j = 0; j < capbundle_svc_nprovides(svc); j++) {
			printf("%s{\"name\":\"%s\",\"requires\":[", j == 0 ? "" : ",",
			    capbundle_svc_provides(svc, j));
			for (unsigned k = 0; k < capbundle_svc_nrequires(svc, j); k++)
				printf("%s\"%s\"", k == 0 ? "" : ",",
				    capbundle_svc_requires(svc, j, k));
			printf("]}");
		}
		printf("]}");
	}
	puts("]}");
}

int
main(int argc, char **argv)
{
	struct capbundle *bundle;
	char error[512] = "";

	if (argc >= 3 && strcmp(argv[1], "init") == 0) {
		if (!program_name(argv[2]) || argc - 3 > CAPBUNDLE_MAX_ATTRIBUTES)
			errx(2, "invalid program name or too many attributes");
		/* Validate everything before emitting any policy. */
		for (int i = 3; i < argc; i++) {
			if (!capbundle_valid_service_name(argv[i], CAPBUNDLE_LABEL_MAX))
				errx(2, "invalid attribute: %s", argv[i]);
			for (int j = 3; j < i; j++)
				if (strcmp(argv[i], argv[j]) == 0)
					errx(2, "duplicate attribute: %s", argv[i]);
		}
		printf("program = \"%s\";\nactivation { exec = true; }\nattributes = [",
		    argv[2]);
		for (int i = 3; i < argc; i++)
			printf("%s\"%s\"", i == 3 ? "" : ", ", argv[i]);
		puts("];");
		return (0);
	}
	if (argc != 3 || (strcmp(argv[1], "validate") != 0 &&
	    strcmp(argv[1], "explain") != 0))
		usage();
	if (capbundle_open(argv[2], &bundle, error, sizeof(error)) == -1)
		errx(2, "%s: %s", argv[2], error);
	if (capbundle_verify(bundle, error, sizeof(error)) == -1) {
		capbundle_close(bundle);
		errx(2, "%s: %s", argv[2], error);
	}
	if (strcmp(argv[1], "validate") == 0)
		puts("valid");
	else
		explain(bundle);
	capbundle_close(bundle);
	return (ferror(stdout) ? 2 : 0);
}
