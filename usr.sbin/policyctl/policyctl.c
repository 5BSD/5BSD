/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <err.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libcapbundle.h>

static void
usage(void)
{
	fprintf(stderr, "usage: policyctl init\n"
	    "       policyctl validate|format FILE\n"
	    "       policyctl explain FILE USER\n");
	exit(64);
}

static gid_t
group_id(void *ctx __unused, const char *name)
{
	struct group *g = getgrnam(name);
	return (g == NULL ? (gid_t)-1 : g->gr_gid);
}

static void
names(const char *key, char values[][CAPBUNDLE_LABEL_MAX], unsigned count, bool all)
{
	unsigned i;
	printf("%s = [", key);
	if (all) printf("\"*\"");
	for (i = 0; i < count; i++)
		printf("%s\"%s\"", (i != 0 || all) ? ", " : "", values[i]);
	puts("];");
}

int
main(int argc, char **argv)
{
	struct capbundle_principal_policy *policy;
	struct capbundle_principal_grant grant;
	struct passwd *pw;
	gid_t groups[NGROUPS_MAX];
	char *formatted;
	int fd, ngroups = nitems(groups);

	if (argc == 2 && strcmp(argv[1], "init") == 0) {
		puts("principals { default { anointments = []; admin_rights = false; } }");
		return (0);
	}
	if (argc < 3 ||
	    (strcmp(argv[1], "validate") != 0 && strcmp(argv[1], "format") != 0 &&
	    strcmp(argv[1], "explain") != 0)) usage();
	if (argc != (strcmp(argv[1], "explain") == 0 ? 4 : 3)) usage();
	fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd == -1) err(2, "%s", argv[2]);
	if (capbundle_principal_policy_load(fd, &policy) != 0)
		errx(2, "%s: invalid or unreadable principal policy", argv[2]);
	close(fd);
	if (strcmp(argv[1], "validate") == 0) puts("valid");
	else if (strcmp(argv[1], "format") == 0) {
		formatted = capbundle_principal_policy_format(policy);
		if (formatted == NULL) errx(2, "cannot format policy");
		puts(formatted);
		free(formatted);
	} else {
		pw = getpwnam(argv[3]);
		if (pw == NULL) errx(2, "unknown local account: %s", argv[3]);
		if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) == -1)
			errx(2, "group membership exceeds supported limit");
		if (capbundle_principal_policy_resolve(policy, pw->pw_uid, groups,
		    ngroups, group_id, NULL, &grant) != 0) err(2, "resolve");
		printf("uid = %u;\n", (unsigned)pw->pw_uid);
		names("anointments", grant.anointments, grant.nanointments, grant.anoint_all);
		names("may_elevate", grant.may_elevate, grant.nmay_elevate, grant.elevate_all);
		printf("admin_rights = %s;\n", grant.admin_rights ? "true" : "false");
	}
	capbundle_principal_policy_free(policy);
	return (0);
}
