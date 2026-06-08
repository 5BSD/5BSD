/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl install — install a .app bundle to the user bundle dir.
 *
 * Bundles run in-place.  Installation is simply copying the bundle
 * directory to the user bundle directory and requesting a reload from serviced.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libappbundle.h>

#include "serviced_ctl.h"
#include "servicectl.h"

#define	INSTALL_DIR	"/Applications"

static const char *
install_dir(void)
{
	const char *dir;

	dir = getenv("SERVICED_BUNDLE_DIR_USER");
	if (dir != NULL && dir[0] != '\0')
		return (dir);
	return (INSTALL_DIR);
}

int
cmd_install(const char *bundle_path)
{
	struct appbundle *b;
	struct stat sb;
	char errbuf[256];
	char dst[PATH_MAX];
	const char *idir;
	const char *bname;
	pid_t pid;
	int status;

	/* Validate bundle first. */
	if (appbundle_open(bundle_path, &b, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: invalid bundle: %s", errbuf);
		return (1);
	}

	if (appbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: verification failed: %s", errbuf);
		appbundle_close(b);
		return (1);
	}

	printf("install: %s (%s v%s, %u services)\n",
	    appbundle_name(b), appbundle_id(b), appbundle_version(b),
	    appbundle_nservices(b));
	appbundle_close(b);

	idir = install_dir();

	/* Ensure /Applications exists. */
	if (stat(idir, &sb) == -1) {
		if (mkdir(idir, 0755) == -1) {
			warn("install: cannot create %s", idir);
			return (1);
		}
	}

	/* Derive destination path.  Reject names that could escape
	 * the install directory. */
	{
		const char *p = strrchr(bundle_path, '/');
		bname = (p != NULL) ? p + 1 : bundle_path;
	}
	if (bname[0] == '\0' || bname[0] == '.' ||
	    strchr(bname, '/') != NULL) {
		warnx("install: invalid bundle name: %s", bname);
		return (1);
	}
	snprintf(dst, sizeof(dst), "%s/%s", idir, bname);

	/* Check if already installed. */
	if (stat(dst, &sb) == 0) {
		warnx("install: %s already exists", dst);
		return (1);
	}

	/* Copy bundle directory using cp -R. */
	pid = fork();
	if (pid == -1) {
		warn("install: fork");
		return (1);
	}
	if (pid == 0) {
		execl("/bin/cp", "cp", "-Rp", bundle_path, dst, (char *)NULL);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) == -1) {
		warn("install: waitpid");
		return (1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		warnx("install: cp failed");
		return (1);
	}

	printf("install: copied to %s\n", dst);
	printf("install: run 'servicectl reload' to activate\n");
	return (0);
}
