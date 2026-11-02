/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <bsm/audit.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <libservice.h>
#include <extensioncmp.h>
#include <sysext_proto.h>

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: sysextctl status | list | config | reload | restore\n"
	    "       sysextctl status|load|unload|allow|deny|reset|enable|disable module\n");
	exit(EX_USAGE);
}

/* Report matching files, independently of policy and kernel residency. */
static const char *
installed_state(const char *name)
{
	struct stat st;
	char file[MAXPATHLEN], *paths, *cursor, *dir;
	const char *suffixes[] = { "", ".ko" };
	size_t len, i;
	int n, uncertain = 0;

	if (sysctlbyname("kern.module_path", NULL, &len, NULL, 0) == -1 ||
	    len == 0 || (paths = malloc(len + 1)) == NULL)
		return ("unknown");
	if (sysctlbyname("kern.module_path", paths, &len, NULL, 0) == -1) {
		free(paths);
		return ("unknown");
	}
	paths[len] = '\0';
	cursor = paths;
	while ((dir = strsep(&cursor, ";")) != NULL) {
		/* Relative paths cannot reliably describe the broker's view. */
		if (dir[0] != '/') {
			uncertain = 1;
			continue;
		}
		for (i = 0; i < nitems(suffixes); i++) {
			n = snprintf(file, sizeof(file), "%s/%s%s", dir, name,
			    suffixes[i]);
			if (n < 0 || (size_t)n >= sizeof(file)) {
				uncertain = 1;
				continue;
			}
			if (stat(file, &st) == 0) {
				if (S_ISREG(st.st_mode)) {
					free(paths);
					return ("yes");
				}
			} else if (errno != ENOENT && errno != ENOTDIR)
				uncertain = 1;
		}
	}
	free(paths);
	return (uncertain ? "unknown" : "no");
}

static void
print_info(const struct service_extension_info *info)
{
	printf("%s: %s, boot=%s, loaded=%s, installed=%s, policy=%s%s\n", info->name,
	    info->allowed ? "allowed" : "denied",
	    info->enabled ? (info->allowed ? "enabled" : "blocked") : "disabled",
	    info->allowed ? (info->loaded ? "yes" : "no") : "undisclosed",
	    installed_state(info->name),
	    info->overridden ? "override" : "default",
	    info->ready ? "" : " (bootstrap; persistent policy not ready)");
}

/* Why a decision came out as it did; shared by status and root loads. */
static const char *
result_text(int result, int error, char *buf, size_t len)
{

	switch (result) {
	case SYSEXT_DECISION_LOADED:
		return ("loaded");
	case SYSEXT_DECISION_PRESENT:
		return ("already loaded");
	case SYSEXT_DECISION_NOT_PERMITTED:
		return ("refused: not on the allow-list and not a hardware "
		    "driver of this kernel");
	case SYSEXT_DECISION_DRIVERS_ONLY:
		return ("refused: client may load hardware drivers only");
	case SYSEXT_DECISION_OVERRIDE:
		return ("refused: denied by an administrator override");
	case SYSEXT_DECISION_FAILED:
		(void)snprintf(buf, len, "load failed: %s", strerror(error));
		return (buf);
	case SYSEXT_DECISION_NOT_PACKAGED:
		return ("refused: not a file of an installed 5BSD base package");
	case SYSEXT_DECISION_CHECKSUM:
		return ("refused: the file does not match the checksum its "
		    "package recorded (modified or replaced; reinstall the "
		    "package)");
	case SYSEXT_DECISION_NOT_KERNEL_DIR:
		return ("refused: no regular module file of that name in the "
		    "running kernel's directory (/boot/kernel), a dependency "
		    "outside it, or that directory no longer holds the running "
		    "kernel (reboot after a kernel upgrade)");
	case SYSEXT_DECISION_UNLOADED:
		return ("unloaded");
	case SYSEXT_DECISION_NOT_ROOT_LOADED:
		return ("refused: not loaded with sysextctl load since the "
		    "broker started, or used by another client");
	case SYSEXT_DECISION_DISABLED:
		return ("refused: root loads are not configured "
		    "(root_load_repository in bsdextension.ucl)");
	case SYSEXT_DECISION_PKGDB:
		return ("refused: the package database could not be read");
	case SYSEXT_DECISION_CHANGED:
		return ("refused: a module file changed, or the kernel loaded "
		    "a file that was not checked, during the load; the load "
		    "was undone");
	case SYSEXT_DECISION_PROTECTED:
		return ("refused: protected module (security policies, "
		    "tracing, storage, packet filters and the hypervisor are "
		    "never loaded or unloaded from a login session)");
	default:
		return ("unknown");
	}
}

static const char *
decision_text(const struct service_extension_decision *d, char *buf,
    size_t len)
{

	return (result_text(d->result, d->error, buf, len));
}

static const char *
operation_text(int operation)
{

	switch (operation) {
	case SYSEXT_OP_RESTORE:
		return ("restore");
	case SYSEXT_OP_ROOT_LOAD:
		return ("root load");
	case SYSEXT_OP_ROOT_UNLOAD:
		return ("root unload");
	default:
		return ("load");
	}
}

static void
print_decision(const struct service_extension_decision *d)
{
	char when[32], buf[128];
	struct tm tm;

	if (localtime_r(&d->time, &tm) == NULL ||
	    strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm) == 0)
		strlcpy(when, "?", sizeof(when));
	printf("  %s %s %s (client %s): %s\n", when,
	    operation_text(d->operation), d->name,
	    d->client[0] != '\0' ? d->client : "?",
	    decision_text(d, buf, sizeof(buf)));
}

/*
 * Print the retained decisions, all or those for one module.  Returns 0, or -1
 * with errno (ENOENT ends the walk and is not an error).
 */
static int
print_decisions(struct extensioncmp_session *session, const char *module,
    unsigned *countp)
{
	struct service_extension_decision d;
	uint64_t after = 0;

	*countp = 0;
	while (extensioncmp_decision(session, after, &d) == 0) {
		after = d.sequence;
		if (module != NULL && strcmp(module, d.name) != 0)
			continue;
		print_decision(&d);
		(*countp)++;
	}
	return (errno == ENOENT ? 0 : -1);
}

static int
name_cmp(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/*
 * The kernel's view, which needs no broker: modules compiled into the kernel
 * (file id 1) and the module files loaded since boot.  kldnext(2), kldstat(2)
 * and modstat(2) are unprivileged queries.
 */
static int
print_kernel_modules(void)
{
	struct kld_file_stat fs;
	struct module_stat ms;
	char **names = NULL, **grown;
	size_t n = 0, cap = 0, i, col;
	int fileid, modid, nfiles = 0;

	/* File id 1 is the kernel: its modules are compiled in. */
	for (modid = kldfirstmod(1); modid > 0; modid = modfnext(modid)) {
		memset(&ms, 0, sizeof(ms));
		ms.version = sizeof(ms);
		if (modstat(modid, &ms) == -1)
			continue;
		if (n == cap) {
			cap = cap == 0 ? 256 : cap * 2;
			grown = reallocarray(names, cap, sizeof(*names));
			if (grown == NULL)
				err(EX_OSERR, "built-in module list");
			names = grown;
		}
		if ((names[n] = strdup(ms.name)) == NULL)
			err(EX_OSERR, "built-in module list");
		n++;
	}
	if (n != 0)
		qsort(names, n, sizeof(*names), name_cmp);
	printf("built into the kernel: %zu module(s)\n", n);
	for (i = 0, col = 0; i < n; i++) {
		if (col == 0)
			col = (size_t)printf(" ");
		col += (size_t)printf(" %s", names[i]);
		if (col > 68 || i + 1 == n) {
			printf("\n");
			col = 0;
		}
		free(names[i]);
	}
	free(names);
	for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
		if (fileid == 1)
			continue;
		memset(&fs, 0, sizeof(fs));
		fs.version = sizeof(fs);
		if (kldstat(fileid, &fs) == -1)
			continue;
		if (nfiles++ == 0)
			printf("loaded module files:\n");
		printf("  %s (id %d)\n", fs.name, fileid);
	}
	if (nfiles == 0)
		printf("loaded module files: none\n");
	return (0);
}

/*
 * Read-only verbs use the caller's full session when it has one (rc, devd),
 * and otherwise the read-only view that switchboard gives a UID 0 login
 * session.  Load and policy verbs never use the read-only view.
 */
static int
open_read_only(struct extensioncmp_session **sessionp)
{

	if (extensioncmp_session_open(sessionp) == 0)
		return (0);
	return (extensioncmp_session_open_status(sessionp));
}

/* `status` without a module: the read-only overview. */
static int
overview(void)
{
	struct extensioncmp_session *session;
	unsigned count;
	int result;

	if (extensioncmp_session_open_status(&session) == -1)
		err(EX_UNAVAILABLE, "cannot reach the SystemExtension status view");
	printf("SystemExtension status (read-only)\n");
	(void)print_kernel_modules();
	printf("recent load decisions (oldest first):\n");
	result = print_decisions(session, NULL, &count);
	if (result == 0 && count == 0)
		printf("  none since the broker started\n");
	if (result == -1) {
		int error = errno;

		extensioncmp_session_close(session);
		errno = error;
		err(error == EPROTO ? EX_PROTOCOL : EX_UNAVAILABLE,
		    "SystemExtension decisions");
	}
	extensioncmp_session_close(session);
	return (0);
}

/*
 * Record a root load or unload with the identity of the login session that
 * asked: the login name and terminal, and the audit user and session when the
 * kernel has audit support.  The broker logs the same decision with the
 * switchboard label and the program nonce; this is the caller's side of it.
 */
static void
log_root_request(const char *verb, const char *name, const char *outcome)
{
	auditinfo_addr_t ai;
	char auid[16] = "none", asid[16] = "none";
	const char *login, *tty;

	memset(&ai, 0, sizeof(ai));
	if (getaudit_addr(&ai, sizeof(ai)) == 0) {
		if (ai.ai_auid != AU_DEFAUDITID)
			(void)snprintf(auid, sizeof(auid), "%u",
			    (unsigned)ai.ai_auid);
		(void)snprintf(asid, sizeof(asid), "%d", (int)ai.ai_asid);
	}
	login = getlogin();
	tty = ttyname(STDIN_FILENO);
	openlog("sysextctl", LOG_PID, LOG_AUTH);
	syslog(LOG_NOTICE, "%s %s by uid %u (login %s, audit user %s, audit "
	    "session %s, tty %s): %s", verb, name, (unsigned)getuid(),
	    login != NULL ? login : "?", auid, asid, tty != NULL ? tty : "none",
	    outcome);
	closelog();
}

/*
 * load (as root without the full endpoint) and unload: the root-load endpoint
 * that switchboard gives a UID 0 login session (root-load.ucl).  The broker
 * loads only a /boot/kernel module file of an installed 5BSD base package that
 * matches the package's checksum, and unloads only what such a load loaded.
 */
static int
root_request(struct extensioncmp_session *session, int load, const char *name)
{
	struct service_extension_root_outcome outcome;
	char buf[128];
	const char *text;
	int result;

	result = load ? extensioncmp_root_load(session, name, &outcome) :
	    extensioncmp_root_unload(session, name, &outcome);
	if (result == -1) {
		int error = errno;

		log_root_request(load ? "load" : "unload", name,
		    strerror(error));
		extensioncmp_session_close(session);
		errno = error;
		if (error == EINVAL || error == ENAMETOOLONG)
			err(EX_USAGE, "invalid module name or request");
		err(error == EPROTO ? EX_PROTOCOL :
		    error == EAGAIN ? EX_TEMPFAIL : EX_UNAVAILABLE,
		    "SystemExtension %s", load ? "load" : "unload");
	}
	extensioncmp_session_close(session);
	text = result_text(outcome.result, outcome.error, buf, sizeof(buf));
	if (!load && outcome.result == SYSEXT_DECISION_FAILED) {
		(void)snprintf(buf, sizeof(buf), "unload failed: %s",
		    strerror(outcome.error));
		text = buf;
	}
	log_root_request(load ? "load" : "unload", name, text);
	switch (outcome.result) {
	case SYSEXT_DECISION_LOADED:
		printf("%s: loaded\n", name);
		return (0);
	case SYSEXT_DECISION_PRESENT:
		printf("%s: already loaded\n", name);
		return (0);
	case SYSEXT_DECISION_UNLOADED:
		printf("%s: unloaded\n", name);
		return (0);
	case SYSEXT_DECISION_FAILED:
		errx(EX_OSERR, "%s: %s", name, text);
	default:
		errx(EX_NOPERM, "%s: %s", name, text);
	}
}

int
main(int argc, char **argv)
{
	struct extensioncmp_session *session;
	struct service_extension_info info;
	enum service_extension_action action = SERVICE_EXTENSION_RESTORE;
	char cursor[SERVICE_EXTENSION_NAME_MAX] = "";
	const char *verb, *name = NULL;
	int error, result = 0, operation;

	if (argc < 2)
		usage();
	verb = argv[1];
	if (argc == 2 && strcmp(verb, "status") == 0)
		return (overview());
	if (argc == 2 && strcmp(verb, "list") == 0)
		operation = 0;
	else if (argc == 2 && strcmp(verb, "config") == 0)
		operation = 1;
	else if (argc == 3 && strcmp(verb, "status") == 0)
		operation = 2;
	else if (argc == 3 && strcmp(verb, "load") == 0)
		operation = 3;
	else if (argc == 2 && strcmp(verb, "reload") == 0)
		operation = 4;
	else if (argc == 3 && strcmp(verb, "unload") == 0)
		operation = 6;
	else {
		operation = 5;
		if (argc == 2 && strcmp(verb, "restore") == 0)
			action = SERVICE_EXTENSION_RESTORE;
		else if (argc != 3)
			usage();
		else if (strcmp(verb, "allow") == 0)
			action = SERVICE_EXTENSION_ALLOW;
		else if (strcmp(verb, "deny") == 0)
			action = SERVICE_EXTENSION_DENY;
		else if (strcmp(verb, "reset") == 0)
			action = SERVICE_EXTENSION_RESET;
		else if (strcmp(verb, "enable") == 0)
			action = SERVICE_EXTENSION_ENABLE;
		else if (strcmp(verb, "disable") == 0)
			action = SERVICE_EXTENSION_DISABLE;
		else
			usage();
	}
	if (argc == 3)
		name = argv[2];
	/* Only a module name selects a file, and only in /boot/kernel. */
	if ((operation == 3 || operation == 6) && strchr(name, '/') != NULL)
		errx(EX_USAGE, "invalid module name or request: %s is a path; "
		    "name a module in /boot/kernel (paths are refused)", name);
	/* unload exists only on the root-load endpoint. */
	if (operation == 6) {
		if (extensioncmp_session_open_rootload(&session) == -1)
			err(EX_UNAVAILABLE, "cannot reach the SystemExtension "
			    "root-load endpoint");
		return (root_request(session, 0, name));
	}
	if ((operation <= 2 ? open_read_only(&session) :
	    extensioncmp_session_open(&session)) == -1) {
		error = errno;
		/*
		 * A root login session has no full endpoint; switchboard gives
		 * it the root-load endpoint for base package modules.
		 */
		if (operation == 3 && error == ENOENT && geteuid() == 0 &&
		    extensioncmp_session_open_rootload(&session) == 0)
			return (root_request(session, 1, name));
		if (operation > 2 && error == ENOENT && geteuid() == 0)
			warnx("a login session may only inspect (sysextctl "
			    "status) and load or unload base package modules "
			    "(sysextctl load|unload)");
		errno = error;
		err(EX_UNAVAILABLE, "cannot reach SystemExtension capability");
	}
	switch (operation) {
	case 0:
	case 1:
		while ((result = extensioncmp_info(session, cursor, 1,
		    &info)) == 0) {
			if (operation == 1)
				print_info(&info);
			else if (info.allowed)
				printf("%s: %s, installed=%s\n", info.name,
				    info.loaded ? "loaded" : "allowed",
				    installed_state(info.name));
			strlcpy(cursor, info.name, sizeof(cursor));
		}
		if (errno == ENOENT)
			result = 0;
		break;
	case 2:
		result = extensioncmp_info(session, name, 0, &info);
		if (result == 0) {
			unsigned count;

			print_info(&info);
			/* Why a load did or did not happen: the read-only view. */
			if (extensioncmp_session_read_only(session) &&
			    print_decisions(session, name, &count) == 0 &&
			    count == 0)
				printf("  no recent load decision\n");
		}
		break;
	case 3:
		result = extensioncmp_load(session, name);
		break;
	case 4:
		result = extensioncmp_reload(session);
		break;
	default:
		result = extensioncmp_manage(session, action, name);
		break;
	}
	error = errno;
	extensioncmp_session_close(session);
	if (result == -1) {
		errno = error;
		if (error == EINVAL || error == ENAMETOOLONG)
			err(EX_USAGE, "invalid module name or request");
		err(error == EPROTO ? EX_PROTOCOL :
		    error == EAGAIN ? EX_TEMPFAIL : EX_UNAVAILABLE,
		    "SystemExtension %s", verb);
	}
	if (operation == 3)
		printf("%s: loaded\n", name);
	else if (operation == 4)
		puts("SystemExtension defaults reloaded; administrator overrides preserved");
	else if (operation == 5) {
		if (action == SERVICE_EXTENSION_RESTORE)
			puts("SystemExtension boot activations restored");
		else
			printf("%s: %s saved; existing loads remain until reboot\n", name, verb);
	}
	if (operation == 2 && (!info.allowed || !info.loaded))
		return (1);
	return (0);
}
