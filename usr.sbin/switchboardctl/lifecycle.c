/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sha256.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include "switchboardctl.h"
#include "switchboard_lifecycle.h"

/* Walk from the selected root; never follow a directory symlink into the host. */
static void
check_directory(const char *root, bool create)
{
	static const char *const parts[] = { "Capabilities", "Config", "switchboard", "lifecycle" };
	int fd, next;
	bool created;
	struct stat st;

	fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1)
		err(EX_NOINPUT, "lifecycle root");
	for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
		created = create && mkdirat(fd, parts[i], i == 3 ? 0700 : 0755) == 0;
		if (create && !created && errno != EEXIST)
			err(EX_CANTCREAT, "lifecycle directory");
		next = openat(fd, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next == -1 || fstat(next, &st) == -1 ||
		    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
		    (st.st_uid != 0 && !(i == 3 && st.st_uid == 976)))
			errx(EX_NOPERM, "untrusted lifecycle directory");
		if (created && i == 3 && fchown(next, 976, 976) == -1)
			err(EX_CANTCREAT, "lifecycle owner");
		if (created && fsync(fd) == -1)
			err(EX_IOERR, "lifecycle directory persistence");
		close(fd);
		fd = next;
	}
	close(fd);
}

int
lifecycle_open_root(const char *selected, struct sl_db *db)
{
	char root[PATH_MAX], path[PATH_MAX];

	if (realpath(selected, root) == NULL)
		return (-1);
	if (snprintf(path, sizeof(path), "%s%s", strcmp(root, "/") == 0 ? "" : root,
	    SL_DIRECTORY) >= (int)sizeof(path))
		return (errno = ENAMETOOLONG, -1);
	check_directory(root, true);
	return (sl_open(path, db));
}

void
lifecycle_reference(const char *source, char out[SL_LABEL_MAX])
{
	char digest[SHA256_DIGEST_STRING_LENGTH];

	SHA256_Data(source, strlen(source), digest);
	/* A stable 128-bit source identifier, separate from installation IDs. */
	memcpy(out, digest, 32);
	out[32] = '\0';
}

static int
run_transaction(struct sl_db *db, const char *root, char **command)
{
	char operation[33];
	int lockfd, status;
	struct stat st;
	pid_t child, waited;

	const char *program = strrchr(command[0], '/');
	program = program == NULL ? command[0] : program + 1;
	if (strcmp(program, "pkg") == 0 &&
	    access("/usr/libexec/switchboard-pkg-reclaim", X_OK) == -1)
		err(EX_UNAVAILABLE, "bootstrap switchboardctl and its lifecycle helper before managed pkg operations");
	lockfd = openat(db->dirfd, "execution-lock", O_RDWR | O_CREAT |
	    O_NOFOLLOW | O_CLOEXEC, 0600);
	if (lockfd == -1 || fstat(lockfd, &st) == -1 ||
	    !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
	    (st.st_uid != 0 && st.st_uid != 976))
		err(EX_IOERR, "lifecycle execution lock");
	/* Do not hold the database lock while another package invocation exits. */
	sl_close(db);
	if (flock(lockfd, LOCK_EX) == -1)
		err(EX_IOERR, "lifecycle execution lock");
	if (lifecycle_open_root(root, db) == -1 ||
	    sl_issue_operation(db, operation) == -1 || sl_commit(db) == -1)
		err(EX_IOERR, "issue lifecycle operation");
	sl_close(db);
	fprintf(stderr, "lifecycle operation %s\n", operation);
	child = fork();
	if (child == -1)
		err(EX_OSERR, "lifecycle fork");
	if (child == 0) {
		if (setenv("SWITCHBOARD_LIFECYCLE_OPERATION", operation, 1) == -1 ||
		    setenv("SWITCHBOARD_LIFECYCLE_ROOT", root, 1) == -1)
			_exit(EX_OSERR);
		execvp(command[0], command);
		_exit(EX_UNAVAILABLE);
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited == -1 && errno == EINTR);
	/* pkg can exit zero after a failed post-install script. Inspect our intent. */
	bool pending = false;
	if (lifecycle_open_root(root, db) == -1) {
		close(lockfd);
		warn("lifecycle completion check");
		return (EX_IOERR);
	}
	for (size_t i = 0; i < db->count; i++) {
		struct sl_record *r = &db->records[i];
		if (r->kind == SL_OPERATION && strcmp(r->provider, operation) == 0 &&
		    (r->phase == SL_INSTALL_PENDING || r->phase == SL_REMOVE_PENDING))
			pending = true;
	}
	sl_close(db);
	close(lockfd);
	if (pending) {
		warnx("lifecycle operation %s requires recovery; inspect lifecycle status %s",
		    operation, root);
		return (EX_TEMPFAIL);
	}
	if (waited == -1)
		return (EX_OSERR);
	if (!WIFEXITED(status))
		return (EX_SOFTWARE);
	return (WEXITSTATUS(status));
}

int
cmd_lifecycle(int argc, char **argv)
{
	struct sl_db db;
	char root[PATH_MAX], token[33], reference[SL_LABEL_MAX];
	uint8_t nonce[16], generation[16];
	const char *op, *operation = NULL;
	int error = 0, first;
	bool status, install, adopt, run, query, issue, prune;

	if (geteuid() != 0)
		errx(EX_NOPERM, "lifecycle management requires root");
	if (argc < 3)
		errx(EX_USAGE, "lifecycle operation root [transaction] source [labels ...]");
	op = argv[1];
	issue = strcmp(op, "issue") == 0;
	prune = strcmp(op, "prune") == 0;
	query = strcmp(op, "query") == 0;
	status = strcmp(op, "status") == 0 || query;
	install = strcmp(op, "install") == 0;
	adopt = strcmp(op, "adopt") == 0 || strcmp(op, "begin-adopt") == 0;
	run = strcmp(op, "run") == 0;
	if (!status && !install && !adopt && !run && !issue && !prune && strcmp(op, "prepare") != 0 &&
	    strcmp(op, "retire") != 0 && strcmp(op, "cancel") != 0 &&
	    strcmp(op, "begin-install") != 0 && strcmp(op, "finish-install") != 0 &&
	    strcmp(op, "cancel-install") != 0)
		errx(EX_USAGE, "unknown lifecycle operation");
	first = install || strcmp(op, "adopt") == 0 ? 4 : 5;
	if ((run && argc < 4) || (!run && !status && !issue && !prune && argc <= first))
		errx(EX_USAGE, "lifecycle operation requires source and labels");
	if ((status && !query && argc != 3) || (query && (argc < 4 || argc > 5)))
		errx(EX_USAGE, "lifecycle status root; lifecycle query root label [installation-id]");
	if ((issue && argc != 3) || (prune && (argc < 3 || argc > 4)))
		errx(EX_USAGE, "lifecycle issue root; lifecycle prune root [keep-count]");
	if (!run && !status && !issue && !prune) {
		if (first == 4) {
			operation = token;
		} else {
			operation = argv[3];
			if (sl_generation_parse(operation, nonce) == -1)
				errx(EX_USAGE, "invalid lifecycle transaction ID");
		}
		lifecycle_reference(argv[first - 1], reference);
		for (int i = first; i < argc; i++)
			if (!sl_label_valid(argv[i]))
				errx(EX_USAGE, "invalid lifecycle label");
	}
	if (realpath(argv[2], root) == NULL)
		err(EX_NOINPUT, "lifecycle root");
	const char *expected = getenv("SWITCHBOARD_LIFECYCLE_ROOT");
	const char *chrooted = getenv("PKG_CHROOTED");
	if (!run && expected != NULL &&
	    !(chrooted != NULL && strcmp(chrooted, "true") == 0 && strcmp(root, "/") == 0)) {
		char canonical[PATH_MAX];
		if (realpath(expected, canonical) == NULL || strcmp(root, canonical) != 0)
			errx(EX_USAGE, "lifecycle transaction root mismatch");
	}
	if (status) {
		char path[PATH_MAX];
		check_directory(root, false);
		if (snprintf(path, sizeof(path), "%s%s", strcmp(root, "/") == 0 ? "" : root,
		    SL_DIRECTORY) >= (int)sizeof(path))
			errx(EX_USAGE, "lifecycle path too long");
		if (sl_open_readonly(path, &db) == -1)
			err(EX_IOERR, "installation authority unavailable");
	} else if (lifecycle_open_root(root, &db) == -1)
		err(EX_IOERR, "lifecycle database");
	if (issue) {
		if (sl_issue_operation(&db, token) == -1 || sl_commit(&db) == -1)
			err(EX_IOERR, "issue lifecycle operation");
		puts(token);
		sl_close(&db);
		return (0);
	}
	if (prune) {
		size_t removed;
		unsigned long retain = SL_HISTORY_KEEP;
		if (argc == 4) {
			char *end;
			errno = 0;
			retain = strtoul(argv[3], &end, 10);
			if (errno != 0 || end == argv[3] || *end != '\0' ||
			    retain == 0 || retain > SL_HISTORY_KEEP)
				errx(EX_USAGE, "keep-count must be 1..%u", SL_HISTORY_KEEP);
		}
		if (sl_prune_history(&db, retain, &removed) == -1 || sl_commit(&db) == -1)
			err(EX_IOERR, "prune lifecycle history");
		printf("discarded %zu history records\n", removed);
		sl_close(&db);
		return (0);
	}
	if (!status && !run && first == 4 && sl_issue_operation(&db, token) == -1)
		err(EX_IOERR, "issue lifecycle operation");
	if (query) {
		struct sl_installation result;
		if (!sl_label_valid(argv[3]) || (argc == 5 &&
		    sl_generation_parse(argv[4], generation) == -1))
			errx(EX_USAGE, "invalid installation identity");
		if (sl_query(&db, argv[3], argc == 5 ? generation : NULL, &result) == -1)
			err(EX_IOERR, "installation query");
		sl_generation_format(result.generation, token);
		printf("%s %s %s live-sources=%u staged-sources=%u\n", argv[3],
		    result.state == SL_UNKNOWN ? "-" : token, sl_state_name(result.state),
		    result.live_sources, result.staged_sources);
		sl_close(&db);
		return (0);
	}
	if (run)
		return (run_transaction(&db, root, &argv[3]));
	if (status) {
		static const char *const kinds[] = {
			"invalid", "owner", "provider", "delivery", "operation", "reference", "holding", "policy", "ticket"
		};
		for (size_t i = 0; i < db.count; i++) {
			struct sl_record *r = &db.records[i];
			if (r->kind == SL_PROVIDER || r->kind == SL_POLICY || r->kind == SL_TICKET)
				continue;
			sl_generation_format(r->generation, token);
			printf("%s %s %s %u %s %s %s\n", kinds[r->kind], r->label,
			    token, r->phase, r->provider, r->reference, r->source);
		}
	}
	for (int i = first; !status && i < argc; i++) {
		struct sl_record *r = sl_operation(&db, argv[i], operation);
		if (r != NULL && strcmp(r->reference, reference) != 0) {
			error = EINVAL;
			break;
		}
		if (adopt && sl_owner(&db, argv[i]) == NULL) {
			if (error == 0 && sl_adopt(&db, argv[i], generation) == -1)
				error = errno;
		}
		if (error == 0 && (install || adopt || strcmp(op, "begin-install") == 0)) {
			/* Repeating installation of the same live source is an upgrade. */
			if (sl_install_begin(&db, argv[i], reference, operation) == -1)
				error = errno;
			if ((first == 4) && error == 0 &&
			    sl_install_finish(&db, argv[i], operation, false) == -1)
				error = errno;
		} else if (error == 0 && strcmp(op, "prepare") == 0) {
			if (sl_remove_begin(&db, argv[i], reference, operation) == -1)
				error = errno;
		} else if (error == 0 && (strcmp(op, "finish-install") == 0 ||
		    strcmp(op, "cancel-install") == 0)) {
			if (sl_install_finish(&db, argv[i], operation,
			    strcmp(op, "cancel-install") == 0) == -1)
				error = errno;
		} else if (error == 0 && sl_remove_finish(&db, argv[i], operation,
		    strcmp(op, "cancel") == 0) == -1)
			error = errno;
		if (error == 0 && sl_record_source(&db, argv[i], operation,
		    argv[first - 1]) == -1)
			error = errno;
		if (error != 0)
			break;
	}
	if (error == 0 && !status && sl_commit(&db) == -1)
		error = errno;
	sl_close(&db);
	if (error != 0) {
		warnx("lifecycle %s: %s; inspect with switchboardctl lifecycle status %s",
		    op, strerror(error), root);
		return (EX_TEMPFAIL);
	}
	return (0);
}
