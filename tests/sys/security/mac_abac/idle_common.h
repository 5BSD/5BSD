/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helpers for the mac_abac idle tests (idle_pin_test, idle_test).
 *
 * Every rule these tests load names the subject label SUBJ_LABEL, which only
 * their own labelled workers carry, and (except where a case says otherwise)
 * the object label OBJ_LABEL, which only their own files carry, so nothing
 * else in the guest is ever constrained, even in enforcing mode.  Each case
 * records the mode and default policy it found and every rule id it added,
 * and its cleanup restores the first and removes the second.
 */
#ifndef _ABAC_IDLE_COMMON_H_
#define _ABAC_IDLE_COMMON_H_

#include <sys/param.h>
#include <sys/extattr.h>
#include <sys/mac.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/mac_abac/mac_abac.h>

#define	SUBJ_LABEL	"type=abacidle-subj"
#define	OBJ_LABEL	"type=abacidle-obj"
#define	IDLE_SET	61005		/* rule set no other test uses */

#define	STATE_FILE	"abac-idle-state"
#define	RULES_FILE	"abac-idle-rules"
#define	DIR_FILE	"abac-idle-dir"

/* Worker commands; each is answered with an int (errno or exit status). */
#define	LW_READ		'r'	/* pread(obj, 1 byte) */
#define	LW_WRITE	'w'	/* pwrite(obj, 1 byte) */
#define	LW_STAT		's'	/* fstat(obj) and stat(path) */
#define	LW_EXEC		'x'	/* fork, execve the labelled binary */
#define	LW_OPEN		'o'	/* open(path, O_RDONLY) and close */
#define	LW_PIPE		'p'	/* write and read 1 byte on own pipe */
#define	LW_QUIT		'q'

struct lworker {
	pid_t	lw_pid;
	int	lw_cmd;
	int	lw_res;
};

static char idle_dir[PATH_MAX];
static char idle_obj[PATH_MAX + 16];
static char idle_bin[PATH_MAX + 16];

static inline int
idle_sysctl_get(const char *name)
{
	size_t len;
	int v;

	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "read %s: %s", name, strerror(errno));
	return (v);
}

static inline uint64_t
idle_sysctl_u64(const char *name)
{
	size_t len;
	uint64_t v;

	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "read %s: %s", name, strerror(errno));
	return (v);
}

static inline void
idle_call(int cmd, void *arg)
{

	ATF_REQUIRE_MSG(mac_syscall("mac_abac", cmd, arg) == 0,
	    "mac_abac command %d: %s", cmd, strerror(errno));
}

/* Record mode and default policy for the cleanup; require no rule loaded. */
static inline void
idle_save_state(void)
{
	FILE *f;

	ATF_REQUIRE_EQ_MSG(0, idle_sysctl_get("security.mac.mac_abac.locked"),
	    "mac_abac is locked");
	ATF_REQUIRE_EQ_MSG(1, idle_sysctl_get("security.mac.mac_abac.enabled"),
	    "mac_abac is not enabled");
	/*
	 * These cases need an empty table.  Another suite's program may leave
	 * rules behind (kernel_test does); the guest is disposable and the
	 * cases exclusive, so start from an empty table.
	 */
	if (idle_sysctl_get("security.mac.mac_abac.rule_count") != 0) {
		printf("note: clearing %d rules left loaded\n",
		    idle_sysctl_get("security.mac.mac_abac.rule_count"));
		idle_call(ABAC_SYS_RULE_CLEAR, NULL);
	}
	f = fopen(STATE_FILE, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%d %d\n", idle_sysctl_get("security.mac.mac_abac.mode"),
	    idle_sysctl_get("security.mac.mac_abac.default_policy"));
	ATF_REQUIRE(fclose(f) == 0);
}

static inline void
idle_set_mode(int mode)
{

	idle_call(ABAC_SYS_SETMODE, &mode);
}

static inline void
idle_set_defpol(int defpol)
{

	idle_call(ABAC_SYS_SETDEFPOL, &defpol);
}

static inline void
idle_note_rule(uint32_t id)
{
	FILE *f;

	f = fopen(RULES_FILE, "a");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%u\n", id);
	ATF_REQUIRE(fclose(f) == 0);
}

/* Pack one rule (header, subject, object) into buf; returns its size. */
static inline size_t
idle_pack_rule(char *buf, size_t buflen, int action, uint32_t ops,
    uint16_t set, const char *subject, const char *object)
{
	struct abac_rule_arg rule;
	size_t sl, ol, size;

	sl = strlen(subject) + 1;
	ol = strlen(object) + 1;
	size = sizeof(rule) + sl + ol;
	ATF_REQUIRE(size <= buflen);
	memset(&rule, 0, sizeof(rule));
	rule.vr_action = action;
	rule.vr_set = set;
	rule.vr_operations = ops;
	rule.vr_subject_len = sl;
	rule.vr_object_len = ol;
	memcpy(buf, &rule, sizeof(rule));
	memcpy(buf + sizeof(rule), subject, sl);
	memcpy(buf + sizeof(rule) + sl, object, ol);
	return (size);
}

static inline uint32_t
idle_add_rule_full(int action, uint32_t ops, uint16_t set,
    const char *subject, const char *object)
{
	char buf[512];
	struct abac_rule_arg *rule;

	(void)idle_pack_rule(buf, sizeof(buf), action, ops, set, subject,
	    object);
	rule = (struct abac_rule_arg *)(void *)buf;
	idle_call(ABAC_SYS_RULE_ADD, rule);
	idle_note_rule(rule->vr_id);
	return (rule->vr_id);
}

static inline uint32_t
idle_add_rule(int action, uint32_t ops)
{

	return (idle_add_rule_full(action, ops, IDLE_SET, SUBJ_LABEL,
	    OBJ_LABEL));
}

static inline void
idle_remove_rule(uint32_t id)
{

	idle_call(ABAC_SYS_RULE_REMOVE, &id);
}

/* Atomically replace the whole table by the given packed rules. */
static inline void
idle_load_rules(char *buf, size_t len, uint32_t count)
{
	struct abac_rule_load_arg la;

	memset(&la, 0, sizeof(la));
	la.vrl_count = count;
	la.vrl_buflen = len;
	la.vrl_buf = buf;
	idle_call(ABAC_SYS_RULE_LOAD, &la);
	ATF_REQUIRE_EQ(count, la.vrl_loaded);
}

static inline void
idle_set_range(int cmd, uint16_t set)
{
	struct abac_set_range r;

	r.vsr_start = set;
	r.vsr_end = set;
	idle_call(cmd, &r);
}

static inline int
idle_setlabel_fd(int fd, const char *label)
{
	char buf[sizeof(struct abac_setlabel_arg) + 128];
	struct abac_setlabel_arg arg;
	size_t len;

	len = strlen(label) + 1;
	ATF_REQUIRE(len <= 128);
	memset(&arg, 0, sizeof(arg));
	arg.vsl_fd = fd;
	arg.vsl_label_len = len;
	memcpy(buf, &arg, sizeof(arg));
	memcpy(buf + sizeof(arg), label, len);
	return (mac_syscall("mac_abac", ABAC_SYS_SETLABEL, buf));
}

static inline int
idle_label_file(const char *path)
{
	int fd, rc;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);
	rc = idle_setlabel_fd(fd, OBJ_LABEL);
	(void)close(fd);
	return (rc);
}

static inline int
idle_copy_file(const char *from, const char *to, mode_t mode)
{
	char buf[65536];
	ssize_t n;
	int in, out;

	in = open(from, O_RDONLY);
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (in < 0 || out < 0)
		return (-1);
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, n) != n)
			return (-1);
	(void)close(in);
	(void)close(out);
	return (n == 0 ? 0 : -1);
}

/*
 * Create the labelled object file and the labelled copy of true(1).  The
 * labels are extended attributes: use the work directory if its file system
 * takes them, else a private directory under /var/tmp.
 */
static inline void
idle_make_objects(void)
{
	const char *bases[] = { ".", "/var/tmp" };
	FILE *f;
	size_t i;
	int fd, rc;

	rc = -1;
	for (i = 0; i < nitems(bases) && rc != 0; i++) {
		if (i == 0)
			strlcpy(idle_dir, ".", sizeof(idle_dir));
		else {
			snprintf(idle_dir, sizeof(idle_dir),
			    "%s/abac-idle.XXXXXX", bases[i]);
			ATF_REQUIRE(mkdtemp(idle_dir) != NULL);
			f = fopen(DIR_FILE, "w");
			ATF_REQUIRE(f != NULL);
			fprintf(f, "%s\n", idle_dir);
			ATF_REQUIRE(fclose(f) == 0);
		}
		snprintf(idle_obj, sizeof(idle_obj), "%s/object", idle_dir);
		snprintf(idle_bin, sizeof(idle_bin), "%s/true", idle_dir);
		fd = open(idle_obj, O_RDWR | O_CREAT | O_TRUNC, 0644);
		ATF_REQUIRE(fd >= 0);
		ATF_REQUIRE(write(fd, "abcd", 4) == 4);
		(void)close(fd);
		rc = idle_label_file(idle_obj);
		if (rc != 0 && errno != EOPNOTSUPP)
			atf_tc_fail("label %s: %s", idle_obj, strerror(errno));
	}
	ATF_REQUIRE_MSG(rc == 0, "no file system here takes labels");
	ATF_REQUIRE(idle_copy_file("/usr/bin/true", idle_bin, 0755) == 0);
	ATF_REQUIRE_MSG(idle_label_file(idle_bin) == 0, "label %s: %s",
	    idle_bin, strerror(errno));
}

static void
lworker_loop(int cmd, int res)
{
	char c, b;
	struct stat sb;
	pid_t pid;
	int fd, obj, p[2], status, r;
	mac_t label;

	if (mac_from_text(&label, "mac_abac/" SUBJ_LABEL) != 0 ||
	    mac_set_proc(label) != 0)
		_exit(100);
	mac_free(label);
	obj = open(idle_obj, O_RDWR);
	if (obj < 0)
		_exit(101);
	for (;;) {
		if (read(cmd, &c, 1) != 1 || c == LW_QUIT)
			_exit(0);
		r = 0;
		switch (c) {
		case LW_READ:
			if (pread(obj, &b, 1, 0) != 1)
				r = errno;
			break;
		case LW_WRITE:
			if (pwrite(obj, "w", 1, 1) != 1)
				r = errno;
			break;
		case LW_STAT:
			if (fstat(obj, &sb) != 0 || stat(idle_obj, &sb) != 0)
				r = errno;
			break;
		case LW_OPEN:
			fd = open(idle_obj, O_RDONLY);
			if (fd < 0)
				r = errno;
			else
				(void)close(fd);
			break;
		case LW_PIPE:
			/* The pipe carries this worker's label. */
			if (pipe(p) != 0) {
				r = errno;
				break;
			}
			if (write(p[1], "p", 1) != 1 || read(p[0], &b, 1) != 1)
				r = errno;
			(void)close(p[0]);
			(void)close(p[1]);
			break;
		case LW_EXEC:
			pid = fork();
			if (pid == 0) {
				execl(idle_bin, "true", (char *)NULL);
				_exit(errno);
			}
			if (pid < 0 || waitpid(pid, &status, 0) != pid)
				r = -1;
			else
				r = WIFEXITED(status) ? WEXITSTATUS(status) :
				    -2;
			break;
		default:
			r = EINVAL;
			break;
		}
		if (write(res, &r, sizeof(r)) != sizeof(r))
			_exit(102);
	}
}

static inline void
lworker_start(struct lworker *w)
{
	int cmd[2], res[2];

	ATF_REQUIRE(pipe(cmd) == 0 && pipe(res) == 0);
	w->lw_pid = fork();
	ATF_REQUIRE(w->lw_pid >= 0);
	if (w->lw_pid == 0) {
		(void)close(cmd[1]);
		(void)close(res[0]);
		lworker_loop(cmd[0], res[1]);
	}
	(void)close(cmd[0]);
	(void)close(res[1]);
	w->lw_cmd = cmd[1];
	w->lw_res = res[0];
}

/* Run one command; returns its answer, or fails the case. */
static inline int
lworker_do(struct lworker *w, char c)
{
	struct pollfd pfd;
	int r, status;

	ATF_REQUIRE(write(w->lw_cmd, &c, 1) == 1);
	pfd.fd = w->lw_res;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 10000) != 1 ||
	    read(w->lw_res, &r, sizeof(r)) != sizeof(r)) {
		if (waitpid(w->lw_pid, &status, WNOHANG) == w->lw_pid)
			atf_tc_fail("labelled worker exited (status %#x)",
			    status);
		atf_tc_fail("labelled worker did not answer '%c'", c);
	}
	return (r);
}

static inline void
lworker_stop(struct lworker *w)
{
	char c = LW_QUIT;
	int status;

	(void)write(w->lw_cmd, &c, 1);
	(void)close(w->lw_cmd);
	(void)close(w->lw_res);
	(void)waitpid(w->lw_pid, &status, 0);
}

/* Cleanup: remove recorded rules, restore mode and default policy. */
static inline void
idle_cleanup(void)
{
	char dir[PATH_MAX], cmd[PATH_MAX + 16];
	FILE *f;
	unsigned id;
	int mode, defpol, force;

	force = 0;
	(void)sysctlbyname("security.mac.mac_abac.force_hooks", NULL, NULL,
	    &force, sizeof(force));
	f = fopen(RULES_FILE, "r");
	if (f != NULL) {
		while (fscanf(f, "%u", &id) == 1) {
			uint32_t rid = id;

			(void)mac_syscall("mac_abac", ABAC_SYS_RULE_REMOVE,
			    &rid);
		}
		(void)fclose(f);
	}
	f = fopen(STATE_FILE, "r");
	if (f != NULL) {
		/*
		 * The case began with an empty table (idle_save_state()), so
		 * whatever is loaded now is its own, ids unknown after a load.
		 */
		(void)mac_syscall("mac_abac", ABAC_SYS_RULE_CLEAR, NULL);
		if (fscanf(f, "%d %d", &mode, &defpol) == 2) {
			(void)mac_syscall("mac_abac", ABAC_SYS_SETDEFPOL,
			    &defpol);
			(void)mac_syscall("mac_abac", ABAC_SYS_SETMODE, &mode);
		}
		(void)fclose(f);
	}
	f = fopen(DIR_FILE, "r");
	if (f != NULL) {
		if (fgets(dir, sizeof(dir), f) != NULL &&
		    strncmp(dir, "/var/tmp/abac-idle.", 19) == 0) {
			dir[strcspn(dir, "\n")] = '\0';
			snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
			(void)system(cmd);
		}
		(void)fclose(f);
	}
}

#endif /* !_ABAC_IDLE_COMMON_H_ */
