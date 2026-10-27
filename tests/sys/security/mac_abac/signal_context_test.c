/* SPDX-License-Identifier: BSD-2-Clause */
/* Real process admission, opt-in only: affected kernels may panic or hang. */
#include <sys/types.h>
#include <sys/mac.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/mac_abac/mac_abac.h>

static int
setting(const char *name)
{
	int value;
	size_t size = sizeof(value);

	ATF_REQUIRE(sysctlbyname(name, &value, &size, NULL, 0) == 0);
	return (value);
}

static uint64_t
denied(void)
{
	uint64_t value;
	size_t size = sizeof(value);

	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.denied", &value,
	    &size, NULL, 0) == 0);
	return (value);
}

static uint32_t
arm_rule(const char *subject, uint32_t operation, int context)
{
	struct abac_rule_arg *rule;
	char *data;
	FILE *record;
	size_t length = strlen(subject) + 1;
	uint32_t id;

	/* Cleanup removes only this test's recorded rule, never the rule table. */
	record = fopen("signal-rule-id", "wx");
	ATF_REQUIRE(record != NULL);
	rule = calloc(1, sizeof(*rule) + length + 2);
	ATF_REQUIRE(rule != NULL);
	rule->vr_action = ABAC_ACTION_DENY;
	rule->vr_operations = operation;
	rule->vr_subject_len = length;
	rule->vr_object_len = 2;
	if (context == 1) {
		rule->vr_obj_context.vc_flags = ABAC_CTX_UID;
		rule->vr_obj_context.vc_uid = geteuid();
	} else if (context == 4) {
		rule->vr_subj_context.vc_flags = ABAC_CTX_HAS_TTY;
		rule->vr_subj_context.vc_has_tty = 0;
	} else if (context >= 2) {
		rule->vr_obj_context.vc_flags = ABAC_CTX_HAS_TTY;
		rule->vr_obj_context.vc_has_tty = context == 3;
	}
	data = (char *)(rule + 1);
	memcpy(data, subject, length);
	memcpy(data + length, "*", 2);
	ATF_REQUIRE(mac_syscall("mac_abac", ABAC_SYS_RULE_ADD, rule) == 0);
	id = rule->vr_id;
	free(rule);
	ATF_REQUIRE(fprintf(record, "%u\n", id) > 0);
	ATF_REQUIRE(fclose(record) == 0);
	return (id);
}

static void
remove_rule(uint32_t id)
{
	ATF_REQUIRE(mac_syscall("mac_abac", ABAC_SYS_RULE_REMOVE, &id) == 0);
	ATF_REQUIRE(unlink("signal-rule-id") == 0);
}

static void
check_operation(pid_t child, uint32_t operation, int priority)
{
	int status;

	if (operation == ABAC_OP_DEBUG) {
		ATF_REQUIRE(ptrace(PT_ATTACH, child, NULL, 0) == 0);
		ATF_REQUIRE(waitpid(child, &status, 0) == child);
		ATF_REQUIRE(WIFSTOPPED(status));
	} else if (operation == ABAC_OP_SIGNAL)
		ATF_REQUIRE(kill(child, 0) == 0);
	else if (operation == ABAC_OP_WAIT)
		/* The live child remains blocked on the pipe until cleanup. */
		ATF_REQUIRE(waitpid(child, NULL, WNOHANG) == 0);
	else {
		ATF_REQUIRE_EQ(operation, ABAC_OP_SCHED);
		ATF_REQUIRE(setpriority(PRIO_PROCESS, child, priority) == 0);
	}
}

/* Detach after measuring and removing the debug rule: detach is also checked. */
static void
finish_operation(pid_t child, uint32_t operation)
{
	if (operation == ABAC_OP_DEBUG)
		ATF_REQUIRE(ptrace(PT_DETACH, child, (caddr_t)1, 0) == 0);
}

static void
check_context(const atf_tc_t *tc, uint32_t operation, int target_tty)
{
	char subject[96], text[112], byte;
	mac_t label;
	pid_t child;
	uint32_t id;
	uint64_t before;
	int gate[2], ready[2], status, priority, master = -1, slave = -1;
	int ttyfd, first, last;

	if (strcmp(atf_tc_get_config_var_wd(tc, "disposable_vm", "no"), "yes") != 0)
		atf_tc_skip("requires explicit disposable_vm=yes; affected kernels may panic");
	if (setting("security.mac.mac_abac.enabled") != 1 ||
	    setting("security.mac.mac_abac.mode") != ABAC_MODE_PERMISSIVE ||
	    setting("security.mac.mac_abac.rule_count") != 0 ||
	    setting("security.mac.mac_abac.default_policy") != 0)
		atf_tc_skip("requires enabled permissive ABAC, empty rules and default allow");
	snprintf(subject, sizeof(subject), "type=process-context-%d", getpid());
	snprintf(text, sizeof(text), "mac_abac/%s", subject);
	ATF_REQUIRE(mac_from_text(&label, text) == 0);
	ATF_REQUIRE(mac_set_proc(label) == 0);
	mac_free(label);
	ATF_REQUIRE(pipe(gate) == 0);
	ATF_REQUIRE(pipe(ready) == 0);
	if (target_tty == 1) {
		master = posix_openpt(O_RDWR | O_NOCTTY);
		ATF_REQUIRE(master >= 0);
		ATF_REQUIRE(grantpt(master) == 0);
		ATF_REQUIRE(unlockpt(master) == 0);
		ATF_REQUIRE(ptsname(master) != NULL);
		slave = open(ptsname(master), O_RDWR | O_NOCTTY);
		ATF_REQUIRE(slave >= 0);
	}
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(gate[1]);
		close(ready[0]);
		if (target_tty >= 0) {
			if (setsid() == -1)
				_exit(10);
			if (target_tty == 1) {
				close(master);
				if (ioctl(slave, TIOCSCTTY, NULL) == -1)
					_exit(11);
			}
			ttyfd = open("/dev/tty", O_RDWR);
			if ((target_tty == 1 && ttyfd < 0) ||
			    (target_tty == 0 && (ttyfd >= 0 || errno != ENXIO)))
				_exit(12);
			if (ttyfd >= 0)
				close(ttyfd);
		}
		if (write(ready[1], "R", 1) != 1)
			_exit(13);
		close(ready[1]);
		while (read(gate[0], &byte, 1) == -1 && errno == EINTR)
			;
		_exit(0);
	}
	close(gate[0]);
	close(ready[1]);
	if (slave >= 0)
		close(slave);
	ATF_REQUIRE(read(ready[0], &byte, 1) == 1 && byte == 'R');
	close(ready[0]);
	/* Preserve the child's inherited priority during scheduling admission. */
	errno = 0;
	priority = getpriority(PRIO_PROCESS, child);
	ATF_REQUIRE(errno == 0);
	check_operation(child, operation, priority);
	finish_operation(child, operation);
	first = target_tty < 0 ? 0 : 2;
	last = target_tty < 0 ? 2 : 4;
	for (int context = first; context != last; context++) {
		id = arm_rule(subject, operation, context);
		before = denied();
		check_operation(child, operation, priority); /* permissive */
		ATF_REQUIRE_EQ(before + (target_tty < 0 || context - 2 == target_tty),
		    denied());
		remove_rule(id);
		finish_operation(child, operation);
		check_operation(child, operation, priority);
		finish_operation(child, operation);
	}
	close(gate[1]);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	if (master >= 0)
		close(master);
}
static void
cleanup_rule(void)
{
	FILE *record;
	uint32_t id;
	int result;

	record = fopen("signal-rule-id", "r");
	if (record == NULL)
		return;
	if (fscanf(record, "%u", &id) == 1) {
		result = mac_syscall("mac_abac", ABAC_SYS_RULE_REMOVE, &id);
		ATF_REQUIRE(result == 0 || errno == ENOENT);
	}
	fclose(record);
	unlink("signal-rule-id");
}
ATF_TC_WITH_CLEANUP(signal_target_context);
ATF_TC_HEAD(signal_target_context, tc)
{
	atf_tc_set_md_var(tc, "descr", "real kill(2) with ABAC target context respects held process lock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(signal_target_context, tc)
{
	check_context(tc, ABAC_OP_SIGNAL, -1);
}
ATF_TC_CLEANUP(signal_target_context, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(sched_target_context);
ATF_TC_HEAD(sched_target_context, tc)
{
	atf_tc_set_md_var(tc, "descr", "real setpriority(2) with ABAC target context respects held process lock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(sched_target_context, tc)
{
	check_context(tc, ABAC_OP_SCHED, -1);
}
ATF_TC_CLEANUP(sched_target_context, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(wait_target_context);
ATF_TC_HEAD(wait_target_context, tc)
{
	atf_tc_set_md_var(tc, "descr", "real waitpid(2) with ABAC target context respects held process lock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(wait_target_context, tc)
{
	check_context(tc, ABAC_OP_WAIT, -1);
}
ATF_TC_CLEANUP(wait_target_context, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(debug_target_context);
ATF_TC_HEAD(debug_target_context, tc)
{
	atf_tc_set_md_var(tc, "descr", "real ptrace(2) with ABAC target context respects held process lock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(debug_target_context, tc)
{
	check_context(tc, ABAC_OP_DEBUG, -1);
}
ATF_TC_CLEANUP(debug_target_context, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(signal_target_without_tty);
ATF_TC_HEAD(signal_target_without_tty, tc)
{
	atf_tc_set_md_var(tc, "descr", "target controlling TTY context: matching and nonmatching rules");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(signal_target_without_tty, tc)
{
	check_context(tc, ABAC_OP_SIGNAL, 0);
}
ATF_TC_CLEANUP(signal_target_without_tty, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(signal_target_with_tty);
ATF_TC_HEAD(signal_target_with_tty, tc)
{
	atf_tc_set_md_var(tc, "descr", "target controlling TTY context: matching and nonmatching rules");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(signal_target_with_tty, tc)
{
	check_context(tc, ABAC_OP_SIGNAL, 1);
}
ATF_TC_CLEANUP(signal_target_with_tty, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TC_WITH_CLEANUP(signal_reciprocal_subject_tty);
ATF_TC_HEAD(signal_reciprocal_subject_tty, tc)
{
	atf_tc_set_md_var(tc, "descr", "Enforced subject TTY checks under reciprocal process-lock pressure");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(signal_reciprocal_subject_tty, tc)
{
	int command[2][2], result[2][2], status;
	pid_t children[2], target;
	char subject[96], text[112], token;
	mac_t label;
	uint32_t id;
	uint64_t before;

	if (strcmp(atf_tc_get_config_var_wd(tc, "disposable_vm", "no"), "yes") != 0)
		atf_tc_skip("disposable_vm=yes required; kernel lockup may defeat ATF timeout");
	if (setting("security.mac.mac_abac.enabled") != 1 ||
	    setting("security.mac.mac_abac.mode") != ABAC_MODE_ENFORCING ||
	    setting("security.mac.mac_abac.rule_count") != 0 ||
	    setting("security.mac.mac_abac.default_policy") != 0)
		atf_tc_skip("requires enabled enforcing ABAC, empty rules and default allow");
	snprintf(subject, sizeof(subject), "type=reciprocal-context-%d", getpid());
	snprintf(text, sizeof(text), "mac_abac/%s", subject);
	ATF_REQUIRE(mac_from_text(&label, text) == 0);
	ATF_REQUIRE(mac_set_proc(label) == 0);
	mac_free(label);
	for (unsigned i = 0; i < 2; i++) {
		ATF_REQUIRE(pipe(command[i]) == 0);
		ATF_REQUIRE(pipe(result[i]) == 0);
	}
	for (unsigned i = 0; i < 2; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0) {
			for (unsigned j = 0; j < 2; j++) {
				close(command[j][1]);
				close(result[j][0]);
				if (j != i) {
					close(command[j][0]);
					close(result[j][1]);
				}
			}
			if (setsid() == -1)
				_exit(10);
			if (write(result[i][1], "R", 1) != 1 ||
			    read(command[i][0], &target, sizeof(target)) != sizeof(target))
				_exit(11);
			for (unsigned attempt = 0; attempt < 4096; attempt++) {
				errno = 0;
				if (kill(target, 0) != -1 || errno != EACCES)
					_exit(12);
			}
			/* Keep both target processes live until both loops finish. */
			if (write(result[i][1], "D", 1) != 1 ||
			    read(command[i][0], &token, 1) != 1)
				_exit(13);
			_exit(0);
		}
	}
	for (unsigned i = 0; i < 2; i++) {
		close(command[i][0]);
		close(result[i][1]);
		ATF_REQUIRE(read(result[i][0], &token, 1) == 1 && token == 'R');
	}
	id = arm_rule(subject, ABAC_OP_SIGNAL, 4);
	before = denied();
	for (unsigned i = 0; i < 2; i++) {
		target = children[1 - i];
		ATF_REQUIRE(write(command[i][1], &target, sizeof(target)) == sizeof(target));
	}
	for (unsigned i = 0; i < 2; i++)
		ATF_REQUIRE(read(result[i][0], &token, 1) == 1 && token == 'D');
	ATF_REQUIRE_EQ(before + 8192, denied());
	remove_rule(id);
	for (unsigned i = 0; i < 2; i++) {
		ATF_REQUIRE(write(command[i][1], "X", 1) == 1);
		close(command[i][1]);
		close(result[i][0]);
		ATF_REQUIRE(waitpid(children[i], &status, 0) == children[i]);
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
}
ATF_TC_CLEANUP(signal_reciprocal_subject_tty, tc)
{
	(void)tc;
	cleanup_rule();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, signal_reciprocal_subject_tty);
	ATF_TP_ADD_TC(tp, signal_target_context);
	ATF_TP_ADD_TC(tp, sched_target_context);
	ATF_TP_ADD_TC(tp, wait_target_context);
	ATF_TP_ADD_TC(tp, debug_target_context);
	ATF_TP_ADD_TC(tp, signal_target_without_tty);
	ATF_TP_ADD_TC(tp, signal_target_with_tty);
	return (atf_no_error());
}
