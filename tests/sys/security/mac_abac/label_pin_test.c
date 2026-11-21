/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pins of what an unlabelled subject or object looks like to mac_abac,
 * which must hold however unlabelled objects are stored: a process, file,
 * pipe or socket that nobody labelled is "type=unlabeled" for rule
 * matching and for label export, a pipe or socket carries its creator's
 * label, and a relabelled process exports and is matched by its new label.
 * Rules name SUBJ_LABEL or OBJ_LABEL so nothing else is constrained.
 */

#include <sys/socket.h>

#include "idle_common.h"

static const char *open_path;

static int
open_one(int a __unused, int b __unused)
{
	int fd;

	fd = open(open_path, O_RDONLY);
	if (fd < 0)
		return (errno);
	(void)close(fd);
	return (0);
}

/* A child labelled SUBJ_LABEL runs fn and exits with its errno. */
static int
labelled_child(int (*fn)(int, int), int a, int b)
{
	pid_t pid;
	mac_t l;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (mac_from_text(&l, "mac_abac/" SUBJ_LABEL) != 0 ||
		    mac_set_proc(l) != 0)
			_exit(100);
		_exit(fn(a, b));
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	return (WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

static void
idle_head(atf_tc_t *tc, const char *descr)
{

	atf_tc_set_md_var(tc, "descr", descr);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}

#define	LABEL_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc) { idle_head(tc, descr); }				\
ATF_TC_CLEANUP(name, tc) { (void)tc; idle_cleanup(); }			\
ATF_TC_BODY(name, tc)

/* The mac_abac element of the calling process's label, as text. */
static char *
proc_label(void)
{
	mac_t label;
	char *text;

	ATF_REQUIRE(mac_prepare(&label, "mac_abac") == 0);
	ATF_REQUIRE_MSG(mac_get_proc(label) == 0, "mac_get_proc: %s",
	    strerror(errno));
	ATF_REQUIRE(mac_to_text(label, &text) == 0);
	mac_free(label);
	return (text);
}

LABEL_TC(l1_unlabelled_process_exports,
    "L-1: an unlabelled process exports type=unlabeled; a labelled one "
    "its label, inherited over fork")
{
	char *text;
	pid_t pid;
	int status;

	(void)tc;
	idle_save_state();
	text = proc_label();
	ATF_CHECK_STREQ_MSG("mac_abac/type=unlabeled", text,
	    "unlabelled process: %s", text);
	free(text);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		mac_t l;

		if (mac_from_text(&l, "mac_abac/" SUBJ_LABEL) != 0 ||
		    mac_set_proc(l) != 0)
			_exit(1);
		text = proc_label();
		if (strcmp(text, "mac_abac/" SUBJ_LABEL) != 0)
			_exit(2);
		if (fork() == 0) {
			text = proc_label();
			_exit(strcmp(text, "mac_abac/" SUBJ_LABEL) != 0 ? 3 :
			    0);
		}
		(void)wait(&status);
		_exit(WIFEXITED(status) ? WEXITSTATUS(status) : 4);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_EQ_MSG(0, WEXITSTATUS(status), "labelled child: step %d",
	    WEXITSTATUS(status));
}

LABEL_TC(l2_unlabelled_file_is_matched,
    "L-2: an unlabelled file matches object type=unlabeled")
{
	int fd;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	fd = open("plain", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_OPEN, IDLE_SET,
	    SUBJ_LABEL, "type=unlabeled");
	open_path = idle_obj;
	ATF_CHECK_EQ_MSG(0, labelled_child(open_one, 0, 0), "labelled file");
	open_path = "plain";
	ATF_CHECK_EQ_MSG(EACCES, labelled_child(open_one, 0, 0),
	    "unlabelled file");
}

LABEL_TC(l3_unlabelled_subject_is_matched,
    "L-3: an unlabelled subject matches subject type=unlabeled")
{
	pid_t pid;
	int status, fd;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_OPEN, IDLE_SET,
	    "type=unlabeled", OBJ_LABEL);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fd = open(idle_obj, O_RDONLY);
		_exit(fd < 0 ? errno : 0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_EQ_MSG(EACCES, WEXITSTATUS(status),
	    "unlabelled subject opened the labelled file: %d",
	    WEXITSTATUS(status));
}


static int
read_one(int rfd, int wfd)
{
	char c;

	if (write(wfd, "x", 1) != 1)
		return (errno);
	return (read(rfd, &c, 1) == 1 ? 0 : errno);
}

static int
own_pipe_read(int a __unused, int b __unused)
{
	int p[2];

	if (pipe(p) != 0)
		return (errno);
	return (read_one(p[0], p[1]));
}

static int
send_one(int s, int b __unused)
{

	return (send(s, "x", 1, 0) == 1 ? 0 : errno);
}

LABEL_TC(l4_pipe_carries_creator_label,
    "L-4: a pipe is labelled as its creator, unlabelled for an unlabelled "
    "creator")
{
	int p[2];

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	ATF_REQUIRE(pipe(p) == 0);	/* created unlabelled */
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_READ, IDLE_SET,
	    SUBJ_LABEL, "type=unlabeled");
	ATF_CHECK_EQ_MSG(EACCES, labelled_child(read_one, p[0], p[1]),
	    "read of an unlabelled creator's pipe");
	ATF_CHECK_EQ_MSG(0, labelled_child(own_pipe_read, 0, 0),
	    "read of the subject's own pipe");
	idle_call(ABAC_SYS_RULE_CLEAR, NULL);
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_READ, IDLE_SET,
	    SUBJ_LABEL, SUBJ_LABEL);
	ATF_CHECK_EQ_MSG(EACCES, labelled_child(own_pipe_read, 0, 0),
	    "own pipe carries the subject label");
	ATF_CHECK_EQ_MSG(0, labelled_child(read_one, p[0], p[1]),
	    "unlabelled creator's pipe is not SUBJ_LABEL");
}

LABEL_TC(l5_socket_carries_creator_label,
    "L-5: a socket is labelled as its creator")
{
	int s[2];

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, s) == 0);
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_SEND, IDLE_SET,
	    SUBJ_LABEL, "type=unlabeled");
	ATF_CHECK_EQ_MSG(EACCES, labelled_child(send_one, s[0], 0),
	    "send on an unlabelled creator's socket");
	idle_call(ABAC_SYS_RULE_CLEAR, NULL);
	(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_SEND, IDLE_SET,
	    SUBJ_LABEL, SUBJ_LABEL);
	ATF_CHECK_EQ_MSG(0, labelled_child(send_one, s[0], 0),
	    "unlabelled creator's socket is not SUBJ_LABEL");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, l1_unlabelled_process_exports);
	ATF_TP_ADD_TC(tp, l2_unlabelled_file_is_matched);
	ATF_TP_ADD_TC(tp, l3_unlabelled_subject_is_matched);
	ATF_TP_ADD_TC(tp, l4_pipe_carries_creator_label);
	ATF_TP_ADD_TC(tp, l5_socket_carries_creator_label);
	return (atf_no_error());
}
