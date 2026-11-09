/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * BSM audit records of an unattached process, as before stage 1c.
 *
 * Stage 1c-iii-b adds "dq_start" and "dq_object" argument tokens
 * (audit_bsm.c, ARG_DQSTART/ARG_DQOBJ) for lookups that start at or
 * produce a served object.  An unattached process never has either, so
 * its records must carry exactly the tokens they did before, in the same
 * order, and no dq token.
 *
 * Expected token sequences from 3f330ee172d audit_bsm.c kaudit_to_bsm():
 * header (kau_close), the event's tokens, the subject, the return token,
 * the trailer (kau_close):
 *
 *   openat(AT_FDCWD, O_RDONLY)  argument(flags) path [attribute]
 *   fstatat(AT_FDCWD)           path [attribute]
 *   renameat(AT_FDCWD x2)       path [attribute] path
 *   socket                      argument(domain) argument(type)
 *                               argument(protocol)
 *
 * The attribute token is present when the lookup found a vnode
 * (ARG_VNODE1), so not for a missing file.  ATFD1/ATFD2 argument tokens
 * appear only for a dirfd other than AT_FDCWD (namei_setup()).  These
 * exact sequences are to be confirmed on the pre-1c kernel.
 *
 * Uses the audit suite's harness (tests/sys/audit/utils.c), so it starts
 * a fake auditd when none runs, like those tests.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <bsm/libbsm.h>
#include <poll.h>
#include <regex.h>
#include <time.h>

#include "procnet_common.h"
#include "utils.h"

static struct pollfd fds[1];

#define	MAXTOK	32

struct record {
	char	text[8192];
	char	names[MAXTOK][24];
	int	ntok;
};

/* Read one record from the pipe; false on a short read. */
static bool
read_record(FILE *pipestream, struct record *r)
{
	tokenstr_t tok;
	FILE *mem;
	u_char *buf;
	char one[1024];
	int reclen, bytes;
	size_t k;

	if ((reclen = au_read_rec(pipestream, &buf)) == -1)
		return (false);
	r->text[0] = '\0';
	r->ntok = 0;
	bytes = 0;
	while (bytes < reclen) {
		if (au_fetch_tok(&tok, buf + bytes, reclen - bytes) == -1)
			break;
		mem = fmemopen(one, sizeof(one), "w");
		ATF_REQUIRE(mem != NULL);
		au_print_flags_tok(mem, &tok, __DECONST(char *, ","),
		    AU_OFLAG_NONE);
		fputc('\0', mem);
		fclose(mem);
		one[sizeof(one) - 1] = '\0';
		strlcat(r->text, one, sizeof(r->text));
		strlcat(r->text, ",", sizeof(r->text));
		if (r->ntok < MAXTOK) {
			k = strcspn(one, ",");
			if (k >= sizeof(r->names[0]))
				k = sizeof(r->names[0]) - 1;
			memcpy(r->names[r->ntok], one, k);
			r->names[r->ntok][k] = '\0';
			r->ntok++;
		}
		bytes += tok.len;
	}
	free(buf);
	return (true);
}

/* Wait (30 s) for a record whose text matches re. */
static void
find_record(FILE *pipestream, const char *re, struct record *r)
{
	struct timespec end, now, left;
	regex_t rx;

	ATF_REQUIRE(regcomp(&rx, re, REG_EXTENDED | REG_NOSUB) == 0);
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	end.tv_sec += 30;
	for (;;) {
		ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
		timespecsub(&end, &now, &left);
		if (left.tv_sec < 0)
			atf_tc_fail("no record matching %s", re);
		switch (ppoll(fds, 1, &left, NULL)) {
		case 1:
			if (!read_record(pipestream, r))
				atf_tc_fail("short audit record");
			if (regexec(&rx, r->text, 0, NULL, 0) == 0) {
				regfree(&rx);
				return;
			}
			break;
		case 0:
			atf_tc_fail("no record matching %s", re);
			break;
		default:
			atf_tc_fail("ppoll: %s", strerror(errno));
		}
	}
}

static void
check_record(const struct record *r, const char *const *want, int nwant)
{
	char got[512];
	int i;

	got[0] = '\0';
	for (i = 0; i < r->ntok; i++) {
		strlcat(got, r->names[i], sizeof(got));
		strlcat(got, " ", sizeof(got));
	}
	ATF_CHECK_MSG(strstr(r->text, "dq_start") == NULL &&
	    strstr(r->text, "dq_object") == NULL,
	    "dq token in an unattached record: %s", r->text);
	ATF_CHECK_EQ_MSG(nwant, r->ntok, "tokens: %s\nrecord: %s", got,
	    r->text);
	for (i = 0; i < nwant && i < r->ntok; i++)
		ATF_CHECK_MSG(strcmp(want[i], r->names[i]) == 0,
		    "token %d is %s, expected %s; record: %s", i,
		    r->names[i], want[i], r->text);
}

static void
marker(char *buf, size_t len, const char *what)
{

	snprintf(buf, len, "procnet_audit_%s_%d", what, (int)getpid());
}

ATF_TC_WITH_CLEANUP(audit_open);
ATF_TC_HEAD(audit_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "openat(2) success and ENOENT records "
	    "carry the pre-1c tokens and no dq token");
}
ATF_TC_BODY(audit_open, tc)
{
	static const char *const ok[] = { "header", "argument", "path",
	    "attribute", "subject", "return", "trailer" };
	static const char *const fail[] = { "header", "argument", "path",
	    "subject", "return", "trailer" };
	char name[128], re[256];
	struct record r;
	FILE *pipestream;
	int fd;

	marker(name, sizeof(name), "open");
	pn_writefile(name, "x", 1, 0644);
	pipestream = setup(fds, "fr");
	fd = open(name, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	snprintf(re, sizeof(re), "openat.*,path,[^,]*%s,.*return,success",
	    name);
	find_record(pipestream, re, &r);
	check_record(&r, ok, (int)nitems(ok));
	close(fd);

	ATF_REQUIRE(unlink(name) == 0);
	ATF_REQUIRE(open(name, O_RDONLY) == -1);
	snprintf(re, sizeof(re), "openat.*,path,[^,]*%s,.*return,failure",
	    name);
	find_record(pipestream, re, &r);
	check_record(&r, fail, (int)nitems(fail));
	fclose(pipestream);
}
ATF_TC_CLEANUP(audit_open, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(audit_stat);
ATF_TC_HEAD(audit_stat, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstatat(2) records carry the pre-1c "
	    "tokens and no dq token");
}
ATF_TC_BODY(audit_stat, tc)
{
	static const char *const ok[] = { "header", "path", "attribute",
	    "subject", "return", "trailer" };
	char name[128], re[256];
	struct record r;
	struct stat st;
	FILE *pipestream;

	marker(name, sizeof(name), "stat");
	pn_writefile(name, "x", 1, 0644);
	pipestream = setup(fds, "fa");
	ATF_REQUIRE(stat(name, &st) == 0);
	snprintf(re, sizeof(re), "fstatat.*,path,[^,]*%s,.*return,success",
	    name);
	find_record(pipestream, re, &r);
	check_record(&r, ok, (int)nitems(ok));
	fclose(pipestream);
}
ATF_TC_CLEANUP(audit_stat, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(audit_rename);
ATF_TC_HEAD(audit_rename, tc)
{
	atf_tc_set_md_var(tc, "descr", "renameat(2) records carry two paths, "
	    "the source attribute and no dq token");
}
ATF_TC_BODY(audit_rename, tc)
{
	static const char *const ok[] = { "header", "path", "attribute",
	    "path", "subject", "return", "trailer" };
	char from[128], to[160], re[512];
	struct record r;
	FILE *pipestream;

	marker(from, sizeof(from), "rename");
	snprintf(to, sizeof(to), "%s_to", from);
	pn_writefile(from, "x", 1, 0644);
	pipestream = setup(fds, "fc");
	ATF_REQUIRE(rename(from, to) == 0);
	snprintf(re, sizeof(re), "rename.*,path,[^,]*%s,.*,path,[^,]*%s,"
	    ".*return,success", from, to);
	find_record(pipestream, re, &r);
	check_record(&r, ok, (int)nitems(ok));
	fclose(pipestream);
}
ATF_TC_CLEANUP(audit_rename, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(audit_socket);
ATF_TC_HEAD(audit_socket, tc)
{
	atf_tc_set_md_var(tc, "descr", "socket(2) success and failure records "
	    "carry domain, type and protocol and no dq token");
}
ATF_TC_BODY(audit_socket, tc)
{
	static const char *const ok[] = { "header", "argument", "argument",
	    "argument", "subject", "return", "trailer" };
	char re[256];
	struct record r;
	FILE *pipestream;
	int s, pid;

	pid = (int)getpid();
	pipestream = setup(fds, "nt");
	/* An unusual protocol number identifies the record. */
	s = socket(AF_UNIX, SOCK_DGRAM, 4321);
	ATF_REQUIRE(s >= 0);
	snprintf(re, sizeof(re), "socket.*,argument,3,0x10e1,protocol,"
	    ".*subject,([^,]*,){5}%d,.*return,success,%d", pid, s);
	find_record(pipestream, re, &r);
	check_record(&r, ok, (int)nitems(ok));
	close(s);

	ATF_REQUIRE(socket(255, SOCK_STREAM, 4321) == -1);
	snprintf(re, sizeof(re), "socket.*,argument,1,0xff,domain,"
	    ".*subject,([^,]*,){5}%d,.*return,failure", pid);
	find_record(pipestream, re, &r);
	check_record(&r, ok, (int)nitems(ok));
	fclose(pipestream);
}
ATF_TC_CLEANUP(audit_socket, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, audit_open);
	ATF_TP_ADD_TC(tp, audit_stat);
	ATF_TP_ADD_TC(tp, audit_rename);
	ATF_TP_ADD_TC(tp, audit_socket);
	return (atf_no_error());
}
