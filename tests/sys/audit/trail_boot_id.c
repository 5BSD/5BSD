/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Every audit trail file begins with a record that names the boot its
 * records come from (5BSD): event AUE_AUDIT_TRAIL_START with the text
 * "boot_id=" and kern.boot_id in hex, written by libauditd before the
 * kernel is handed the file, at auditd's start and at each rotation.
 * audit_token(3) ids are unique only within a boot.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef AUE_AUDIT_TRAIL_START
#define	AUE_AUDIT_TRAIL_START	43966
#endif

#define	AUDIT_DIR	"/var/audit"
#define	CURRENT		AUDIT_DIR "/current"

/* "boot_id=" and kern.boot_id in hex. */
static void
boot_id_text(char *buf, size_t size)
{
	uint8_t id[16];
	size_t len;
	int i;

	len = sizeof(id);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname("kern.boot_id", id, &len, NULL, 0),
	    "kern.boot_id: %s", strerror(errno));
	ATF_REQUIRE_EQ(sizeof(id), len);
	strlcpy(buf, "boot_id=", size);
	for (i = 0; i < (int)sizeof(id); i++)
		snprintf(buf + strlen(buf), size - strlen(buf), "%02x", id[i]);
}

/* The first record of the trail file is the boot record of this boot. */
static void
check_first_record(const char *path)
{
	char want[64];
	tokenstr_t tok;
	u_char *buf;
	FILE *fp;
	u_short event;
	int reclen, off;
	bool text;

	boot_id_text(want, sizeof(want));
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));
	reclen = au_read_rec(fp, &buf);
	ATF_REQUIRE_MSG(reclen > 0, "%s: no first record", path);
	event = 0;
	text = false;
	for (off = 0; off < reclen; off += tok.len) {
		ATF_REQUIRE_EQ(0, au_fetch_tok(&tok, buf + off, reclen - off));
		if (tok.id == AUT_HEADER32)
			event = tok.tt.hdr32.e_type;
		else if (tok.id == AUT_HEADER32_EX)
			event = tok.tt.hdr32_ex.e_type;
		else if (tok.id == AUT_TEXT) {
			ATF_CHECK_STREQ_MSG(want, tok.tt.text.text,
			    "%s: first record text", path);
			text = true;
		}
	}
	ATF_CHECK_EQ_MSG((u_short)AUE_AUDIT_TRAIL_START, event,
	    "%s: first record is event %u", path, event);
	ATF_CHECK_MSG(text, "%s: first record has no text token", path);
	free(buf);
	ATF_REQUIRE_EQ(0, fclose(fp));
}

/*
 * Every trail file of this boot: the guest's /var/audit starts empty, so
 * every file there was opened since boot, the first one at auditd's start.
 */
ATF_TC_WITHOUT_HEAD(trail_boot_id_every_file);
ATF_TC_BODY(trail_boot_id_every_file, tc)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *dir;
	int n;

	dir = opendir(AUDIT_DIR);
	ATF_REQUIRE_MSG(dir != NULL, AUDIT_DIR ": %s", strerror(errno));
	n = 0;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_type != DT_REG || de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), AUDIT_DIR "/%s", de->d_name);
		check_first_record(path);
		n++;
	}
	ATF_REQUIRE_EQ(0, closedir(dir));
	if (n == 0)
		atf_tc_fail("no trail file in " AUDIT_DIR);
}

/*
 * A rotation asked of auditd(8) opens a new trail file that begins with
 * the boot record.  The wait is on the audit directory, which auditd
 * writes when it replaces the "current" link.
 */
ATF_TC_WITHOUT_HEAD(trail_boot_id_at_rotation);
ATF_TC_BODY(trail_boot_id_at_rotation, tc)
{
	char before[PATH_MAX], now[PATH_MAX];
	struct kevent kev;
	ssize_t len;
	int kq, dfd, trigger;

	len = readlink(CURRENT, before, sizeof(before) - 1);
	ATF_REQUIRE_MSG(len > 0, CURRENT ": %s", strerror(errno));
	before[len] = '\0';

	dfd = open(AUDIT_DIR, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, dfd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	trigger = AUDIT_TRIGGER_ROTATE_USER;
	if (auditon(A_SENDTRIGGER, &trigger, sizeof(trigger)) != 0) {
		ATF_REQUIRE_EQ_MSG(ENODEV, errno, "A_SENDTRIGGER: %s",
		    strerror(errno));
		atf_tc_skip("auditd(8) is not running");
	}
	for (;;) {
		len = readlink(CURRENT, now, sizeof(now) - 1);
		if (len > 0) {
			now[len] = '\0';
			if (strcmp(now, before) != 0)
				break;
		}
		ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, NULL));
	}
	check_first_record(now);
	ATF_REQUIRE_EQ(0, close(kq));
	ATF_REQUIRE_EQ(0, close(dfd));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, trail_boot_id_every_file);
	ATF_TP_ADD_TC(tp, trail_boot_id_at_rotation);
	return (atf_no_error());
}
