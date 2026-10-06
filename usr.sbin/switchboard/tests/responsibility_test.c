/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * responsibility_test — the responsible-parent decision (responsibility.c)
 * against the management model, plus the apply path's degradation, with the
 * kernel coalition calls stubbed.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_coalition_proto.h>

#include "switchboard.h"
#include "authority.h"

struct switchboard_state sd;

/* --- stubs: the pieces responsibility.c reaches --- */

static int set_resp_calls, set_resp_parent, set_resp_status;
static uint32_t set_resp_flags;
static int stat_status;
static uint64_t stat_id = 700, stat_rid = 600;

int
mac_cap_coalition_set_responsible(int coalition_fd, int parent_fd,
    uint32_t flags)
{

	(void)coalition_fd;
	set_resp_calls++;
	set_resp_parent = parent_fd;
	set_resp_flags = flags;
	if (set_resp_status != 0 && parent_fd >= 0) {
		errno = set_resp_status;
		return (set_resp_status);
	}
	return (0);
}

int
mac_cap_coalition_stat(int coalition_fd, struct coalition_stat_reply *sr)
{

	(void)coalition_fd;
	memset(sr, 0, sizeof(*sr));
	if (stat_status != 0) {
		errno = stat_status;
		return (stat_status);
	}
	sr->id = stat_id;
	sr->responsible_id = stat_rid;
	return (0);
}

int
mac_cap_coalition_set_signal(int coalition_fd, int sig)
{

	(void)coalition_fd;
	(void)sig;
	return (0);
}

int
mac_cap_create_coalition(void)
{

	errno = ENODEV;
	return (-1);
}

/* --- helpers --- */

static void
unit_init(struct svc_runtime *u, const char *label, int mgmt, uid_t owner)
{

	memset(u, 0, sizeof(*u));
	svc_runtime_init_fds(u);
	strlcpy(u->manifest.label, label, sizeof(u->manifest.label));
	u->manifest.management = mgmt;
	u->owner_uid = owner;
}

/* A real, distinct descriptor to stand in for a coalition fd. */
static int
some_fd(void)
{
	int fd = open("/dev/null", O_RDONLY);

	ATF_REQUIRE(fd >= 0);
	return (fd);
}

static bool
same_file(int a, int b)
{
	struct stat sa, sb;

	return (a >= 0 && b >= 0 && fstat(a, &sa) == 0 &&
	    fstat(b, &sb) == 0 && sa.st_dev == sb.st_dev &&
	    sa.st_ino == sb.st_ino);
}

/* --- decide --- */

ATF_TC_WITHOUT_HEAD(helper_is_responsible_to_requester);
ATF_TC_BODY(helper_is_responsible_to_requester, tc)
{
	struct svc_runtime req, unit;

	unit_init(&req, "app/main", SVC_MGMT_SYSTEM, (uid_t)-1);
	req.coalition_fd = some_fd();
	req.coalition_id = 41;
	unit_init(&unit, "app/helper", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.manifest.is_helper = true;

	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_UNIT);
	ATF_CHECK_STREQ(unit.responsible.label, "app/main");
	ATF_CHECK_EQ(unit.responsible.parent_id, 41);
	/* An owned dup of the requester's coalition fd, close-on-exec. */
	ATF_CHECK(unit.responsible.parent_fd >= 0);
	ATF_CHECK(unit.responsible.parent_fd != req.coalition_fd);
	ATF_CHECK(same_file(unit.responsible.parent_fd, req.coalition_fd));
	ATF_CHECK(fcntl(unit.responsible.parent_fd, F_GETFD) & FD_CLOEXEC);
	svc_responsibility_clear(&unit);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_UNSET);
}

ATF_TC_WITHOUT_HEAD(shared_provider_roots_itself);
ATF_TC_BODY(shared_provider_roots_itself, tc)
{
	struct svc_runtime req, unit;

	unit_init(&req, "user/agent", SVC_MGMT_USER, 1001);
	req.coalition_fd = some_fd();
	/* SYSTEM and CORE providers answer for themselves, whoever asked. */
	unit_init(&unit, "system.Crypto", SVC_MGMT_SYSTEM, (uid_t)-1);
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);

	unit_init(&unit, "core.Filesystem", SVC_MGMT_CORE, (uid_t)-1);
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);
}

ATF_TC_WITHOUT_HEAD(user_unit_follows_owner);
ATF_TC_BODY(user_unit_follows_owner, tc)
{
	struct svc_runtime req, unit;

	unit_init(&req, "user/agent", SVC_MGMT_USER, 1001);
	req.coalition_fd = some_fd();
	req.coalition_id = 9;
	/* Same owner: the requester is responsible. */
	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1001);
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_UNIT);
	ATF_CHECK_EQ(unit.responsible.parent_id, 9);
	svc_responsibility_clear(&unit);
	/* Different owner: not this requester's doing. */
	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1002);
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	/* An un-owned USER unit never binds to a uid it does not have. */
	unit_init(&unit, "user/worker", SVC_MGMT_USER, (uid_t)-1);
	unit_init(&req, "user/agent", SVC_MGMT_USER, (uid_t)-1);
	req.coalition_fd = some_fd();
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
}

ATF_TC_WITHOUT_HEAD(requester_without_coalition_degrades_to_self);
ATF_TC_BODY(requester_without_coalition_degrades_to_self, tc)
{
	struct svc_runtime req, unit;

	unit_init(&req, "app/main", SVC_MGMT_SYSTEM, (uid_t)-1);
	req.coalition_fd = -1;	/* an rc-adopted or stopped requester */
	unit_init(&unit, "app/helper", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.manifest.is_helper = true;
	svc_responsibility_decide(&unit, &req, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);
}

ATF_TC_WITHOUT_HEAD(authority_does_not_imply_session_coalition);
ATF_TC_BODY(authority_does_not_imply_session_coalition, tc)
{
	struct svc_runtime unit;
	struct svc_domain caller = { .kind = SVC_DOMAIN_USER, .uid = 1001,
	    .authority_issuer = 1, .authority_identity = 1 };

	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1001);
	svc_responsibility_decide(&unit, NULL, &caller);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);
	ATF_CHECK_EQ(unit.responsible.parent_id, 0);
}

ATF_TC_WITHOUT_HEAD(boot_and_operator_belong_to_switchboard);
ATF_TC_BODY(boot_and_operator_belong_to_switchboard, tc)
{
	struct svc_runtime unit;

	sd.root_coalition_fd = some_fd();
	sd.root_coalition_id = 3;
	unit_init(&unit, "system.Log", SVC_MGMT_SYSTEM, (uid_t)-1);
	svc_responsibility_decide(&unit, NULL, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SWITCHBOARD);
	ATF_CHECK_EQ(unit.responsible.parent_id, 3);
	ATF_CHECK(same_file(unit.responsible.parent_fd, sd.root_coalition_fd));
	svc_responsibility_clear(&unit);

	/* No root coalition available: the unit roots itself. */
	close(sd.root_coalition_fd);
	sd.root_coalition_fd = -1;
	sd.root_coalition_id = 0;
	svc_responsibility_decide(&unit, NULL, NULL);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
}

ATF_TC_WITHOUT_HEAD(name_strings);
ATF_TC_BODY(name_strings, tc)
{
	struct svc_responsible r;
	char buf[64];

	memset(&r, 0, sizeof(r));
	ATF_CHECK_STREQ(svc_responsibility_name(&r, buf, sizeof(buf)), "unset");
	r.kind = SVC_RESP_SELF;
	ATF_CHECK_STREQ(svc_responsibility_name(&r, buf, sizeof(buf)), "self");
	r.kind = SVC_RESP_SWITCHBOARD;
	ATF_CHECK_STREQ(svc_responsibility_name(&r, buf, sizeof(buf)),
	    "switchboard");
	r.kind = SVC_RESP_UNIT;
	strlcpy(r.label, "app/main", sizeof(r.label));
	ATF_CHECK_STREQ(svc_responsibility_name(&r, buf, sizeof(buf)),
	    "app/main");
	r.kind = SVC_RESP_SESSION;
	r.uid = 1001;
	ATF_CHECK_STREQ(svc_responsibility_name(&r, buf, sizeof(buf)),
	    "session:uid=1001");
}

/* --- apply --- */

ATF_TC_WITHOUT_HEAD(apply_records_parent_and_learns_ids);
ATF_TC_BODY(apply_records_parent_and_learns_ids, tc)
{
	struct svc_runtime req, unit;
	int cfd;

	unit_init(&req, "app/main", SVC_MGMT_SYSTEM, (uid_t)-1);
	req.coalition_fd = some_fd();
	req.coalition_id = 600;
	unit_init(&unit, "app/helper", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.manifest.is_helper = true;
	svc_responsibility_decide(&unit, &req, NULL);

	set_resp_calls = 0;
	set_resp_status = 0;
	stat_status = 0;
	cfd = some_fd();
	svc_responsibility_apply(&unit, cfd);
	ATF_CHECK_EQ(set_resp_calls, 1);
	ATF_CHECK_EQ(set_resp_parent, unit.responsible.parent_fd);
	ATF_CHECK_EQ(set_resp_flags, 0);
	ATF_CHECK_EQ(unit.coalition_id, 700);
	ATF_CHECK_EQ(unit.responsible.parent_id, 600);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_UNIT);
	/* The parent dup is kept for the next launch (restart). */
	ATF_CHECK(unit.responsible.parent_fd >= 0);
}

ATF_TC_WITHOUT_HEAD(apply_self_uses_self_flag);
ATF_TC_BODY(apply_self_uses_self_flag, tc)
{
	struct svc_runtime unit;

	unit_init(&unit, "system.Crypto", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.responsible.kind = SVC_RESP_SELF;
	set_resp_calls = 0;
	set_resp_status = 0;
	stat_status = 0;
	stat_rid = 700;
	svc_responsibility_apply(&unit, some_fd());
	ATF_CHECK_EQ(set_resp_calls, 1);
	ATF_CHECK_EQ(set_resp_parent, -1);
	ATF_CHECK_EQ(set_resp_flags, COALITION_RESP_SELF);
	ATF_CHECK_EQ(unit.coalition_id, 700);
	ATF_CHECK_EQ(unit.responsible.parent_id, 700);
}

ATF_TC_WITHOUT_HEAD(apply_unset_defaults_to_switchboard);
ATF_TC_BODY(apply_unset_defaults_to_switchboard, tc)
{
	struct svc_runtime unit;

	/* An operator start or boot launch never went through decide(). */
	sd.root_coalition_fd = some_fd();
	sd.root_coalition_id = 3;
	unit_init(&unit, "system.Log", SVC_MGMT_SYSTEM, (uid_t)-1);
	set_resp_calls = 0;
	set_resp_status = 0;
	stat_status = 0;
	svc_responsibility_apply(&unit, some_fd());
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SWITCHBOARD);
	ATF_CHECK_EQ(set_resp_calls, 1);
	ATF_CHECK(set_resp_parent >= 0);
	close(sd.root_coalition_fd);
	sd.root_coalition_fd = -1;
}

ATF_TC_WITHOUT_HEAD(apply_dead_parent_degrades_to_self);
ATF_TC_BODY(apply_dead_parent_degrades_to_self, tc)
{
	struct svc_runtime req, unit;

	unit_init(&req, "app/main", SVC_MGMT_SYSTEM, (uid_t)-1);
	req.coalition_fd = some_fd();
	unit_init(&unit, "app/helper", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.manifest.is_helper = true;
	svc_responsibility_decide(&unit, &req, NULL);

	/* The kernel says the parent is gone: fall back to a self-root. */
	set_resp_calls = 0;
	set_resp_status = EBADF;
	stat_status = 0;
	stat_rid = 700;
	svc_responsibility_apply(&unit, some_fd());
	ATF_CHECK_EQ(set_resp_calls, 2);
	ATF_CHECK_EQ(set_resp_parent, -1);
	ATF_CHECK_EQ(set_resp_flags, COALITION_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	ATF_CHECK_EQ(unit.responsible.parent_fd, -1);
	ATF_CHECK_EQ(unit.coalition_id, 700);
	set_resp_status = 0;
}

ATF_TC_WITHOUT_HEAD(apply_never_fails_the_launch);
ATF_TC_BODY(apply_never_fails_the_launch, tc)
{
	struct svc_runtime unit;

	unit_init(&unit, "system.Log", SVC_MGMT_SYSTEM, (uid_t)-1);
	unit.responsible.kind = SVC_RESP_SELF;
	/* stat failing leaves the ids at 0 and nothing else changed. */
	stat_status = EIO;
	svc_responsibility_apply(&unit, some_fd());
	ATF_CHECK_EQ(unit.coalition_id, 0);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
	stat_status = 0;
	/* No coalition at all (an RC unit): nothing to record. */
	set_resp_calls = 0;
	svc_responsibility_apply(&unit, -1);
	ATF_CHECK_EQ(set_resp_calls, 0);
	ATF_CHECK_EQ(unit.coalition_id, 0);
}


/* --- launch constraints (svc_responsible_allowed) --- */

static void
constrain(struct svc_runtime *u, const char *a, const char *b)
{

	u->manifest.nlaunch_responsible = 0;
	if (a != NULL)
		strlcpy(u->manifest.launch_responsible[
		    u->manifest.nlaunch_responsible++], a,
		    sizeof(u->manifest.launch_responsible[0]));
	if (b != NULL)
		strlcpy(u->manifest.launch_responsible[
		    u->manifest.nlaunch_responsible++], b,
		    sizeof(u->manifest.launch_responsible[0]));
}

static void
set_resp(struct svc_runtime *u, enum svc_responsible_kind kind,
    const char *label, uid_t uid)
{

	memset(&u->responsible, 0, sizeof(u->responsible));
	u->responsible.parent_fd = -1;
	u->responsible.kind = kind;
	u->responsible.uid = uid;
	if (label != NULL)
		strlcpy(u->responsible.label, label,
		    sizeof(u->responsible.label));
}

ATF_TC_WITHOUT_HEAD(constraint_absent_allows_anyone);
ATF_TC_BODY(constraint_absent_allows_anyone, tc)
{
	struct svc_runtime u;

	unit_init(&u, "app/worker", SVC_MGMT_SYSTEM, (uid_t)-1);
	ATF_CHECK_EQ(0U, u.manifest.nlaunch_responsible);
	set_resp(&u, SVC_RESP_SESSION, NULL, 1001);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SELF, NULL, 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "other/main", 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
}

ATF_TC_WITHOUT_HEAD(constraint_matches_simple_kinds);
ATF_TC_BODY(constraint_matches_simple_kinds, tc)
{
	struct svc_runtime u;

	unit_init(&u, "app/worker", SVC_MGMT_SYSTEM, (uid_t)-1);

	constrain(&u, "self", NULL);
	set_resp(&u, SVC_RESP_SELF, NULL, 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SWITCHBOARD, NULL, 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));

	constrain(&u, "switchboard", NULL);
	set_resp(&u, SVC_RESP_SWITCHBOARD, NULL, 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SELF, NULL, 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));

	/* An unset party never satisfies a constraint. */
	constrain(&u, "self", "switchboard");
	set_resp(&u, SVC_RESP_UNSET, NULL, 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
}

ATF_TC_WITHOUT_HEAD(constraint_session_any_and_by_uid);
ATF_TC_BODY(constraint_session_any_and_by_uid, tc)
{
	struct svc_runtime u;

	unit_init(&u, "user/worker", SVC_MGMT_USER, 1001);

	/* "session" is any login session. */
	constrain(&u, "session", NULL);
	set_resp(&u, SVC_RESP_SESSION, NULL, 1001);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SESSION, NULL, 4242);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));

	/* A uid-qualified token is exact. */
	constrain(&u, "session:uid=1001", NULL);
	set_resp(&u, SVC_RESP_SESSION, NULL, 1001);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SESSION, NULL, 1002);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
	/* And it does not leak into other kinds. */
	set_resp(&u, SVC_RESP_SWITCHBOARD, NULL, 1001);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
}

ATF_TC_WITHOUT_HEAD(constraint_unit_label_and_bundle);
ATF_TC_BODY(constraint_unit_label_and_bundle, tc)
{
	struct svc_runtime u;

	unit_init(&u, "org.test.app/worker", SVC_MGMT_SYSTEM, (uid_t)-1);

	/* An exact label. */
	constrain(&u, "org.test.app/main", NULL);
	set_resp(&u, SVC_RESP_UNIT, "org.test.app/main", 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "org.test.app/other", 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));

	/* "bundle": any unit of this unit's own bundle, and only that one. */
	constrain(&u, "bundle", NULL);
	set_resp(&u, SVC_RESP_UNIT, "org.test.app/main", 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "org.test.app/anything", 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "org.test.other/main", 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
	/* A prefix of the bundle id is not the bundle id. */
	set_resp(&u, SVC_RESP_UNIT, "org.test.ap/main", 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "org.test.appx/main", 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
	/* "bundle" does not admit a session or the switchboard. */
	set_resp(&u, SVC_RESP_SESSION, NULL, 1001);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SWITCHBOARD, NULL, 0);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
}

ATF_TC_WITHOUT_HEAD(constraint_any_entry_suffices);
ATF_TC_BODY(constraint_any_entry_suffices, tc)
{
	struct svc_runtime u;

	unit_init(&u, "org.test.app/worker", SVC_MGMT_SYSTEM, (uid_t)-1);
	constrain(&u, "switchboard", "bundle");
	set_resp(&u, SVC_RESP_SWITCHBOARD, NULL, 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_UNIT, "org.test.app/main", 0);
	ATF_CHECK(svc_responsible_allowed(&u.manifest, &u.responsible));
	set_resp(&u, SVC_RESP_SESSION, NULL, 1001);
	ATF_CHECK(!svc_responsible_allowed(&u.manifest, &u.responsible));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, helper_is_responsible_to_requester);
	ATF_TP_ADD_TC(tp, shared_provider_roots_itself);
	ATF_TP_ADD_TC(tp, user_unit_follows_owner);
	ATF_TP_ADD_TC(tp, requester_without_coalition_degrades_to_self);
	ATF_TP_ADD_TC(tp, authority_does_not_imply_session_coalition);
	ATF_TP_ADD_TC(tp, boot_and_operator_belong_to_switchboard);
	ATF_TP_ADD_TC(tp, name_strings);
	ATF_TP_ADD_TC(tp, apply_records_parent_and_learns_ids);
	ATF_TP_ADD_TC(tp, apply_self_uses_self_flag);
	ATF_TP_ADD_TC(tp, apply_unset_defaults_to_switchboard);
	ATF_TP_ADD_TC(tp, apply_dead_parent_degrades_to_self);
	ATF_TP_ADD_TC(tp, apply_never_fails_the_launch);
	ATF_TP_ADD_TC(tp, constraint_absent_allows_anyone);
	ATF_TP_ADD_TC(tp, constraint_matches_simple_kinds);
	ATF_TP_ADD_TC(tp, constraint_session_any_and_by_uid);
	ATF_TP_ADD_TC(tp, constraint_unit_label_and_bundle);
	ATF_TP_ADD_TC(tp, constraint_any_entry_suffices);
	return (atf_no_error());
}
