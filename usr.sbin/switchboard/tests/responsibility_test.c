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

struct switchboard_state sd;

/* --- stubs: the pieces responsibility.c reaches --- */

static int stub_session_fd = -1;
static uint64_t stub_session_id;
static uid_t stub_session_uid = (uid_t)-1;

int
lookup_channel_coalition_fd(const struct svc_lookup_channel *lc)
{

	return (lc != NULL ? stub_session_fd : -1);
}

uint64_t
lookup_channel_coalition_id(const struct svc_lookup_channel *lc)
{

	return (lc != NULL ? stub_session_id : 0);
}

uid_t
lookup_channel_uid(const struct svc_lookup_channel *lc)
{

	return (lc != NULL ? stub_session_uid : (uid_t)-1);
}

static int set_resp_calls, set_resp_parent, set_resp_status;
static uint32_t set_resp_flags;
static int stat_status;
static uint64_t stat_id = 700, stat_rid = 600;
static int band_floor_calls, band_floor_status;
static uint32_t band_floor_set = UINT32_MAX;

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
mac_cap_coalition_set_band_floor(int coalition_fd, uint32_t floor)
{

	(void)coalition_fd;
	band_floor_calls++;
	band_floor_set = floor;
	if (band_floor_status != 0) {
		errno = band_floor_status;
		return (band_floor_status);
	}
	return (0);
}

int
mac_cap_coalition_get_band(int coalition_fd, struct coalition_band_reply *br)
{

	(void)coalition_fd;
	memset(br, 0, sizeof(*br));
	br->floor = band_floor_set == UINT32_MAX ? COALITION_BAND_STANDARD :
	    band_floor_set;
	br->effective = br->floor;
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

ATF_TC_WITHOUT_HEAD(session_owns_its_user_units);
ATF_TC_BODY(session_owns_its_user_units, tc)
{
	struct svc_runtime unit;
	int lc_token = 0;	/* any non-NULL pointer stands for the session */

	stub_session_fd = some_fd();
	stub_session_id = 77;
	stub_session_uid = 1001;

	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1001);
	svc_responsibility_decide(&unit, NULL,
	    (const struct svc_lookup_channel *)&lc_token);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SESSION);
	ATF_CHECK_EQ(unit.responsible.uid, 1001);
	ATF_CHECK_EQ(unit.responsible.parent_id, 77);
	ATF_CHECK(same_file(unit.responsible.parent_fd, stub_session_fd));
	svc_responsibility_clear(&unit);

	/* Another user's session does not own it. */
	stub_session_uid = 1002;
	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1001);
	svc_responsibility_decide(&unit, NULL,
	    (const struct svc_lookup_channel *)&lc_token);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);

	/* A shared provider activated from a session roots itself. */
	stub_session_uid = 1001;
	unit_init(&unit, "system.Crypto", SVC_MGMT_SYSTEM, (uid_t)-1);
	svc_responsibility_decide(&unit, NULL,
	    (const struct svc_lookup_channel *)&lc_token);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);

	/* A session without a coalition (mint degraded) cannot be a parent. */
	close(stub_session_fd);
	stub_session_fd = -1;
	unit_init(&unit, "user/worker", SVC_MGMT_USER, 1001);
	svc_responsibility_decide(&unit, NULL,
	    (const struct svc_lookup_channel *)&lc_token);
	ATF_CHECK_EQ(unit.responsible.kind, SVC_RESP_SELF);
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


ATF_TC_WITHOUT_HEAD(band_floor_is_derived_not_declared);
ATF_TC_BODY(band_floor_is_derived_not_declared, tc)
{
	struct svc_manifest m;

	/*
	 * A CORE unit is critical whatever it declares: the manifest's band is
	 * a scheduling request, not a claim on the system's willingness to
	 * keep it.
	 */
	memset(&m, 0, sizeof(m));
	m.management = SVC_MGMT_CORE;
	m.band = SVC_BAND_BACKGROUND;
	ATF_CHECK_EQ(svc_band_floor(&m), COALITION_BAND_CRITICAL);

	/* Everything else maps its declared band. */
	memset(&m, 0, sizeof(m));
	m.management = SVC_MGMT_SYSTEM;
	ATF_CHECK_EQ(svc_band_floor(&m), COALITION_BAND_STANDARD);
	m.band = SVC_BAND_BACKGROUND;
	ATF_CHECK_EQ(svc_band_floor(&m), COALITION_BAND_BACKGROUND);
	m.band = SVC_BAND_INTERACTIVE;
	ATF_CHECK_EQ(svc_band_floor(&m), COALITION_BAND_INTERACTIVE);

	/* A user unit gets the same mapping, never the critical band. */
	m.management = SVC_MGMT_USER;
	m.band = SVC_BAND_INTERACTIVE;
	ATF_CHECK_EQ(svc_band_floor(&m), COALITION_BAND_INTERACTIVE);
	ATF_CHECK(svc_band_floor(&m) != COALITION_BAND_CRITICAL);
}

ATF_TC_WITHOUT_HEAD(band_floor_applied_on_launch);
ATF_TC_BODY(band_floor_applied_on_launch, tc)
{
	struct svc_runtime svc;

	memset(&svc, 0, sizeof(svc));
	(void)strlcpy(svc.manifest.label, "com.example.core",
	    sizeof(svc.manifest.label));
	svc.manifest.management = SVC_MGMT_CORE;
	svc.responsible.kind = SVC_RESP_SELF;
	svc.responsible.parent_fd = -1;
	band_floor_calls = 0;
	band_floor_set = UINT32_MAX;

	svc_responsibility_apply(&svc, 3);
	ATF_CHECK_EQ(band_floor_calls, 1);
	ATF_CHECK_EQ(band_floor_set, COALITION_BAND_CRITICAL);
	/* The coalition id was still learned. */
	ATF_CHECK_EQ(svc.coalition_id, stat_id);
}

ATF_TC_WITHOUT_HEAD(band_floor_failure_does_not_fail_launch);
ATF_TC_BODY(band_floor_failure_does_not_fail_launch, tc)
{
	struct svc_runtime svc;

	memset(&svc, 0, sizeof(svc));
	(void)strlcpy(svc.manifest.label, "com.example.svc",
	    sizeof(svc.manifest.label));
	svc.manifest.management = SVC_MGMT_SYSTEM;
	svc.responsible.kind = SVC_RESP_SELF;
	svc.responsible.parent_fd = -1;
	band_floor_status = EPERM;
	band_floor_calls = 0;

	svc_responsibility_apply(&svc, 3);
	band_floor_status = 0;
	ATF_CHECK_EQ(band_floor_calls, 1);
	/* Attribution still recorded; a band that cannot be set is not fatal. */
	ATF_CHECK_EQ(svc.coalition_id, stat_id);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, helper_is_responsible_to_requester);
	ATF_TP_ADD_TC(tp, shared_provider_roots_itself);
	ATF_TP_ADD_TC(tp, user_unit_follows_owner);
	ATF_TP_ADD_TC(tp, requester_without_coalition_degrades_to_self);
	ATF_TP_ADD_TC(tp, session_owns_its_user_units);
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
	ATF_TP_ADD_TC(tp, band_floor_is_derived_not_declared);
	ATF_TP_ADD_TC(tp, band_floor_applied_on_launch);
	ATF_TP_ADD_TC(tp, band_floor_failure_does_not_fail_launch);
	return (atf_no_error());
}
