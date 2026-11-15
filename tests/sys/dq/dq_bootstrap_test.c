/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * BS-0: pins of what a dq-attached process sees of its service lookup
 * route today, written before the bootstrap slices (BS-1 onward) put the
 * supervisor in front of it.  Every case records what the kernel and the
 * base libraries do now and names the slice expected to change it.
 *
 * Today DQ_IOC_ATTACH does not touch the route: the attached child keeps
 * the lookup channel it inherited (cap_process(2), MAC_CAP_PROCESS_*), and
 * resolves public names through it exactly as an unattached child does.
 * Each attached row therefore has an unattached control; at BS-1 the
 * attached rows flip and the controls must not.
 *
 * Not here, and why: BS-0 (b1), (b2) and (e) need a process launched by
 * SwitchBoard as a unit (descriptor 3) and a provider's view of
 * SVC_OP_NEW_CLIENT; a kyua test program is neither.
 */

#include <sys/param.h>
#include <sys/cap_process.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_channel_proto.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libservice_session.h>
#include <logcmp.h>
#include <notify.h>
#include <sysctlcmp.h>

#include "dq_test.h"

/*
 * A pin does not skip: the plane and the queue device are there.  Without
 * this, dqt_open_queue() would turn a missing /dev/dq into a skip.
 */
static void
pin_require_plane(void)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 1 };

	len = sizeof(kp);
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), &kp, &len, NULL, 0));
	ATF_REQUIRE_MSG(strcmp(kp.ki_comm, "capsule") == 0, "the capability "
	    "plane is off (PID 1 is %s): this pin runs with it on",
	    kp.ki_comm);
	ATF_REQUIRE_MSG(access("/dev/dq", F_OK) == 0, "/dev/dq: %s",
	    strerror(errno));
}

#define	NA	(-9999)		/* a step that was not reached */
#define	ERRNO_OF(call)	((call) == -1 ? errno : 0)

#define	ROW(what, got, want) do {					\
	int got_ = (int)(got), want_ = (int)(want);			\
	ATF_CHECK_EQ_MSG(want_, got_, "%s: got %d, pinned %d", (what),	\
	    got_, want_);						\
} while (0)

static int
cap_proc(int op, int fd, void *data)
{

	return (syscall(SYS_cap_process, op, fd, 0, data));
}

static int
plane_connect(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl == -1)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		saved = errno;
		(void)close(ctl);
		errno = saved;
		return (-1);
	}
	(void)close(ctl);
	return (ca.fd);
}

static int
chan_create(int pair[2])
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t op;
	int fd, peer, saved;

	fd = plane_connect("channel");
	if (fd == -1)
		return (-1);
	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer;
	ra.nfds = 1;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) != 0 ||
	    ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0 || ra.nfds != 1) {
		saved = errno;
		(void)close(fd);
		errno = saved != 0 ? saved : EPROTO;
		return (-1);
	}
	pair[0] = fd;
	pair[1] = peer;
	return (0);
}

/*
 * The kernel slot.  The test installs a channel of its own as its route,
 * so the far end is in its hands: a message the child sends on the
 * descriptor MAC_CAP_PROCESS_GET gave it arrives there and nowhere else.
 */
struct slot_res {
	int			 info_err, get_err, send_err, cloexec;
	struct mac_cap_process_info info;
};

static void
slot_child(void *arg, void *result)
{
	struct mac_capability_sendmsg_args sa;
	struct slot_res *r = result;
	const char *tag = arg;
	int fd;

	r->send_err = r->cloexec = NA;
	r->info_err = ERRNO_OF(cap_proc(MAC_CAP_PROCESS_INFO, -1, &r->info));
	fd = cap_proc(MAC_CAP_PROCESS_GET, -1, NULL);
	r->get_err = ERRNO_OF(fd);
	if (fd == -1)
		return;
	r->cloexec = (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
	memset(&sa, 0, sizeof(sa));
	sa.payload = tag;
	sa.payload_len = strlen(tag);
	r->send_err = ERRNO_OF(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

/* One queued message on the test's end of the route, or errno. */
static int
route_recv(int end, char *buf, size_t len)
{
	struct mac_capability_recvmsg_args ra;

	memset(buf, 0, len);
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = len - 1;
	return (ERRNO_OF(ioctl(end, MAC_CAPABILITY_RECVMSG, &ra)));
}

static void
slot_check(const char *who, const struct slot_res *r,
    const struct mac_cap_process_info *mine, int end, const char *tag)
{
	char buf[32];

	printf("%s: present %u identity %ju responsible %ju generation %ju "
	    "uid %u\n", who, r->info.present, (uintmax_t)r->info.identity,
	    (uintmax_t)r->info.responsible_identity,
	    (uintmax_t)r->info.generation, r->info.uid);
	ROW("MAC_CAP_PROCESS_INFO", r->info_err, 0);
	ROW("present", r->info.present, 1);
	ATF_CHECK_EQ_MSG(mine->generation, r->info.generation,
	    "%s: route generation %ju, the parent's is %ju", who,
	    (uintmax_t)r->info.generation, (uintmax_t)mine->generation);
	ATF_CHECK_EQ_MSG(mine->uid, r->info.uid, "%s: route uid", who);
	ROW("MAC_CAP_PROCESS_GET", r->get_err, 0);
	ROW("GET descriptor is close-on-exec", r->cloexec, 1);
	ROW("send on the GET descriptor", r->send_err, 0);
	ROW("arrives at the parent's far end", route_recv(end, buf,
	    sizeof(buf)), 0);
	ATF_CHECK_STREQ_MSG(tag, buf, "%s: the far end received \"%s\"", who,
	    buf);
}

ATF_TC(route_slot_inherited);
ATF_TC_HEAD(route_slot_inherited, tc)
{
	atf_tc_set_md_var(tc, "descr", "BS-0 (a), (c), the kernel half: a "
	    "child attached to a queue before it ran reports the route its "
	    "parent installed (present, same generation and uid), and "
	    "MAC_CAP_PROCESS_GET hands it a descriptor for that very "
	    "channel: what it sends arrives at the parent's far end.  An "
	    "unattached child sees the same.  BS-1 replaces the attached "
	    "child's route (ENOENT or the supervisor's channel); the "
	    "unattached rows stay");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(route_slot_inherited, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ach;
	struct mac_cap_process_info mine;
	struct slot_res r;
	char tag_a[] = "attached", tag_u[] = "unattached";
	int pair[2];

	pin_require_plane();
	ATF_REQUIRE_MSG(chan_create(pair) == 0, "channel: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, cap_proc(MAC_CAP_PROCESS_SET, pair[0], NULL),
	    "MAC_CAP_PROCESS_SET: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, cap_proc(MAC_CAP_PROCESS_INFO, -1, &mine));
	ATF_REQUIRE_EQ(1, mine.present);

	dqt_init(&c);
	dqt_attach_spawn(&c, &ach, slot_child, tag_a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ach, &r, sizeof(r));
	slot_check("attached", &r, &mine, pair[1], tag_a);

	memset(&r, 0, sizeof(r));
	dqt_run_child(slot_child, tag_u, &r, sizeof(r));
	slot_check("unattached", &r, &mine, pair[1], tag_u);

	dqt_fini(&c);
	ATF_CHECK_EQ(0, cap_proc(MAC_CAP_PROCESS_CLEAR, -1, NULL));
	(void)close(pair[0]);
	(void)close(pair[1]);
}

/*
 * The libraries.  The child keeps the route it was born with or clears it
 * itself, then asks for a public name the way base programs do.
 */
struct lookup_res {
	int			 info_err, present;
	int			 clear;
	int			 open_notify, open_log, open_sysctl;
	int			 notify, logcmp, sysctlcmp;
	int			 info2_err, present2;
};

static int
try_open(const char *name)
{
	int error, fd;

	fd = -1;
	error = ERRNO_OF(service_open(name, &fd));
	if (fd != -1)
		(void)close(fd);
	return (error);
}

static void
lookup_child(void *arg, void *result)
{
	struct mac_cap_process_info info;
	struct lookup_res *r = result;
	struct notify_client *nc;
	struct logcmp_client *lc;
	struct sysctlcmp_client *sc;
	bool clear = *(bool *)arg;

	memset(&info, 0, sizeof(info));
	r->info_err = ERRNO_OF(cap_proc(MAC_CAP_PROCESS_INFO, -1, &info));
	r->present = info.present;
	r->clear = clear ? ERRNO_OF(service_clear_ambient_lookup()) : NA;

	nc = NULL;
	r->notify = ERRNO_OF(notify_client_open(&nc));
	if (nc != NULL)
		notify_client_close(nc);
	lc = NULL;
	r->logcmp = ERRNO_OF(logcmp_client_open(&lc));
	if (lc != NULL)
		logcmp_client_close(lc);
	sc = NULL;
	r->sysctlcmp = ERRNO_OF(sysctlcmp_client_open(&sc));
	if (sc != NULL)
		sysctlcmp_client_close(sc);

	r->open_notify = try_open("system.Notify");
	r->open_log = try_open("system.Log");
	r->open_sysctl = try_open("system.Sysctl");

	memset(&info, 0, sizeof(info));
	r->info2_err = ERRNO_OF(cap_proc(MAC_CAP_PROCESS_INFO, -1, &info));
	r->present2 = info.present;
}

/*
 * What each consumer returns: with the route, and with it cleared.
 *
 * notify_client_open() is 0 with the route since the BSDNotify
 * NOFDRECV repair (5b1325c979a); before it both rows were EPIPE.
 */
struct lookup_want {
	int			 open_notify, open_log, open_sysctl;
	int			 notify, logcmp, sysctlcmp;
};
static const struct lookup_want want_route = { 0, 0, 0, 0, 0, 0 };
static const struct lookup_want want_cleared = {
	ENOENT, ENOENT, ENOENT, ENOENT, ENOENT, ENOENT
};

static void
lookup_check(const char *who, const struct lookup_res *r, bool cleared)
{
	const struct lookup_want *w = cleared ? &want_cleared : &want_route;

	printf("%s: present %d clear %d service_open %d/%d/%d clients "
	    "%d/%d/%d present after %d\n", who, r->present, r->clear,
	    r->open_notify, r->open_log, r->open_sysctl, r->notify,
	    r->logcmp, r->sysctlcmp, r->present2);
	ROW("MAC_CAP_PROCESS_INFO", r->info_err, 0);
	ROW("route present at birth", r->present, 1);
	ROW("service_clear_ambient_lookup", r->clear, cleared ? 0 : NA);
	ROW("service_open(system.Notify)", r->open_notify, w->open_notify);
	ROW("service_open(system.Log)", r->open_log, w->open_log);
	ROW("service_open(system.Sysctl)", r->open_sysctl, w->open_sysctl);
	ROW("notify_client_open", r->notify, w->notify);
	ROW("logcmp_client_open", r->logcmp, w->logcmp);
	ROW("sysctlcmp_client_open", r->sysctlcmp, w->sysctlcmp);
	ROW("route present afterwards", r->present2, cleared ? 0 : 1);
}

static void
lookup_pair(bool clear)
{
	struct dqt_ctl c;
	struct dqt_achild ach;
	struct mac_cap_process_info mine;
	struct lookup_res r;

	/* A pin does not skip: without a route there is nothing to pin. */
	ATF_REQUIRE_EQ_MSG(0, cap_proc(MAC_CAP_PROCESS_INFO, -1, &mine),
	    "MAC_CAP_PROCESS_INFO: %s", strerror(errno));
	ATF_REQUIRE_MSG(mine.present == 1, "the test program was started "
	    "without a service lookup route (capability plane off, or the "
	    "runner cleared it)");

	dqt_init(&c);
	dqt_attach_spawn(&c, &ach, lookup_child, &clear);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ach, &r, sizeof(r));
	lookup_check("attached", &r, clear);
	dqt_fini(&c);

	memset(&r, 0, sizeof(r));
	dqt_run_child(lookup_child, &clear, &r, sizeof(r));
	lookup_check("unattached", &r, clear);
}

ATF_TC(public_lookup);
ATF_TC_HEAD(public_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr", "BS-0 (a), (c), the SwitchBoard half: "
	    "a child attached before it ran resolves the public names "
	    "system.Notify, system.Log and system.Sysctl through the route "
	    "it inherited, by service_open and by the three base client "
	    "libraries, exactly as an unattached child does.  BS-1 flips "
	    "the attached rows (ENOENT, or the supervisor answers); the "
	    "unattached rows stay");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(public_lookup, tc)
{

	pin_require_plane();
	lookup_pair(false);
}

ATF_TC(cleared_lookup);
ATF_TC_HEAD(cleared_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr", "BS-0 (d): a program that clears its "
	    "own route (service_clear_ambient_lookup) gets the same answer "
	    "from service_open and from the notify, log and sysctl clients "
	    "whether it is attached or not.  This is what a confined "
	    "program sees at BS-1 when the supervisor serves no bootstrap: "
	    "the errnos recorded here are the ones base consumers must "
	    "already handle");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(cleared_lookup, tc)
{

	pin_require_plane();
	lookup_pair(true);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, route_slot_inherited);
	ATF_TP_ADD_TC(tp, public_lookup);
	ATF_TP_ADD_TC(tp, cleared_lookup);
	return (atf_no_error());
}
