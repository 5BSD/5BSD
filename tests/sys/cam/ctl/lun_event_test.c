/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <stdio.h>

#include <cam/scsi/scsi_all.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	LIVE_EVENT_LUNS	(CTL_LUN_EVENT_QUEUE_MIN + 2)

static uint32_t live_luns[LIVE_EVENT_LUNS];
static size_t live_nluns;

static int
create_live_lun(uint32_t *lun_id)
{
	char line[256];
	FILE *fp;
	unsigned int id;
	int status;
	bool found;

	fp = popen("ctladm create -b ramdisk -s 1048576 "
	    "-o capacity=1048576", "r");
	if (fp == NULL)
		return (errno);
	found = false;
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "LUN ID: %u", &id) == 1) {
			*lun_id = id;
			found = true;
		}
	}
	status = pclose(fp);
	if (status == -1)
		return (errno);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || !found)
		return (EIO);
	return (0);
}

static void
remove_live_luns(void)
{
	char command[128];

	while (live_nluns != 0) {
		live_nluns--;
		(void)snprintf(command, sizeof(command),
		    "ctladm remove -b ramdisk -l %u >/dev/null 2>&1",
		    live_luns[live_nluns]);
		(void)system(command);
	}
}

ATF_TC_WITHOUT_HEAD(abi_layout);
ATF_TC_BODY(abi_layout, tc)
{

	/*
	 * These values are the published CTL userspace ABI, not values imported
	 * from the bhyve device model.
	 */
	ATF_CHECK_EQ(sizeof(struct ctl_lun_event_subscribe), 24);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event_subscribe, version), 0);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event_subscribe, queue_depth), 8);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event_subscribe, sequence), 16);
	ATF_CHECK_EQ(sizeof(struct ctl_lun_event), 32);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event, type), 4);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event, lun_id), 12);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event, sequence), 16);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event, device_type), 24);
	ATF_CHECK_EQ(offsetof(struct ctl_lun_event, reserved), 28);
	ATF_CHECK_EQ(CTL_LUN_EVENT_VERSION, 2);
	ATF_CHECK_EQ(CTL_LUN_EVENT_QUEUE_MIN, 16);
	ATF_CHECK_EQ(CTL_LUN_EVENT_QUEUE_DEFAULT, 128);
	ATF_CHECK_EQ(CTL_LUN_EVENT_QUEUE_MAX, 1024);
	ATF_CHECK_EQ(CTL_LUN_EVENT_RESCAN, 0);
	ATF_CHECK_EQ(CTL_LUN_EVENT_ADDED, 1);
	ATF_CHECK_EQ(CTL_LUN_EVENT_REMOVED, 2);
	ATF_CHECK_EQ(CTL_LUN_EVENT_CHANGED, 3);
	ATF_CHECK_EQ(CTL_LUN_EVENT_F_MISSED, 1);
	ATF_CHECK_EQ(CTL_LUN_EVENT_DEVICE_TYPE_UNKNOWN, UINT32_MAX);
}

ATF_TC(live_subscription);
ATF_TC_HEAD(live_subscription, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.files", CTL_DEFAULT_DEV);
}
ATF_TC_BODY(live_subscription, tc)
{
	struct ctl_lun_event_subscribe subscribe;
	struct ctl_lun_event event;
	struct pollfd pfd;
	int fd;

	fd = open(CTL_DEFAULT_DEV, O_RDWR | O_NONBLOCK);
	ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", CTL_DEFAULT_DEV,
	    strerror(errno));

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.version = CTL_LUN_EVENT_VERSION + 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CTL_LUN_EVENT_SUBSCRIBE,
	    &subscribe) == -1);

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.version = CTL_LUN_EVENT_VERSION;
	subscribe.queue_depth = CTL_LUN_EVENT_QUEUE_MIN - 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CTL_LUN_EVENT_SUBSCRIBE,
	    &subscribe) == -1);

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.version = CTL_LUN_EVENT_VERSION;
	ATF_REQUIRE_MSG(ioctl(fd, CTL_LUN_EVENT_SUBSCRIBE, &subscribe) == 0,
	    "subscribe: %s", strerror(errno));
	ATF_CHECK_EQ(subscribe.queue_depth, CTL_LUN_EVENT_QUEUE_DEFAULT);

	ATF_CHECK_ERRNO(EALREADY, ioctl(fd, CTL_LUN_EVENT_SUBSCRIBE,
	    &subscribe) == -1);
	pfd = (struct pollfd){
		.fd = fd,
		.events = POLLIN,
	};
	ATF_REQUIRE_EQ(poll(&pfd, 1, 0), 1);
	ATF_CHECK((pfd.revents & POLLIN) != 0);

	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	event.device_type = 1;
	ATF_CHECK_ERRNO(EINVAL, ioctl(fd, CTL_LUN_EVENT_NEXT, &event) == -1);

	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	ATF_REQUIRE_MSG(ioctl(fd, CTL_LUN_EVENT_NEXT, &event) == 0,
	    "initial event: %s", strerror(errno));
	ATF_CHECK_EQ(event.version, CTL_LUN_EVENT_VERSION);
	ATF_CHECK_EQ(event.type, CTL_LUN_EVENT_RESCAN);
	ATF_CHECK_EQ(event.flags, 0);
	ATF_CHECK_EQ(event.lun_id, UINT32_MAX);
	ATF_CHECK_EQ(event.sequence, subscribe.sequence);
	ATF_CHECK_EQ(event.device_type, CTL_LUN_EVENT_DEVICE_TYPE_UNKNOWN);
	ATF_CHECK_EQ(event.reserved, 0);

	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, CTL_LUN_EVENT_NEXT, &event) == -1);
	ATF_REQUIRE_EQ(close(fd), 0);
}

ATF_TC_WITH_CLEANUP(live_loss_boundary);
ATF_TC_HEAD(live_loss_boundary, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.files", CTL_DEFAULT_DEV);
	atf_tc_set_md_var(tc, "require.progs", "ctladm");
}
ATF_TC_BODY(live_loss_boundary, tc)
{
	struct ctl_lun_event_subscribe subscribe;
	struct ctl_lun_event event;
	uint64_t previous;
	int error, fd;

	live_nluns = 0;
	fd = open(CTL_DEFAULT_DEV, O_RDWR | O_NONBLOCK);
	ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", CTL_DEFAULT_DEV,
	    strerror(errno));

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.version = CTL_LUN_EVENT_VERSION;
	subscribe.queue_depth = CTL_LUN_EVENT_QUEUE_MIN;
	ATF_REQUIRE_MSG(ioctl(fd, CTL_LUN_EVENT_SUBSCRIBE, &subscribe) == 0,
	    "subscribe: %s", strerror(errno));
	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	ATF_REQUIRE_EQ(ioctl(fd, CTL_LUN_EVENT_NEXT, &event), 0);
	ATF_REQUIRE_EQ(event.type, CTL_LUN_EVENT_RESCAN);

	/*
	 * Fill all 16 slots, then lose event 17.  After one retained event is
	 * consumed, event 18 is accepted and must carry the loss boundary.
	 */
	for (size_t i = 0; i < CTL_LUN_EVENT_QUEUE_MIN + 1; i++) {
		error = create_live_lun(&live_luns[live_nluns]);
		ATF_REQUIRE_MSG(error == 0, "create LUN %zu: %s", i,
		    strerror(error));
		live_nluns++;
	}

	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	ATF_REQUIRE_EQ(ioctl(fd, CTL_LUN_EVENT_NEXT, &event), 0);
	ATF_CHECK_EQ(event.type, CTL_LUN_EVENT_ADDED);
	ATF_CHECK_EQ(event.flags, 0);
	ATF_CHECK_EQ(event.device_type, T_DIRECT);
	previous = event.sequence;

	error = create_live_lun(&live_luns[live_nluns]);
	ATF_REQUIRE_MSG(error == 0, "create boundary LUN: %s",
	    strerror(error));
	live_nluns++;

	for (size_t i = 0; i < CTL_LUN_EVENT_QUEUE_MIN; i++) {
		memset(&event, 0, sizeof(event));
		event.version = CTL_LUN_EVENT_VERSION;
		ATF_REQUIRE_EQ(ioctl(fd, CTL_LUN_EVENT_NEXT, &event), 0);
		ATF_CHECK_EQ(event.type, CTL_LUN_EVENT_ADDED);
		ATF_CHECK(event.sequence > previous);
		ATF_CHECK_EQ(event.device_type, T_DIRECT);
		if (i + 1 == CTL_LUN_EVENT_QUEUE_MIN)
			ATF_CHECK_EQ(event.flags, CTL_LUN_EVENT_F_MISSED);
		else
			ATF_CHECK_EQ(event.flags, 0);
		previous = event.sequence;
	}
	memset(&event, 0, sizeof(event));
	event.version = CTL_LUN_EVENT_VERSION;
	ATF_CHECK_ERRNO(EAGAIN, ioctl(fd, CTL_LUN_EVENT_NEXT, &event) == -1);
	ATF_REQUIRE_EQ(close(fd), 0);
}
ATF_TC_CLEANUP(live_loss_boundary, tc)
{

	remove_live_luns();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi_layout);
	ATF_TP_ADD_TC(tp, live_subscription);
	ATF_TP_ADD_TC(tp, live_loss_boundary);
	return (atf_no_error());
}
