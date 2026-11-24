/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Mark an interface up or down with a netlink RTM_NEWLINK request.  Unlike
 * SIOCSIFFLAGS, which ifconfig(8) uses, the kernel then calls if_up() or
 * if_down() without a request to the driver, so IFF_UP changes and the
 * driver's running state does not.
 *
 * usage: nl_ifupdown ifname up|down
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
	struct snl_state ss;
	struct snl_writer nw;
	struct snl_errmsg_data e = { 0 };
	struct nlmsghdr *hdr;
	struct ifinfomsg *ifi;
	int flags;

	if (argc != 3)
		errx(2, "usage: nl_ifupdown ifname up|down");
	if (strcmp(argv[2], "up") == 0)
		flags = IFF_UP;
	else if (strcmp(argv[2], "down") == 0)
		flags = 0;
	else
		errx(2, "usage: nl_ifupdown ifname up|down");

	if (!snl_init(&ss, NETLINK_ROUTE))
		err(1, "snl_init");
	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, NL_RTM_NEWLINK);
	ifi = snl_reserve_msg_object(&nw, struct ifinfomsg);
	snl_add_msg_attr_string(&nw, IFLA_IFNAME, argv[1]);
	if (ifi != NULL) {
		ifi->ifi_flags = flags;
		ifi->ifi_change = IFF_UP;
	}
	hdr = snl_finalize_msg(&nw);
	if (hdr == NULL)
		errx(1, "cannot build the request");
	if (!snl_send_message(&ss, hdr))
		err(1, "send");
	if (!snl_read_reply_code(&ss, hdr->nlmsg_seq, &e))
		errc(1, e.error, "RTM_NEWLINK %s %s", argv[1], argv[2]);
	snl_free(&ss);
	return (0);
}
