/* SPDX-License-Identifier: BSD-2-Clause */
/* Preserve the command-response seam of the existing encoder fixtures. */
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

int __wrap_bt_devreq_events(int, struct bt_devreq *, time_t,
    void (*)(int, const void *, size_t));

int
__wrap_bt_devreq_events(int fd, struct bt_devreq *r, time_t timeout,
    void (*event_cb)(int, const void *, size_t) __unused)
{

	return (bt_devreq(fd, r, timeout));
}
