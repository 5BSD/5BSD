/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NETWORK_STATE_H_
#define _NETWORK_STATE_H_
#include <sys/types.h>

#include <stdint.h>
#define NETWORK_STATE_INTERFACE	       "system.Network.State"
#define NETWORK_STATE_RIGHT_READ       UINT64_C(1)
#define NETWORK_STATE_MAX_INTERFACES   256
#define NETWORK_STATE_TIMEOUT_INFINITE UINT32_MAX
#define NETWORK_STATE_LINK_UNKNOWN     0
#define NETWORK_STATE_LINK_DOWN	       1
#define NETWORK_STATE_LINK_UP	       2
struct network_state_interface {
	uint32_t index, flags, mtu;
	uint8_t link_state, reserved[3];
	char name[16];
};
struct network_state_snapshot {
	uint64_t epoch, generation;
	int32_t source_error; /* Positive errno; zero means current data
				 available. */
	uint32_t count;
	struct network_state_interface interfaces[NETWORK_STATE_MAX_INTERFACES];
};
struct network_state_client;
__BEGIN_DECLS
int network_state_open(struct network_state_client **);
/* First call returns immediately. Later calls coalesce changes; EAGAIN on
 * timeout. */
int network_state_watch(struct network_state_client *,
    struct network_state_snapshot *, uint32_t);
void network_state_close(struct network_state_client *);
__END_DECLS
#endif
