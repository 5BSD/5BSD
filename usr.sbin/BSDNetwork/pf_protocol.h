// SPDX-License-Identifier: BSD-2-Clause
#pragma once
#include <stdint.h>
#include <sys/ioctl.h>

#define PF_MONITOR_SERVICE "system.Network.PF"
#define PF_MONITOR_RIGHT_READ UINT64_C(1)
#define PF_MONITOR_MAGIC UINT32_C(0x50465331)
struct pf_monitor_message { uint32_t magic; int32_t error; };

// The client's descriptor admits only pf(4)'s read-only state export,
// DIOCGETSTATES (struct pfioc_states of struct pfsync_state, <net/pfvar.h>).
#define PF_MONITOR_GETSTATES DIOCGETSTATES
