/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_TEST_RETIRED_PROTOCOL_H
#define SWITCHBOARD_TEST_RETIRED_PROTOCOL_H

/* Historical request layout for rejection tests only. Never issue grants. */
#include <switchboard_svc_proto.h>
#define SVC_MINT_DOMAIN_USER 0U
#define SVC_MINT_DOMAIN_SYSTEM 1U
struct svc_mint_domain_req {
 uint32_t op, flags, uid, domain, nanointments, reserved;
 char anointments[SVC_ANOINT_MAX][SVC_ANOINT_NAME_MAX];
};
#endif
