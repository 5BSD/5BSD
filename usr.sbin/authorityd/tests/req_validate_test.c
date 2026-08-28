/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/socket.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "config.h"
#include "req_validate.h"

ATF_TC_WITHOUT_HEAD(bluetooth_network_requests);
ATF_TC_BODY(bluetooth_network_requests, tc)
{
	static const int protocols[] = { 0, ORT_BTPROTO_HCI,
	    ORT_BTPROTO_L2CAP, ORT_BTPROTO_RFCOMM, ORT_BTPROTO_SCO,
	    ORT_BTPROTO_ISO };
	struct authority_net_req req;
	struct ort_net_claim claim;
	unsigned i;
	int error;

	for (i = 0; i < nitems(protocols); i++) {
		memset(&req, 0, sizeof(req));
		req.op = AUTHORITY_OP_MINT_NET;
		req.domain = AF_BLUETOOTH;
		req.protocol = protocols[i];
		req.port_max = UINT16_MAX;
		req.direction = ORT_NET_DIR_ANY;
		ATF_CHECK(validate_net_req(&req, sizeof(req), &claim, &error));
		ATF_CHECK_EQ(AF_BLUETOOTH, claim.domain);
		ATF_CHECK_EQ(protocols[i], claim.protocol);
	}

	req.protocol = IPPROTO_TCP;
	ATF_CHECK(!validate_net_req(&req, sizeof(req), &claim, &error));
	ATF_CHECK_EQ(EINVAL, error);
	req.protocol = ORT_BTPROTO_L2CAP;
	req.prefix = 47;
	ATF_CHECK(!validate_net_req(&req, sizeof(req), &claim, &error));
	ATF_CHECK_EQ(EINVAL, error);
	req.prefix = 48;
	ATF_CHECK(validate_net_req(&req, sizeof(req), &claim, &error));
}

ATF_TC_WITHOUT_HEAD(strict_wire_shape);
ATF_TC_BODY(strict_wire_shape, tc)
{
	struct authority_net_req req;
	struct ort_net_claim claim;
	int error;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_MINT_NET;
	req.domain = AF_INET;
	req.protocol = IPPROTO_TCP;
	req.port_max = UINT16_MAX;
	req.direction = ORT_NET_DIR_BIND;
	ATF_REQUIRE(validate_net_req(&req, sizeof(req), &claim, &error));
	ATF_CHECK(!validate_net_req(&req, sizeof(req) - 1, &claim, &error));
	ATF_CHECK(!validate_net_req(&req, sizeof(req) + 1, &claim, &error));
	req._reserved[0] = 1;
	ATF_CHECK(!validate_net_req(&req, sizeof(req), &claim, &error));

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_MINT_NET;
	req.domain = 0;
	req.port_max = UINT16_MAX;
	req.direction = ORT_NET_DIR_ANY;
	req.addr[15] = 1;
	ATF_CHECK(!validate_net_req(&req, sizeof(req), &claim, &error));
}

ATF_TC_WITHOUT_HEAD(kmod_request_validation);
ATF_TC_BODY(kmod_request_validation, tc)
{
	struct authority_kmod_req req;
	const struct authority_kmod_req *validated;
	int error;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_ENSURE_KMOD;
	strlcpy(req.name, "mac_capability", sizeof(req.name));
	ATF_CHECK(validate_kmod_req(&req, sizeof(req), &validated, &error));
	ATF_CHECK_STREQ(req.name, validated->name);
	ATF_CHECK(!validate_kmod_req(&req, sizeof(req) - 1, &validated,
	    &error));
	strlcpy(req.name, "../evil.ko", sizeof(req.name));
	ATF_CHECK(!validate_kmod_req(&req, sizeof(req), &validated, &error));
	req.name[0] = '\0';
	ATF_CHECK(!validate_kmod_req(&req, sizeof(req), &validated, &error));
}

ATF_TC_WITHOUT_HEAD(service_request_validation);
ATF_TC_BODY(service_request_validation, tc)
{
	static const char *const valid[] = { "mount", "node", "accounting",
	    "identity" };
	struct authority_service_req req;
	const struct authority_service_req *validated;
	unsigned i;
	int error;

	for (i = 0; i < nitems(valid); i++) {
		memset(&req, 0, sizeof(req));
		req.op = AUTHORITY_OP_DELEGATE_SERVICE;
		strlcpy(req.name, valid[i], sizeof(req.name));
		ATF_CHECK(validate_service_req(&req, sizeof(req), &validated,
		    &error));
		ATF_CHECK_STREQ(valid[i], validated->name);
	}
	ATF_CHECK(!validate_service_req(&req, sizeof(req) - 1, &validated,
	    &error));
	memset(&req, 'x', sizeof(req));
	req.op = AUTHORITY_OP_DELEGATE_SERVICE;
	req._pad = 0;
	ATF_CHECK(!validate_service_req(&req, sizeof(req), &validated, &error));
	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "channel", sizeof(req.name));
	ATF_CHECK(!validate_service_req(&req, sizeof(req), &validated, &error));
	strlcpy(req.name, "mount", sizeof(req.name));
	req._pad = 1;
	ATF_CHECK(!validate_service_req(&req, sizeof(req), &validated, &error));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bluetooth_network_requests);
	ATF_TP_ADD_TC(tp, strict_wire_shape);
	ATF_TP_ADD_TC(tp, kmod_request_validation);
	ATF_TP_ADD_TC(tp, service_request_validation);
	return (atf_no_error());
}
