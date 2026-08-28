/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the shared claim-parse helpers, focused on the
 * AF_BLUETOOTH reservation grammar: protocol name mapping, BD_ADDR
 * parsing, and the fully-wildcard reservation that trips the
 * mac_capability_isolation block-all socket() gate.
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <stdint.h>
#include <string.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <atf-c.h>

#include "claim_parse.h"
#include "authorityrt.h"

/*
 * Mirror of the ort_net_claim -> fi_net_request assembly authorityd uses
 * in mac_capability_claim_net().  Kept here so the test asserts the
 * exact wire form the kernel receives, independent of authorityd.
 */
static void
build_fi_net_request(const struct ort_net_claim *nc, struct fi_net_request *req)
{

	memset(req, 0, sizeof(*req));
	req->op = FI_OP_CLAIM_NET;
	req->domain = nc->domain;
	req->protocol = nc->protocol;
	req->port_min = htons(nc->port_min);
	req->port_max = htons(nc->port_max);
	req->direction = nc->direction;
	req->prefix = nc->prefix;
	memcpy(req->addr, nc->addr, sizeof(req->addr));
}

ATF_TC_WITHOUT_HEAD(protocol_names);
ATF_TC_BODY(protocol_names, tc)
{
	int p;

	ATF_REQUIRE(parse_net_protocol_string("any", &p) == 0);
	ATF_CHECK_EQ(0, p);
	ATF_REQUIRE(parse_net_protocol_string("*", &p) == 0);
	ATF_CHECK_EQ(0, p);
	ATF_REQUIRE(parse_net_protocol_string("tcp", &p) == 0);
	ATF_CHECK_EQ(IPPROTO_TCP, p);
	ATF_REQUIRE(parse_net_protocol_string("udp", &p) == 0);
	ATF_CHECK_EQ(IPPROTO_UDP, p);
	ATF_REQUIRE(parse_net_protocol_string("l2cap", &p) == 0);
	ATF_CHECK_EQ(ORT_BTPROTO_L2CAP, p);
	ATF_REQUIRE(parse_net_protocol_string("rfcomm", &p) == 0);
	ATF_CHECK_EQ(ORT_BTPROTO_RFCOMM, p);
	ATF_REQUIRE(parse_net_protocol_string("sco", &p) == 0);
	ATF_CHECK_EQ(ORT_BTPROTO_SCO, p);
	ATF_REQUIRE(parse_net_protocol_string("iso", &p) == 0);
	ATF_CHECK_EQ(ORT_BTPROTO_ISO, p);
	ATF_REQUIRE(parse_net_protocol_string("hci", &p) == 0);
	ATF_CHECK_EQ(ORT_BTPROTO_HCI, p);

	ATF_CHECK_STREQ("any", ort_net_protocol_name(0));
	ATF_CHECK_STREQ("tcp", ort_net_protocol_name(IPPROTO_TCP));
	ATF_CHECK_STREQ("udp", ort_net_protocol_name(IPPROTO_UDP));
	ATF_CHECK_STREQ("hci", ort_net_protocol_name(ORT_BTPROTO_HCI));
	ATF_CHECK_STREQ("l2cap", ort_net_protocol_name(ORT_BTPROTO_L2CAP));
	ATF_CHECK_STREQ("rfcomm", ort_net_protocol_name(ORT_BTPROTO_RFCOMM));
	ATF_CHECK_STREQ("sco", ort_net_protocol_name(ORT_BTPROTO_SCO));
	ATF_CHECK_STREQ("iso", ort_net_protocol_name(ORT_BTPROTO_ISO));
	ATF_CHECK_STREQ("any", ort_net_domain_name(0));
	ATF_CHECK_STREQ("inet", ort_net_domain_name(AF_INET));
	ATF_CHECK_STREQ("inet6", ort_net_domain_name(AF_INET6));
	ATF_CHECK_STREQ("bluetooth", ort_net_domain_name(AF_BLUETOOTH));

	/* Unknown names are rejected. */
	ATF_CHECK(parse_net_protocol_string("sctp", &p) != 0);
	ATF_CHECK(parse_net_protocol_string("bluetooth", &p) != 0);
	ATF_CHECK(parse_net_protocol_string("", &p) != 0);
}

ATF_TC_WITHOUT_HEAD(bdaddr_wildcard);
ATF_TC_BODY(bdaddr_wildcard, tc)
{
	uint8_t addr[16];
	uint8_t prefix = 0xff;
	uint8_t zero[16];

	memset(zero, 0, sizeof(zero));

	/* "*" is the any-address wildcard: all-zero addr, prefix 0. */
	ATF_REQUIRE(parse_bdaddr_string("*", addr, &prefix) == 0);
	ATF_CHECK_EQ(0, prefix);
	ATF_CHECK(memcmp(addr, zero, sizeof(addr)) == 0);
}

ATF_TC_WITHOUT_HEAD(bdaddr_exact);
ATF_TC_BODY(bdaddr_exact, tc)
{
	uint8_t addr[16];
	uint8_t prefix = 0;
	int i;

	/*
	 * A literal fills addr[0..5] in bt_aton(3) order: leftmost octet
	 * is most significant (b[5]).  prefix is 48 for an exact match.
	 */
	ATF_REQUIRE(parse_bdaddr_string("00:11:22:33:44:55", addr,
	    &prefix) == 0);
	ATF_CHECK_EQ(48, prefix);
	ATF_CHECK_EQ(0x55, addr[0]);
	ATF_CHECK_EQ(0x44, addr[1]);
	ATF_CHECK_EQ(0x33, addr[2]);
	ATF_CHECK_EQ(0x22, addr[3]);
	ATF_CHECK_EQ(0x11, addr[4]);
	ATF_CHECK_EQ(0x00, addr[5]);
	/* Remaining bytes stay zero -- only the 6-byte BD_ADDR is set. */
	for (i = 6; i < 16; i++)
		ATF_CHECK_EQ(0, addr[i]);
}

ATF_TC_WITHOUT_HEAD(bdaddr_malformed);
ATF_TC_BODY(bdaddr_malformed, tc)
{
	uint8_t addr[16];
	uint8_t prefix;

	/* Too few octets. */
	ATF_CHECK(parse_bdaddr_string("00:11:22:33:44", addr, &prefix) != 0);
	/* Too many octets. */
	ATF_CHECK(parse_bdaddr_string("00:11:22:33:44:55:66", addr,
	    &prefix) != 0);
	/* Octet out of range. */
	ATF_CHECK(parse_bdaddr_string("00:11:22:33:44:1ff", addr,
	    &prefix) != 0);
	/* Non-hex garbage. */
	ATF_CHECK(parse_bdaddr_string("gg:hh:ii:jj:kk:ll", addr,
	    &prefix) != 0);
	/* Trailing junk after a valid address. */
	ATF_CHECK(parse_bdaddr_string("00:11:22:33:44:55x", addr,
	    &prefix) != 0);
	/* Empty string. */
	ATF_CHECK(parse_bdaddr_string("", addr, &prefix) != 0);
}

/*
 * The reservation the broker needs: a fully-wildcard AF_BLUETOOTH claim
 * whose fi_net_request matches the kernel block-all gate exactly --
 * domain AF_BLUETOOTH, protocol 0, port_min 0, port_max 0xffff,
 * direction FI_NET_ANY, prefix 0, addr all-zero.
 */
ATF_TC_WITHOUT_HEAD(wildcard_reservation_matches_kernel_schema);
ATF_TC_BODY(wildcard_reservation_matches_kernel_schema, tc)
{
	struct ort_net_claim nc;
	struct fi_net_request req;
	uint8_t zero[16];

	memset(zero, 0, sizeof(zero));

	/* Build the wildcard reservation as the parsers would. */
	memset(&nc, 0, sizeof(nc));
	nc.port_min = 0;
	nc.port_max = UINT16_MAX;
	ATF_REQUIRE(parse_net_protocol_string("any", &nc.protocol) == 0);
	nc.domain = AF_BLUETOOTH;
	ATF_REQUIRE(parse_bdaddr_string("*", nc.addr, &nc.prefix) == 0);
	nc.direction = ORT_NET_DIR_ANY;

	build_fi_net_request(&nc, &req);

	ATF_CHECK_EQ(AF_BLUETOOTH, req.domain);
	ATF_CHECK_EQ(0, req.protocol);
	ATF_CHECK_EQ(0, req.port_min);
	ATF_CHECK_EQ(htons(UINT16_MAX), req.port_max);
	/* htons(0xffff) is still 0xffff regardless of endianness. */
	ATF_CHECK_EQ(0xffff, req.port_max);
	ATF_CHECK_EQ(FI_NET_ANY, req.direction);
	ATF_CHECK_EQ(0, req.prefix);
	ATF_CHECK(memcmp(req.addr, zero, sizeof(req.addr)) == 0);

	/* ORT_NET_DIR_ANY and the kernel's FI_NET_ANY are the same bit. */
	ATF_CHECK_EQ(FI_NET_ANY, ORT_NET_DIR_ANY);
}

/*
 * A scoped L2CAP claim (specific BD_ADDR + PSM) carries the BD_ADDR in
 * addr[0..5] with prefix 48 and the PSM in the port fields in network
 * byte order -- the per-channel form the kernel's bind/connect check
 * keys on.
 */
ATF_TC_WITHOUT_HEAD(scoped_l2cap_claim);
ATF_TC_BODY(scoped_l2cap_claim, tc)
{
	struct ort_net_claim nc;
	struct fi_net_request req;

	memset(&nc, 0, sizeof(nc));
	ATF_REQUIRE(parse_net_protocol_string("l2cap", &nc.protocol) == 0);
	nc.domain = AF_BLUETOOTH;
	ATF_REQUIRE(parse_bdaddr_string("00:11:22:33:44:55", nc.addr,
	    &nc.prefix) == 0);
	/* PSM 0x0080 as a single-value port range. */
	nc.port_min = 0x0080;
	nc.port_max = 0x0080;
	nc.direction = ORT_NET_DIR_CONNECT;

	build_fi_net_request(&nc, &req);

	ATF_CHECK_EQ(AF_BLUETOOTH, req.domain);
	ATF_CHECK_EQ(ORT_BTPROTO_L2CAP, req.protocol);
	ATF_CHECK_EQ(48, req.prefix);
	ATF_CHECK_EQ(0x55, req.addr[0]);
	ATF_CHECK_EQ(0x00, req.addr[5]);
	ATF_CHECK_EQ(htons(0x0080), req.port_min);
	ATF_CHECK_EQ(htons(0x0080), req.port_max);
	ATF_CHECK_EQ(FI_NET_CONNECT, req.direction);
}

ATF_TC_WITHOUT_HEAD(storage_lifetimes);
ATF_TC_BODY(storage_lifetimes, tc)
{
	uint8_t lifetime;

	ATF_REQUIRE_EQ(0, parse_storage_lifetime_string(NULL, &lifetime));
	ATF_CHECK_EQ(ORT_STORAGE_PERSISTENT, lifetime);
	ATF_REQUIRE_EQ(0, parse_storage_lifetime_string("persistent", &lifetime));
	ATF_CHECK_EQ(ORT_STORAGE_PERSISTENT, lifetime);
	ATF_REQUIRE_EQ(0, parse_storage_lifetime_string("cache", &lifetime));
	ATF_CHECK_EQ(ORT_STORAGE_CACHE, lifetime);
	ATF_REQUIRE_EQ(0, parse_storage_lifetime_string("boot", &lifetime));
	ATF_CHECK_EQ(ORT_STORAGE_BOOT, lifetime);
	ATF_REQUIRE_EQ(0, parse_storage_lifetime_string("lease", &lifetime));
	ATF_CHECK_EQ(ORT_STORAGE_LEASE, lifetime);
	ATF_CHECK(parse_storage_lifetime_string("ephemeral", &lifetime) == -1);
	ATF_CHECK(parse_storage_lifetime_string("", &lifetime) == -1);
	ATF_CHECK(parse_storage_lifetime_string("forever", &lifetime) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, protocol_names);
	ATF_TP_ADD_TC(tp, bdaddr_wildcard);
	ATF_TP_ADD_TC(tp, bdaddr_exact);
	ATF_TP_ADD_TC(tp, bdaddr_malformed);
	ATF_TP_ADD_TC(tp, wildcard_reservation_matches_kernel_schema);
	ATF_TP_ADD_TC(tp, scoped_l2cap_claim);
	ATF_TP_ADD_TC(tp, storage_lifetimes);

	return (atf_no_error());
}
