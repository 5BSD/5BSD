/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for certificate-based provisioning: the provisioning record
 * transfer procedure (MshPRT_v1.1.1 Sections 5.4.1.11 - 5.4.1.14 and 5.4.2.6)
 * and the certificate-delivered OOB Public Key it feeds (Sections 5.4.2.3 and
 * 5.5).
 *
 * Every case drives a meshd ENTRY POINT, never a libmesh function directly:
 *
 *   meshd_prov_records_recv()	a PB-ADV packet arriving for the record
 *				service this node offers while unprovisioned;
 *   meshd_prov_records_drain()	that service's bearer output;
 *   meshd_unprov_beacon_emit()	the Unprovisioned Device beacon whose OOB
 *				Information field advertises the feature;
 *   meshd_provisioner_begin()	/ _recv() / _poll(), the Provisioner side that
 *				retrieves and validates a device's certificate
 *				before it sends the Provisioning Invite PDU;
 *   meshd_ctl_exec()		the "provision-cert" and "provision-records"
 *				control verbs meshctl(8) sends.
 *
 * Oracles.  BlueZ 5.87's mesh/ subtree implements none of this -- there is no
 * provisioning record PDU, no Record ID, and no certificate handling anywhere
 * in it, and its provisioning PDU table stops at Provisioning Failed (0x09) --
 * so, as with Subnet Bridge, there is no second implementation to check
 * against and the specification text is the only adjudicator.  The wire
 * vectors are therefore the verbatim PB-ADV octets of Section 8.13
 * ("Provisioning Record Retrieval"), which pin the Type octets, the field
 * order and widths, the transaction numbering, the segmentation and the FCS.
 *
 * The certificates cannot come from the specification: Section 8.11.2 gives a
 * Device Certificate but not the CA that signed it, and its validity ended in
 * March 2024, so nothing can be validated against it.  The path-validation
 * cases therefore build their own two-certificate PKI here, and the Section
 * 8.11.2 sample is used where it can be: as the record payload whose first
 * fragment is compared byte for byte with Section 8.13.7.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "mesh_test_heap.h"
#include "meshd.h"

/* ================================================================
 * Section 8.13 sample data.  MshPRT_v1.1.1, "Provisioning Record Retrieval".
 * ================================================================ */

/* "The provisioning link has been opened, and the link ID is 0x1289ef." */
#define	SAMPLE_LINK_ID		0x001289efU

/* 8.13.1 PB-ADV Provisioning Records Get, Message0. */
static const char SAMPLE_RECORDS_GET[] = "001289ef00000001390c";
/* 8.13.3 PB-ADV Provisioning Records List, Message0. */
static const char SAMPLE_RECORDS_LIST[] = "001289ef80000007f10d000000010002";
/* 8.13.2 and 8.13.6: the Transaction Acknowledgments the device sends. */
static const char SAMPLE_TXN_ACK_GET[] = "001289ef0001";
static const char SAMPLE_TXN_ACK_REQ[] = "001289ef0101";
/* 8.13.5 PB-ADV Device Certificate Record Request, Message0. */
static const char SAMPLE_RECORD_REQ[] = "001289ef01000007940a00010000003a";
/*
 * 8.13.7 PB-ADV Device Certificate Record Response.  The section's three
 * "SegmentN" lines, each prefixed with the PB-ADV LinkID and Transaction
 * number and, for Segment0, the SegN / PDU Length / FCS header the section
 * states separately (SegN 02, PDU Length 0042, FCS ce).
 *
 * The section's own "Message :" line is one octet short of its field values
 * and of these segments: it drops one of the two 0x00 octets between the Type
 * and the Record ID, so it decodes to Record ID 0x0100 rather than to the
 * 0x0001 the section states.  The segments and the field list agree with each
 * other and with the stated PDU Length of 0x42 (Type + 7 parameter octets + a
 * 58-octet fragment), so the segments are taken as authoritative and the
 * Message line as a transcription erratum.
 */
static const char SAMPLE_RSP_SEG0[] = "001289ef81" "08" "0042" "ce"
    "0b000001000002b8308202b43082025aa0030201";
static const char SAMPLE_RSP_SEG1[] = "001289ef81" "06"
    "0202021000300a06082a8648ce3d0403023081a7310b30";
static const char SAMPLE_RSP_SEG2[] = "001289ef81" "0a"
    "090603550406130246493110300e06035504080c075575";

/*
 * 8.13: "The length of the device certificate data is 695 bytes", while the
 * Total Length field of the same section's response is 0x02b8 = 696 and the
 * response's own data begins 30 82 02 b4, a DER SEQUENCE of 0x2b4 = 692
 * content octets, i.e. 696 octets in total.  The bytes agree with the field
 * and not with the prose, so 696 is used.  (The same section says the data is
 * the Section 8.11.2 certificate, which is 651 octets and begins 30 82 02 87;
 * that cross-reference does not hold either.)
 */
#define	SAMPLE_CERT_LEN		696
/* The 58 octets of certificate data the response carries, from 8.13.7. */
static const char SAMPLE_CERT_HEAD[] =
    "308202b43082025aa00302010202021000300a06082a8648ce3d0403023081a7"
    "310b300906035504061302464931" "10300e06035504080c075575";

/*
 * 8.11.3.1: the Certificate-Based Provisioning Base URI of the sample data,
 * "https://mesh.example.com/oob".  A real record carries the URI AD type
 * encoding of that string; the octets are opaque to the retrieval procedure
 * and are reported to the operator verbatim.
 */
static const char SAMPLE_BASE_URI[] = "https://mesh.example.com/oob";

/* 8.11.1 Device UUID used by all the certificate-based sample data. */
static const char SAMPLE_UUID_HEX[] = "b09dc847540840cc9c540fe8c87429e7";
static const char SAMPLE_UUID_CANON[] = "b09dc847-5408-40cc-9c54-0fe8c87429e7";

/* ================================================================
 * Small helpers.
 * ================================================================ */

static size_t
unhex(const char *hex, uint8_t *out, size_t max)
{
	size_t n = 0;
	unsigned v;

	while (*hex != '\0' && n < max) {
		if (*hex == ' ') {
			hex++;
			continue;
		}
		ATF_REQUIRE(sscanf(hex, "%2x", &v) == 1);
		out[n++] = (uint8_t)v;
		hex += 2;
	}
	return (n);
}

static void
hexdump(char *dst, size_t dstlen, const uint8_t *b, size_t n)
{
	size_t i, o = 0;

	for (i = 0; i < n && o + 3 < dstlen; i++)
		o += (size_t)snprintf(dst + o, dstlen - o, "%02x", b[i]);
	dst[o] = '\0';
}

#define	CHECK_BYTES(want_hex, got, gotlen) do {				\
	uint8_t _w[512];						\
	size_t _wn = unhex((want_hex), _w, sizeof(_w));			\
	char _gs[1100], _ws[1100];					\
	hexdump(_gs, sizeof(_gs), (got), (gotlen));			\
	hexdump(_ws, sizeof(_ws), _w, _wn);				\
	ATF_CHECK_MSG(_wn == (gotlen) && memcmp(_w, (got), _wn) == 0,	\
	    "want %s got %s", _ws, _gs);				\
} while (0)

/* ================================================================
 * Capture bearer.
 * ================================================================ */
#define	CAP_MAX		64
static struct capframe {
	uint8_t			buf[MESH_PBADV_PKT_MAX];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_cap[CAP_MAX];
static size_t g_ncap;

static int
cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	ATF_REQUIRE(len <= sizeof(g_cap[0].buf));
	if (g_ncap < CAP_MAX) {
		memcpy(g_cap[g_ncap].buf, pdu, len);
		g_cap[g_ncap].len = len;
		g_cap[g_ncap].cls = cls;
		g_ncap++;
	}
	return (0);
}

/* Bring up an UNPROVISIONED node with a Device UUID, on the capture bearer. */
static void
unprov_node(struct meshd_node *nd, struct meshd_config *cfg,
    struct meshd_bearer *bearer, const uint8_t uuid[16])
{

	meshd_config_defaults(cfg);
	memcpy(cfg->device_uuid, uuid, 16);
	cfg->have_uuid = 1;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
	bearer->tx = cap_tx;
	meshd_set_bearer(nd, bearer);
	g_ncap = 0;
}

/* Run one control verb, exactly as meshctl(8) would send it. */
static int
verb(struct meshd_node *nd, char *reply, size_t reply_max, int argc, ...)
{
	char *av[8];
	va_list ap;
	int i;

	ATF_REQUIRE(argc <= (int)nitems(av));
	va_start(ap, argc);
	for (i = 0; i < argc; i++)
		av[i] = va_arg(ap, char *);
	va_end(ap);
	reply[0] = '\0';
	return (meshd_ctl_exec_client(nd, NULL, argc, av, reply, reply_max));
}

/*
 * Install one provisioning record through the control verb, which is the only
 * way an operator has of doing it: the data is written to a file and the verb
 * is told to read it.
 */
static void
install_record(struct meshd_node *nd, uint16_t id, const uint8_t *data,
    size_t len)
{
	char path[64], idbuf[16], reply[MESHD_CTL_REPLY_MAX];
	FILE *f;

	(void)snprintf(path, sizeof(path), "record-%04x.bin", id);
	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(len, fwrite(data, 1, len, f));
	ATF_REQUIRE_EQ(0, fclose(f));
	(void)snprintf(idbuf, sizeof(idbuf), "0x%04x", id);
	ATF_REQUIRE_EQ_MSG(0, verb(nd, reply, sizeof(reply), 4,
	    "provision-records", "add", idbuf, path), "%s", reply);
}

/*
 * Feed one PB-ADV packet to the record service and return the packets it
 * emitted, in order.  This is the daemon entry point the advertising bearer
 * calls for AD type 0x29.
 */
static size_t
svc_rx(struct meshd_node *nd, const char *pkt_hex, uint64_t now)
{
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	size_t len;

	g_ncap = 0;
	len = unhex(pkt_hex, pkt, sizeof(pkt));
	(void)meshd_prov_records_recv(nd, pkt, len, now);
	return (g_ncap);
}

/* The PB-ADV Link Open a Provisioner sends to `uuid` on the sample Link ID. */
static void
svc_link_open(struct meshd_node *nd, const uint8_t uuid[16], uint64_t now)
{
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	size_t len;

	pkt[0] = (uint8_t)(SAMPLE_LINK_ID >> 24);
	pkt[1] = (uint8_t)(SAMPLE_LINK_ID >> 16);
	pkt[2] = (uint8_t)(SAMPLE_LINK_ID >> 8);
	pkt[3] = (uint8_t)SAMPLE_LINK_ID;
	pkt[4] = 0x00;			/* transaction number */
	pkt[5] = 0x03;			/* GPCF Control, opcode Link Open */
	memcpy(pkt + 6, uuid, 16);
	len = 22;
	g_ncap = 0;
	(void)meshd_prov_records_recv(nd, pkt, len, now);
	/* The device answers a Link Open with a Link Ack (Section 5.3.1.4.1). */
	ATF_REQUIRE_EQ(1, g_ncap);
	g_ncap = 0;
}

/*
 * Acknowledge the device's transaction, as a Provisioner does (Sections
 * 8.13.4 and 8.13.8): until this arrives the device is still awaiting the
 * acknowledgment of the PDU it sent, and "the Provisioner shall not send a new
 * PDU until it has received a [response] to the previously sent request"
 * (Section 5.4.2.6.1) means a well-behaved peer never overlaps them.
 */
static void
svc_txn_ack(struct meshd_node *nd, uint8_t txn, uint64_t now)
{
	uint8_t pkt[8];

	pkt[0] = (uint8_t)(SAMPLE_LINK_ID >> 24);
	pkt[1] = (uint8_t)(SAMPLE_LINK_ID >> 16);
	pkt[2] = (uint8_t)(SAMPLE_LINK_ID >> 8);
	pkt[3] = (uint8_t)SAMPLE_LINK_ID;
	pkt[4] = txn;
	pkt[5] = 0x01;			/* GPCF Transaction Acknowledgment */
	(void)meshd_prov_records_recv(nd, pkt, 6, now);
}

/*
 * The reassembled Provisioning PDU carried by the captured PB-ADV packets,
 * for the cases whose oracle is a field value rather than the exact octets.
 */
static size_t
svc_reassemble(uint8_t *out, size_t max)
{
	size_t i, n = 0;
	const uint8_t *p;

	for (i = 0; i < g_ncap; i++) {
		p = g_cap[i].buf;
		ATF_REQUIRE(g_cap[i].len >= 6);
		if ((p[5] & 0x03) == 0x01)	/* Transaction Ack */
			continue;
		if ((p[5] & 0x03) == 0x00) {	/* Transaction Start */
			n = 0;
			ATF_REQUIRE(g_cap[i].len > 9);
			ATF_REQUIRE(n + g_cap[i].len - 9 <= max);
			memcpy(out + n, p + 9, g_cap[i].len - 9);
			n += g_cap[i].len - 9;
		} else if ((p[5] & 0x03) == 0x02) {	/* Continuation */
			ATF_REQUIRE(n + g_cap[i].len - 6 <= max);
			memcpy(out + n, p + 6, g_cap[i].len - 6);
			n += g_cap[i].len - 6;
		}
	}
	return (n);
}

/* ================================================================
 * 5.4.2.6.1 Provisioning record list retrieval.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(records_get_list_sample);
ATF_TC_BODY(records_get_list_sample, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], cert[SAMPLE_CERT_LEN], inter[64];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);

	/*
	 * 8.13.3: "the device stores the Device Certificate record and one
	 * Intermediate Certificate record", and the Records List it answers
	 * with is "0d 0000 0001 0002".
	 */
	memset(cert, 0, sizeof(cert));
	memset(inter, 0x5a, sizeof(inter));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, cert, sizeof(cert));
	install_record(nd, MESH_PROV_RECORD_INTERMEDIATE1, inter,
	    sizeof(inter));

	svc_link_open(nd, uuid, 1000);
	/*
	 * Two packets: the Transaction Acknowledgment of 8.13.2, then the
	 * Provisioning Records List of 8.13.3.
	 */
	ATF_REQUIRE_EQ(2, svc_rx(nd, SAMPLE_RECORDS_GET, 1100));
	CHECK_BYTES(SAMPLE_TXN_ACK_GET, g_cap[0].buf, g_cap[0].len);
	CHECK_BYTES(SAMPLE_RECORDS_LIST, g_cap[1].buf, g_cap[1].len);
}

/* ================================================================
 * 5.4.2.6.2 Provisioning record data retrieval.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(record_request_response_sample);
ATF_TC_BODY(record_request_response_sample, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], cert[SAMPLE_CERT_LEN];
	size_t head;

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);

	/*
	 * The record is the 696-octet Device Certificate of Section 8.13, whose
	 * first 58 octets the section prints; the remainder is not printed and
	 * is never reached by this request, whose Fragment Maximum Size is
	 * 0x003a = 58.
	 */
	memset(cert, 0, sizeof(cert));
	head = unhex(SAMPLE_CERT_HEAD, cert, sizeof(cert));
	ATF_REQUIRE_EQ(58, head);
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, cert, sizeof(cert));

	svc_link_open(nd, uuid, 1000);
	/*
	 * Section 8.13 is one exchange: the Records Get and its List come
	 * first, so the device's Provisioning Record Response is its SECOND
	 * transaction and carries transaction number 0x81.
	 */
	ATF_REQUIRE_EQ(2, svc_rx(nd, SAMPLE_RECORDS_GET, 1100));
	svc_txn_ack(nd, 0x80, 1150);
	/*
	 * The Transaction Acknowledgment of 8.13.6, then the three PB-ADV
	 * segments of 8.13.7, exactly as the section prints them.
	 */
	ATF_REQUIRE_EQ(4, svc_rx(nd, SAMPLE_RECORD_REQ, 1200));
	CHECK_BYTES(SAMPLE_TXN_ACK_REQ, g_cap[0].buf, g_cap[0].len);
	CHECK_BYTES(SAMPLE_RSP_SEG0, g_cap[1].buf, g_cap[1].len);
	CHECK_BYTES(SAMPLE_RSP_SEG1, g_cap[2].buf, g_cap[2].len);
	CHECK_BYTES(SAMPLE_RSP_SEG2, g_cap[3].buf, g_cap[3].len);
}

/*
 * Table 5.50, first validation condition: "The record identified by the Record
 * ID field is present on the device"; when it is not, the status is Requested
 * Record Is Not Present, and Section 5.4.1.12 requires Total Length 0x0000 and
 * an empty Data field.
 */
ATF_TC_WITHOUT_HEAD(record_not_present);
ATF_TC_BODY(record_not_present, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], cert[64];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);
	memset(cert, 0x11, sizeof(cert));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, cert, sizeof(cert));

	svc_link_open(nd, uuid, 1000);
	/* Record 0x0011 (Complete Local Name) is not stored. */
	ATF_REQUIRE_EQ(2, svc_rx(nd,
	    "001289ef010000070c0a00110000003a", 1100));
	CHECK_BYTES("001289ef800000082e0b01001100000000", g_cap[1].buf,
	    g_cap[1].len);
}

/*
 * Table 5.50, second validation condition: "The Fragment Offset field value is
 * smaller than Total Length of the identified record".  When it is not, the
 * status is Requested Offset Is Out Of Bounds -- and Section 5.4.1.12 requires
 * the Total Length to be reported for that status, unlike the not-present one.
 */
ATF_TC_WITHOUT_HEAD(record_offset_out_of_bounds);
ATF_TC_BODY(record_offset_out_of_bounds, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], rec[64], pdu[MESH_PROV_BEARER_PDU_MAX];
	size_t n;

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);
	memset(rec, 0x22, sizeof(rec));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, rec, sizeof(rec));

	svc_link_open(nd, uuid, 1000);
	/* Offset 0x0040 == the 64-octet record length: not smaller. */
	ATF_REQUIRE(svc_rx(nd, "001289ef01000007ff0a00010040003a", 1100) >= 1);
	svc_txn_ack(nd, 0x80, 1150);
	n = svc_reassemble(pdu, sizeof(pdu));
	ATF_REQUIRE_EQ(8, n);
	ATF_CHECK_EQ(MESH_PROV_RECORD_RESPONSE, pdu[0]);
	ATF_CHECK_EQ(MESH_PROV_REC_OFFSET_OOB, pdu[1]);
	ATF_CHECK_EQ(0x0001, (pdu[2] << 8) | pdu[3]);
	ATF_CHECK_EQ(0x0040, (pdu[4] << 8) | pdu[5]);
	ATF_CHECK_EQ(64, (pdu[6] << 8) | pdu[7]);

	/* One octet earlier the condition holds and a fragment comes back. */
	ATF_REQUIRE(svc_rx(nd, "001289ef02000007fd0a0001003f003a", 1200) >= 1);
	n = svc_reassemble(pdu, sizeof(pdu));
	ATF_REQUIRE_EQ(9, n);
	ATF_CHECK_EQ(MESH_PROV_REC_SUCCESS, pdu[1]);
	ATF_CHECK_EQ(0x22, pdu[8]);
}

/*
 * Tables 5.49 and 5.51: a Provisioning Records Get or Provisioning Record
 * Request "received after a Provisioning Invite PDU was received in the same
 * provisioning session" is answered with a Provisioning Failed PDU carrying
 * Unexpected PDU.  The Invite itself gets Out of Resources: this daemon serves
 * records but has no Provisionee role to conduct the session with.
 */
ATF_TC_WITHOUT_HEAD(records_after_invite_unexpected_pdu);
ATF_TC_BODY(records_after_invite_unexpected_pdu, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], rec[32], pdu[MESH_PROV_BEARER_PDU_MAX];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);
	memset(rec, 0x33, sizeof(rec));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, rec, sizeof(rec));
	svc_link_open(nd, uuid, 1000);

	/* Before the Invite, a Records Get is answered normally. */
	ATF_REQUIRE(svc_rx(nd, SAMPLE_RECORDS_GET, 1100) >= 1);
	ATF_REQUIRE_EQ(5, svc_reassemble(pdu, sizeof(pdu)));
	ATF_CHECK_EQ(MESH_PROV_RECORDS_LIST, pdu[0]);
	svc_txn_ack(nd, 0x80, 1150);

	/* Provisioning Invite, Attention Duration 0x00 (Section 5.4.1.1). */
	ATF_REQUIRE(svc_rx(nd, "001289ef01000002140000", 1200) >= 1);
	ATF_REQUIRE_EQ(2, svc_reassemble(pdu, sizeof(pdu)));
	ATF_CHECK_EQ(MESH_PROV_FAILED, pdu[0]);
	ATF_CHECK_EQ(MESH_PROV_ERR_OUT_OF_RESOURCES, pdu[1]);
	svc_txn_ack(nd, 0x81, 1250);

	/* Now the same Records Get is an Unexpected PDU. */
	ATF_REQUIRE(svc_rx(nd, "001289ef02000001390c", 1300) >= 1);
	ATF_REQUIRE_EQ(2, svc_reassemble(pdu, sizeof(pdu)));
	ATF_CHECK_EQ(MESH_PROV_FAILED, pdu[0]);
	ATF_CHECK_EQ(MESH_PROV_ERR_UNEXPECTED_PDU, pdu[1]);
	svc_txn_ack(nd, 0x82, 1350);

	/* And so is a Record Request. */
	ATF_REQUIRE(svc_rx(nd, "001289ef03000007940a00010000003a", 1400) >= 1);
	ATF_REQUIRE_EQ(2, svc_reassemble(pdu, sizeof(pdu)));
	ATF_CHECK_EQ(MESH_PROV_FAILED, pdu[0]);
	ATF_CHECK_EQ(MESH_PROV_ERR_UNEXPECTED_PDU, pdu[1]);
}

/*
 * Section 5.4.1.11: "A value of 0x0000 is Prohibited" for Fragment Maximum
 * Size, and Section 5.4.4 makes a Prohibited field value an error in the
 * provisioning protocol for the Provisionee that receives it.  Table 5.41's
 * Invalid Format covers "the arguments of the protocol PDUs are outside
 * expected values".
 */
ATF_TC_WITHOUT_HEAD(record_request_prohibited_frag_max);
ATF_TC_BODY(record_request_prohibited_frag_max, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], rec[32], pdu[MESH_PROV_BEARER_PDU_MAX];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);
	memset(rec, 0x44, sizeof(rec));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, rec, sizeof(rec));
	svc_link_open(nd, uuid, 1000);

	ATF_REQUIRE(svc_rx(nd, "001289ef010000075d0a000100000000",
	    1100) >= 1);
	ATF_REQUIRE_EQ(2, svc_reassemble(pdu, sizeof(pdu)));
	ATF_CHECK_EQ(MESH_PROV_FAILED, pdu[0]);
	ATF_CHECK_EQ(MESH_PROV_ERR_INVALID_FORMAT, pdu[1]);
}

/*
 * Section 3.10.2, Table 3.79: "If a device supports provisioning records ...
 * it shall set bit 8 of the OOB Information field of the Unprovisioned Device
 * beacon"; and a device with a Device Certificate available for retrieval
 * "shall set bit 7 ... and shall set bit 8".
 */
ATF_TC_WITHOUT_HEAD(unprov_beacon_oob_bits);
ATF_TC_BODY(unprov_beacon_oob_bits, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], rec[16];
	char reply[MESHD_CTL_REPLY_MAX];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);

	/* No records: neither bit, as before this feature existed. */
	g_ncap = 0;
	ATF_REQUIRE_EQ(1, meshd_unprov_beacon_emit(nd));
	ATF_REQUIRE_EQ(1, g_ncap);
	ATF_REQUIRE_EQ(19, g_cap[0].len);	/* Type + UUID + OOB */
	ATF_CHECK_EQ(0x0000, (g_cap[0].buf[17] << 8) | g_cap[0].buf[18]);

	/* A non-certificate record: records supported, bit 8 only. */
	memset(rec, 0x66, sizeof(rec));
	install_record(nd, MESH_PROV_RECORD_LOCAL_NAME, rec, sizeof(rec));
	g_ncap = 0;
	ATF_REQUIRE_EQ(1, meshd_unprov_beacon_emit(nd));
	ATF_CHECK_EQ(0x0100, (g_cap[0].buf[17] << 8) | g_cap[0].buf[18]);

	/* A Device Certificate record: certificate-based provisioning too. */
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, rec, sizeof(rec));
	g_ncap = 0;
	ATF_REQUIRE_EQ(1, meshd_unprov_beacon_emit(nd));
	ATF_CHECK_EQ(0x0180, (g_cap[0].buf[17] << 8) | g_cap[0].buf[18]);

	/* Clearing the store takes both bits away again. */
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 2,
	    "provision-records", "clear"));
	g_ncap = 0;
	ATF_REQUIRE_EQ(1, meshd_unprov_beacon_emit(nd));
	ATF_CHECK_EQ(0x0000, (g_cap[0].buf[17] << 8) | g_cap[0].buf[18]);
}

/* The operator surface for the served records. */
ATF_TC_WITHOUT_HEAD(records_verbs);
ATF_TC_BODY(records_verbs, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	uint8_t uuid[16], rec[40];
	char reply[MESHD_CTL_REPLY_MAX];

	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));
	unprov_node(nd, &cfg, &bearer, uuid);

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1,
	    "provision-records"));
	ATF_CHECK_MSG(strstr(reply, "n=0") != NULL, "%s", reply);

	memset(rec, 0x77, sizeof(rec));
	install_record(nd, MESH_PROV_RECORD_DEVICE_CERT, rec, sizeof(rec));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 2,
	    "provision-records", "list"));
	ATF_CHECK_MSG(strstr(reply, "n=1") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "0001=40") != NULL, "%s", reply);

	/* A Record ID outside Table 5.52 is refused. */
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 4, "provision-records",
	    "add", "0x0013", "/nonexistent"));
	/* As is an unreadable file, and a bad sub-verb. */
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 4, "provision-records",
	    "add", "0x0001", "/nonexistent/record.der"));
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 2, "provision-records",
	    "bogus"));

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 2,
	    "provision-records", "clear"));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1,
	    "provision-records"));
	ATF_CHECK_MSG(strstr(reply, "n=0") != NULL, "%s", reply);
}

/* ================================================================
 * A two-certificate PKI, built here because the specification's sample
 * Device Certificate (Section 8.11.2) comes without the CA that signed it and
 * expired in March 2024, so nothing can be validated against it.
 * ================================================================ */

static EVP_PKEY *
pki_keygen(void)
{
	EVP_PKEY *k;

	k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	ATF_REQUIRE(k != NULL);
	return (k);
}

/* The 32-octet private scalar, for handing to mesh_prov_device_init(). */
static void
pki_priv32(EVP_PKEY *k, uint8_t out[32])
{
	BIGNUM *bn = NULL;

	ATF_REQUIRE_EQ(1, EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PRIV_KEY,
	    &bn));
	ATF_REQUIRE_EQ(32, BN_bn2binpad(bn, out, 32));
	BN_free(bn);
}

static void
pki_add_ext(X509 *x, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509_EXTENSION *ex;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	ATF_REQUIRE_MSG(ex != NULL, "extension nid %d value %s", nid, value);
	ATF_REQUIRE_EQ(1, X509_add_ext(x, ex, -1));
	X509_EXTENSION_free(ex);
}

/*
 * Build one certificate.  `ku` is the key usage string ("keyAgreement" for a
 * Device Certificate per Section 5.5.1.1.4.12), `bc` the basic constraints
 * ("CA:FALSE" per Section 5.5.1.1.4.18).  issuer_cert / issuer_key NULL makes
 * it self-signed, which is how the root is built -- and, per Section 5.4.2.6.5,
 * is exactly what a Provisionee must never serve.
 */
static X509 *
pki_cert(EVP_PKEY *subject_pub, const char *cn, X509 *issuer_cert,
    EVP_PKEY *issuer_key, const char *bc, const char *ku, int policies,
    long not_before, long not_after)
{
	X509 *x;
	X509_NAME *name;

	x = X509_new();
	ATF_REQUIRE(x != NULL);
	ATF_REQUIRE_EQ(1, X509_set_version(x, 2));	/* v3 (5.5.1.1.4.1) */
	ATF_REQUIRE_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(x), 4096));
	ATF_REQUIRE(X509_gmtime_adj(X509_getm_notBefore(x), not_before) != NULL);
	ATF_REQUIRE(X509_gmtime_adj(X509_getm_notAfter(x), not_after) != NULL);
	ATF_REQUIRE_EQ(1, X509_set_pubkey(x, subject_pub));

	name = X509_get_subject_name(x);
	ATF_REQUIRE_EQ(1, X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
	    (const unsigned char *)"FI", -1, -1, 0));
	ATF_REQUIRE_EQ(1, X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
	    (const unsigned char *)"Example Company", -1, -1, 0));
	ATF_REQUIRE_EQ(1, X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	    (const unsigned char *)cn, -1, -1, 0));
	ATF_REQUIRE_EQ(1, X509_set_issuer_name(x, issuer_cert != NULL ?
	    X509_get_subject_name(issuer_cert) : name));

	pki_add_ext(x, issuer_cert, NID_basic_constraints, bc);
	pki_add_ext(x, issuer_cert, NID_key_usage, ku);
	pki_add_ext(x, issuer_cert, NID_subject_key_identifier, "hash");
	if (issuer_cert != NULL)
		pki_add_ext(x, issuer_cert, NID_authority_key_identifier,
		    "keyid:always");
	if (policies) {
		/*
		 * The certificate policies extension of Section 5.5.1.1.4.13,
		 * marked critical as that section requires.  Built here rather
		 * than through the X509V3 configuration syntax, which needs a
		 * configuration database to resolve a policy section.  The OID
		 * is the NIST test policy the Section 8.11.2 sample uses.
		 */
		CERTIFICATEPOLICIES *pols;
		POLICYINFO *pi;

		pols = sk_POLICYINFO_new_null();
		ATF_REQUIRE(pols != NULL);
		pi = POLICYINFO_new();
		ATF_REQUIRE(pi != NULL);
		pi->policyid = OBJ_txt2obj("2.16.840.1.101.3.2.1.48.1", 1);
		ATF_REQUIRE(pi->policyid != NULL);
		ATF_REQUIRE(sk_POLICYINFO_push(pols, pi) > 0);
		ATF_REQUIRE_EQ(1, X509_add1_ext_i2d(x,
		    NID_certificate_policies, pols, 1, 0));
		CERTIFICATEPOLICIES_free(pols);
	}
	ATF_REQUIRE(X509_sign(x, issuer_key != NULL ? issuer_key : subject_pub,
	    EVP_sha256()) > 0);
	return (x);
}

static void
pki_write_pem(const char *path, X509 *x)
{
	FILE *f;

	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(1, PEM_write_X509(f, x));
	ATF_REQUIRE_EQ(0, fclose(f));
}

static size_t
pki_der(X509 *x, uint8_t *out, size_t max)
{
	unsigned char *p = NULL;
	int n;

	n = i2d_X509(x, &p);
	ATF_REQUIRE(n > 0 && (size_t)n <= max);
	memcpy(out, p, (size_t)n);
	OPENSSL_free(p);
	return ((size_t)n);
}

/* The Common Name of Section 5.5.1.1.4.6: UUID, then BCID: and BPID:. */
static void
pki_cn(char *out, size_t max, const char *uuid_canon)
{

	(void)snprintf(out, max, "%s BCID:8001 BPID:03ff", uuid_canon);
}

/* ================================================================
 * A simulated Provisionee: a PB-ADV device link, a record responder whose
 * PDUs are encoded here rather than by the code under test, and a libmesh
 * device session for the provisioning protocol proper.
 * ================================================================ */

#define	SIM_MAXREC	4

struct simdev {
	struct mesh_prov_link		link;
	struct mesh_prov_session	sess;
	int				sess_live;
	uint8_t				uuid[16];
	uint8_t				priv[32];
	int				have_priv;
	struct mesh_prov_caps		caps;
	struct {
		uint16_t	id;
		const uint8_t  *data;
		size_t		len;
	}				rec[SIM_MAXREC];
	size_t				nrec;
	uint16_t			list_extensions;
	int				misanswer;	/* wrong Record ID */
	/* Observations. */
	uint8_t				start[5];
	int				have_start;
	int				sent_pubkey;
	int				got_failed;
	uint8_t				failed_code;
	size_t				requests;	/* Record Requests seen */
};

static void
sim_add_record(struct simdev *sd, uint16_t id, const uint8_t *data, size_t len)
{

	ATF_REQUIRE(sd->nrec < SIM_MAXREC);
	sd->rec[sd->nrec].id = id;
	sd->rec[sd->nrec].data = data;
	sd->rec[sd->nrec].len = len;
	sd->nrec++;
}

static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
get16(const uint8_t *p)
{

	return ((uint16_t)((uint16_t)p[0] << 8 | p[1]));
}

/*
 * Encode this device's Provisioning Records List (Section 5.4.1.14) and
 * Provisioning Record Response (Section 5.4.1.12) by hand, so the Provisioner's
 * decoder is being read by an encoder it does not share any code with.
 */
static size_t
sim_records_list(struct simdev *sd, uint8_t *out)
{
	size_t i;

	out[0] = MESH_PROV_RECORDS_LIST;
	put16(out + 1, sd->list_extensions);
	for (i = 0; i < sd->nrec; i++)
		put16(out + 3 + 2 * i, sd->rec[i].id);
	return (3 + 2 * sd->nrec);
}

static size_t
sim_record_response(struct simdev *sd, const uint8_t *req, uint8_t *out)
{
	uint16_t id, off, max;
	size_t i, frag;

	sd->requests++;
	id = get16(req + 1);
	off = get16(req + 3);
	max = get16(req + 5);
	out[0] = MESH_PROV_RECORD_RESPONSE;
	put16(out + 2, sd->misanswer ? (uint16_t)(id ^ 0x0010) : id);
	put16(out + 4, off);
	for (i = 0; i < sd->nrec; i++)
		if (sd->rec[i].id == id)
			break;
	if (i == sd->nrec) {
		out[1] = MESH_PROV_REC_NOT_PRESENT;
		put16(out + 6, 0);
		return (8);
	}
	put16(out + 6, (uint16_t)sd->rec[i].len);
	if (off >= sd->rec[i].len) {
		out[1] = MESH_PROV_REC_OFFSET_OOB;
		return (8);
	}
	out[1] = MESH_PROV_REC_SUCCESS;
	frag = sd->rec[i].len - off;
	if (frag > max)
		frag = max;
	memcpy(out + 8, sd->rec[i].data + off, frag);
	return (8 + frag);
}

/* One Provisioning PDU has arrived at the device.  Answer it. */
static void
sim_recv_pdu(struct simdev *sd, const uint8_t *pdu, size_t len, uint64_t now)
{
	uint8_t out[MESH_PROV_BEARER_PDU_MAX];
	size_t outlen = 0;

	switch (pdu[0] & 0x3f) {
	case MESH_PROV_RECORDS_GET:
		outlen = sim_records_list(sd, out);
		break;
	case MESH_PROV_RECORD_REQUEST:
		outlen = sim_record_response(sd, pdu, out);
		break;
	case MESH_PROV_FAILED:
		sd->got_failed = 1;
		sd->failed_code = pdu[1];
		return;
	default:
		if (!sd->sess_live) {
			ATF_REQUIRE_EQ(0, mesh_prov_device_init(&sd->sess,
			    sd->have_priv ? sd->priv : NULL, NULL, &sd->caps));
			sd->sess_live = 1;
		}
		if ((pdu[0] & 0x3f) == MESH_PROV_START && len == 6) {
			memcpy(sd->start, pdu + 1, 5);
			sd->have_start = 1;
		}
		(void)mesh_prov_session_recv(&sd->sess, pdu, len);
		return;
	}
	ATF_REQUIRE(mesh_prov_link_idle(&sd->link));
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&sd->link, out, outlen, now));
}

/*
 * Pump the Provisioner (the daemon) and the simulated device against each
 * other until both are quiescent or one of them has failed.  Returns the
 * number of iterations spent, so a caller can assert progress was made.
 */
static int
sim_pump(struct meshd_node *nd, struct simdev *sd, uint64_t now)
{
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	uint8_t pdu[MESH_PROV_BEARER_PDU_MAX], spdu[MESH_PROV_BEARER_PDU_MAX];
	size_t len, alen, plen, slen;
	int i, have_pdu, have_ack, ack_pending = 0;

	for (i = 0; i < 600; i++) {
		if (meshd_provisioner_poll(nd, now, pkt, &len) == 1) {
			have_pdu = have_ack = 0;
			ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&sd->link, pkt,
			    len, now, pdu, &plen, &have_pdu, ack, &alen,
			    &have_ack));
			if (have_ack)
				ack_pending = 1;
			if (have_pdu)
				sim_recv_pdu(sd, pdu, plen, now);
			continue;
		}
		if (ack_pending) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, ack, alen,
			    now));
			ack_pending = 0;
			continue;
		}
		if (mesh_prov_link_poll(&sd->link, now, pkt, &len) == 1) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, pkt, len,
			    now));
			continue;
		}
		if (sd->sess_live && mesh_prov_link_idle(&sd->link) &&
		    mesh_prov_session_poll(&sd->sess, spdu, &slen) == 1) {
			if ((spdu[0] & 0x3f) == MESH_PROV_PUBLIC_KEY)
				sd->sent_pubkey = 1;
			ATF_REQUIRE_EQ(0, mesh_prov_link_send(&sd->link, spdu,
			    slen, now));
			continue;
		}
		break;
	}
	return (i);
}

/* ================================================================
 * 5.5 Certificate-based provisioning, Provisioner side.
 * ================================================================ */

/* Bring up a PROVISIONED node that can act as a Provisioner. */
static void
prov_node(struct meshd_node *nd, struct meshd_config *cfg,
    struct meshd_bearer *bearer)
{

	meshd_config_defaults(cfg);
	memset(cfg->netkey, 0x11, sizeof(cfg->netkey));
	cfg->have_netkey = 1;
	memset(cfg->appkey, 0x22, sizeof(cfg->appkey));
	cfg->have_appkey = 1;
	cfg->unicast_addr = 0x0001;
	cfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
	bearer->tx = cap_tx;
	meshd_set_bearer(nd, bearer);
	g_ncap = 0;
}

struct certcase {
	/* Certificate shape. */
	const char	*cn_uuid;	/* UUID text in the Common Name */
	const char	*bc;		/* leaf basicConstraints */
	const char	*ku;		/* leaf keyUsage */
	int		policies;	/* leaf certificate policies extension */
	int		expired;	/* leaf validity already over */
	/* What the device serves and advertises. */
	int		serve_root;	/* serve the root as Intermediate 1 */
	int		no_cert_record;	/* serve no Device Certificate at all */
	int		serve_base_uri;	/* serve a Base URI record as well */
	int		pubkey_oob_bit;	/* Capabilities Public Key Type bit 0 */
	size_t		pad_cert;	/* pad the record to force fragments */
	/* Provisioner configuration. */
	int		wrong_root;	/* trust a DIFFERENT CA */
	int		misanswer;	/* device answers with a wrong Record ID */
	const char	*mode;		/* "on" or "require" */
	const char	*cid_pid[2];	/* required CID/PID, or NULLs */
	/* Results. */
	int		provisioned;
	int		iterations;
	char		status[MESHD_CTL_REPLY_MAX];
	struct simdev	sd;
	uint8_t		leaf[4096];
	uint8_t		root[2048];
	size_t		leaf_len;
	size_t		root_len;
};

static void
cert_run(struct meshd_node *nd, struct certcase *c)
{
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	struct mesh_prov_data pdata;
	EVP_PKEY *cak, *devk, *otherk;
	X509 *ca, *other, *leaf;
	uint8_t pkt[MESH_PBADV_PKT_MAX], raw[25];
	uint8_t pdu[MESH_PROV_BEARER_PDU_MAX], ack[MESH_PBADV_PKT_MAX];
	char cn[128], reply[MESHD_CTL_REPLY_MAX];
	size_t len, plen, alen;
	int have_pdu, have_ack;
	long from, to;

	/* The PKI. */
	cak = pki_keygen();
	devk = pki_keygen();
	ca = pki_cert(cak, "Example CA", NULL, NULL, "critical,CA:TRUE",
	    "critical,keyCertSign,cRLSign", 0, -3600, 86400);
	pki_cn(cn, sizeof(cn), c->cn_uuid);
	from = c->expired ? -86400 * 30 : -3600;
	to = c->expired ? -86400 * 2 : 86400;
	leaf = pki_cert(devk, cn, ca, cak, c->bc, c->ku, c->policies, from, to);
	c->leaf_len = pki_der(leaf, c->leaf, sizeof(c->leaf));
	c->root_len = pki_der(ca, c->root, sizeof(c->root));
	if (c->pad_cert != 0) {
		/*
		 * DER is self-delimiting, so trailing octets would make the
		 * record un-decodable; the padding therefore goes nowhere near
		 * a certificate case.  It is only used to force the retrieval
		 * to span several fragments, on a record that is not parsed.
		 */
		ATF_REQUIRE(c->leaf_len + c->pad_cert <= sizeof(c->leaf));
		memset(c->leaf + c->leaf_len, 0xa5, c->pad_cert);
		c->leaf_len += c->pad_cert;
	}
	if (c->wrong_root) {
		otherk = pki_keygen();
		other = pki_cert(otherk, "Other CA", NULL, NULL,
		    "critical,CA:TRUE", "critical,keyCertSign,cRLSign", 0,
		    -3600, 86400);
		pki_write_pem("roots.pem", other);
		X509_free(other);
		EVP_PKEY_free(otherk);
	} else
		pki_write_pem("roots.pem", ca);

	/* The device. */
	memset(&c->sd, 0, sizeof(c->sd));
	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, c->sd.uuid,
	    sizeof(c->sd.uuid)));
	pki_priv32(devk, c->sd.priv);
	c->sd.have_priv = 1;
	c->sd.caps.num_elements = 1;
	c->sd.caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC |
	    MESH_PROV_ALGO_BIT_P256_HMAC;
	c->sd.caps.public_key_type = c->pubkey_oob_bit ? 0x01 : 0x00;
	c->sd.misanswer = c->misanswer;
	if (!c->no_cert_record)
		sim_add_record(&c->sd, MESH_PROV_RECORD_DEVICE_CERT, c->leaf,
		    c->leaf_len);
	if (c->serve_base_uri)
		sim_add_record(&c->sd, MESH_PROV_RECORD_BASE_URI,
		    (const uint8_t *)SAMPLE_BASE_URI,
		    strlen(SAMPLE_BASE_URI));
	if (c->serve_root)
		sim_add_record(&c->sd, MESH_PROV_RECORD_INTERMEDIATE1, c->root,
		    c->root_len);
	mesh_prov_link_init_device(&c->sd.link, c->sd.uuid, 100000, 3);

	/* The Provisioner. */
	prov_node(nd, &cfg, &bearer);
	ATF_REQUIRE_EQ_MSG(0, verb(nd, reply, sizeof(reply), 3,
	    "provision-cert", (char *)(uintptr_t)c->mode, "roots.pem"), "%s",
	    reply);
	if (c->cid_pid[0] != NULL)
		ATF_REQUIRE_EQ_MSG(0, verb(nd, reply, sizeof(reply), 4,
		    "provision-cert", "cid-pid", (char *)(uintptr_t)c->cid_pid[0],
		    (char *)(uintptr_t)c->cid_pid[1]), "%s", reply);

	ATF_REQUIRE_EQ(25, unhex(
	    "efb2255e6422d330088e09bb015ed707056700010203040b0c", raw,
	    sizeof(raw)));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	ATF_REQUIRE_EQ(0, meshd_provisioner_begin(nd, c->sd.uuid, 0x11223344,
	    NULL, NULL, 0x00, &pdata, 100000, 3, 1000, pkt, &len));
	have_pdu = have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&c->sd.link, pkt, len, 1000, pdu,
	    &plen, &have_pdu, ack, &alen, &have_ack));
	ATF_REQUIRE(have_ack);
	ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, ack, alen, 1000));

	c->iterations = sim_pump(nd, &c->sd, 1000);
	c->provisioned = meshd_provisioner_done(nd) &&
	    c->sd.sess_live && mesh_prov_session_done(&c->sd.sess);
	ATF_REQUIRE_EQ(0, verb(nd, c->status, sizeof(c->status), 1,
	    "provision-cert"));

	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(devk);
	EVP_PKEY_free(cak);
}

/* A well-formed Device Certificate case, with everything the spec asks for. */
static void
cert_case_defaults(struct certcase *c)
{

	memset(c, 0, sizeof(*c));
	c->cn_uuid = SAMPLE_UUID_CANON;
	c->bc = "CA:FALSE";
	c->ku = "keyAgreement";
	c->policies = 1;
	c->pubkey_oob_bit = 1;
	c->mode = "require";
}

/*
 * The whole procedure end to end.  Section 5.4.2.3: "a Provisionee's public
 * key that is contained in a Device Certificate ... and retrievable from the
 * device over an established provisioning bearer ... is considered to be
 * available using an OOB technology", in which case "the Provisioner sets the
 * Public Key field in the Provisioning Start PDU to 1 ... and the public key
 * read from the device using the appropriate OOB technology shall be used",
 * while "the Provisionee shall send its generated public key IF the Public Key
 * field ... is set to zero".
 */
ATF_TC_WITHOUT_HEAD(cert_oob_public_key_end_to_end);
ATF_TC_BODY(cert_oob_public_key_end_to_end, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=ok") != NULL, "%s", c->status);
	ATF_CHECK_MSG(strstr(c->status, SAMPLE_UUID_CANON) != NULL, "%s",
	    c->status);
	ATF_REQUIRE(c->sd.have_start);
	/* Provisioning Start: Public Key field (octet 1) is 0x01. */
	ATF_CHECK_EQ(0x01, c->sd.start[1]);
	/* And the device never put its public key on the air. */
	ATF_CHECK_EQ(0, c->sd.sent_pubkey);
	ATF_CHECK_MSG(c->provisioned, "provisioning did not complete (%d "
	    "iterations, failed=%d code=0x%02x)", c->iterations,
	    c->sd.got_failed, c->sd.failed_code);
}

/*
 * The same, with a record big enough that Section 5.4.2.6.2's "the Provisioner
 * may issue Provisioning Record Request PDUs multiple times in order to
 * retrieve all fragments needed to reconstruct provisioning record data" is
 * actually exercised, and with the Common Name CID/PID pinned by the operator.
 */
ATF_TC_WITHOUT_HEAD(cert_multi_fragment_retrieval);
ATF_TC_BODY(cert_multi_fragment_retrieval, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->cid_pid[0] = "0x8001";
	c->cid_pid[1] = "0x03ff";
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=ok") != NULL, "%s", c->status);
	ATF_CHECK_MSG(c->provisioned, "provisioning did not complete");
	/* A ~500-octet certificate cannot fit one 173-octet fragment. */
	ATF_CHECK_MSG(c->sd.requests >= 3, "%zu record requests",
	    c->sd.requests);
}

/*
 * Section 5.5.1.1.4.6: "Before using the OOB Public Key in the certificate
 * when provisioning the device, the Provisioner shall check that the Device
 * UUID in the Common Name field of the DN matches the UUID of the device being
 * provisioned."  A certificate for another device is a valid certificate; it
 * is simply not this device's, and the key in it must not be used.
 */
ATF_TC_WITHOUT_HEAD(cert_uuid_mismatch_refused);
ATF_TC_BODY(cert_uuid_mismatch_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->cn_uuid = "00112233-4455-6677-8899-aabbccddeeff";
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=uuid-mismatch") != NULL, "%s",
	    c->status);
	ATF_CHECK(!c->provisioned);
	/* The exchange never reached Provisioning Start. */
	ATF_CHECK(!c->sd.have_start);
}

/*
 * Fail closed.  Section 5.5.1 requires RFC 5280 certification path validation
 * "before using the contained OOB Public Key"; a certificate that chains to no
 * configured trust anchor has not been validated, and its key is whatever the
 * peer chose to send.
 */
ATF_TC_WITHOUT_HEAD(cert_unknown_root_refused);
ATF_TC_BODY(cert_unknown_root_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->wrong_root = 1;
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=path-validation-failed") != NULL,
	    "%s", c->status);
	ATF_CHECK(!c->provisioned);
	ATF_CHECK(!c->sd.have_start);
}

/* An expired certificate fails the same path validation (RFC 5280 §6.1.3). */
ATF_TC_WITHOUT_HEAD(cert_expired_refused);
ATF_TC_BODY(cert_expired_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->expired = 1;
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=path-validation-failed") != NULL,
	    "%s", c->status);
	ATF_CHECK_MSG(strstr(c->status, "expired") != NULL, "%s", c->status);
	ATF_CHECK(!c->provisioned);
}

/*
 * Section 5.5.1.1.4.12: "A key usage extension shall be present.  The
 * keyAgreement bit ... shall be set ... No other bits shall be set."  A
 * certificate whose key is not a key-agreement key is not a Device
 * Certificate, however well it validates.
 */
ATF_TC_WITHOUT_HEAD(cert_profile_key_usage_refused);
ATF_TC_BODY(cert_profile_key_usage_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->ku = "digitalSignature,keyAgreement";
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=profile-violation") != NULL,
	    "%s", c->status);
	ATF_CHECK_MSG(strstr(c->status, "keyAgreement alone") != NULL, "%s",
	    c->status);
	ATF_CHECK(!c->provisioned);
}

/*
 * Section 5.5.1.1.4.18: "The basic constraints extension shall be present.
 * The cA field value shall be present ... and shall be set to FALSE."
 */
ATF_TC_WITHOUT_HEAD(cert_profile_ca_true_refused);
ATF_TC_BODY(cert_profile_ca_true_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->bc = "critical,CA:TRUE";
	c->ku = "keyAgreement,keyCertSign";
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=") != NULL, "%s", c->status);
	ATF_CHECK_MSG(strstr(c->status, "last=ok") == NULL, "%s", c->status);
	ATF_CHECK(!c->provisioned);
}

/*
 * Section 5.4.2.6.5: "Root certificates shall not be stored on the
 * Provisionee.  If the Provisionee responds to a Provisioning Record Request
 * with root certificate data, the Provisioner shall treat that as a
 * provisioning error."
 */
ATF_TC_WITHOUT_HEAD(cert_root_in_chain_refused);
ATF_TC_BODY(cert_root_in_chain_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->serve_root = 1;
	cert_run(nd, c);

	ATF_CHECK_MSG(strstr(c->status, "last=root-in-chain") != NULL, "%s",
	    c->status);
	ATF_CHECK(!c->provisioned);
}

/*
 * The anti-downgrade rule.  The certificate validates, so its key is this
 * device's OOB Public Key -- but the device's Capabilities do not advertise
 * Public Key OOB information (Table 5.22 bit 0), so it will not accept the
 * OOB path.  Section 5.4.2.3: "If the Provisioner has requirements that the
 * Provisionee does not meet, then the Provisioner shall determine it cannot
 * provision the Provisionee, the provisioning protocol shall fail".  Falling
 * back to the over-the-air key exchange would provision the device with the
 * unauthenticated exchange the certificate exists to replace.
 */
ATF_TC_WITHOUT_HEAD(cert_no_downgrade_without_peer_oob_bit);
ATF_TC_BODY(cert_no_downgrade_without_peer_oob_bit, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->pubkey_oob_bit = 0;
	cert_run(nd, c);

	/* The certificate itself was fine ... */
	ATF_CHECK_MSG(strstr(c->status, "last=ok") != NULL, "%s", c->status);
	/* ... and the exchange still failed rather than downgrading. */
	ATF_CHECK(!c->provisioned);
	ATF_CHECK_EQ(0, c->sd.sent_pubkey);
	ATF_CHECK_MSG(c->sd.got_failed, "no Provisioning Failed PDU");
	ATF_CHECK_EQ(MESH_PROV_ERR_INVALID_PDU, c->sd.failed_code);
}

/*
 * A device with no Device Certificate record.  With "require" the attempt is
 * refused (Section 5.4.2.3 lets the Provisioner require OOB Public Key
 * retrieval); with "on" it is a device that simply has no certificate, and
 * provisioning proceeds by the ordinary path with the verdict recorded.
 */
ATF_TC_WITHOUT_HEAD(cert_absent_require_versus_try);
ATF_TC_BODY(cert_absent_require_versus_try, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->no_cert_record = 1;
	cert_run(nd, c);
	ATF_CHECK_MSG(strstr(c->status, "last=no-device-certificate") != NULL,
	    "%s", c->status);
	ATF_CHECK_MSG(!c->provisioned, "require provisioned a device with no "
	    "certificate");
	ATF_CHECK(!c->sd.have_start);

	memset(nd, 0, sizeof(*nd));
	cert_case_defaults(c);
	c->no_cert_record = 1;
	c->serve_base_uri = 1;
	c->mode = "on";
	cert_run(nd, c);
	ATF_CHECK_MSG(strstr(c->status, "last=no-device-certificate") != NULL,
	    "%s", c->status);
	/*
	 * Section 5.4.2.6.4: a device whose certificate lives on a server
	 * publishes the Base URI instead.  Retrieving the certificate from
	 * there (Section 5.6) is not implemented, so the URI is retrieved and
	 * reported and the device counts as having no certificate.
	 */
	ATF_CHECK_MSG(strstr(c->status, SAMPLE_BASE_URI) != NULL, "%s",
	    c->status);
	ATF_CHECK_MSG(c->provisioned, "a device with no certificate could not "
	    "be provisioned in try mode");
	ATF_REQUIRE(c->sd.have_start);
	/* No OOB Public Key: the ordinary exchange, and the device's key. */
	ATF_CHECK_EQ(0x00, c->sd.start[1]);
	ATF_CHECK_EQ(1, c->sd.sent_pubkey);
}

/* The operator surface, and its fail-closed configuration rules. */
/*
 * Section 5.4.1.12: "The value of the Record ID field of the Provisioning
 * Record Response PDU shall be set to the value of the Record ID field of the
 * corresponding Provisioning Record Request PDU", and the same for the
 * Fragment Offset.  A Response that does not match is not the answer to the
 * Request in flight, and its data must not be assembled into the record: doing
 * so would let a peer (or an interleaved reply) decide which octets end up in
 * the certificate whose key is about to be trusted.
 */
ATF_TC_WITHOUT_HEAD(cert_response_mismatch_refused);
ATF_TC_BODY(cert_response_mismatch_refused, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct certcase, c);

	cert_case_defaults(c);
	c->misanswer = 1;
	cert_run(nd, c);

	ATF_CHECK_MSG(!c->provisioned, "a mismatched Record Response was "
	    "assembled and used");
	/* No certificate verdict was ever reached: nothing was assembled. */
	ATF_CHECK_MSG(strstr(c->status, "last=none") != NULL, "%s", c->status);
	/* The Provisioner refused the PDU rather than the certificate. */
	ATF_CHECK_MSG(c->sd.got_failed, "no Provisioning Failed PDU");
	ATF_CHECK_EQ(MESH_PROV_ERR_INVALID_PDU, c->sd.failed_code);
}

ATF_TC_WITHOUT_HEAD(cert_verbs);
ATF_TC_BODY(cert_verbs, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer;
	struct mesh_prov_data pdata;
	uint8_t uuid[16], raw[25];
	char reply[MESHD_CTL_REPLY_MAX];

	prov_node(nd, &cfg, &bearer);
	ATF_REQUIRE_EQ(16, unhex(SAMPLE_UUID_HEX, uuid, sizeof(uuid)));

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1, "provision-cert"));
	ATF_CHECK_MSG(strstr(reply, "mode=off") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "last=none") != NULL, "%s", reply);

	/* Enabling without trust anchors is refused, not silently accepted. */
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 2, "provision-cert",
	    "on"));
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 3, "provision-cert",
	    "on", ""));
	/*
	 * A CID/PID requirement may be set before the feature is enabled -- it
	 * is a stored preference, and it only ever narrows what will be
	 * accepted -- but a malformed one is refused.
	 */
	ATF_CHECK_EQ(0, verb(nd, reply, sizeof(reply), 4, "provision-cert",
	    "cid-pid", "0x8001", "0x03ff"));
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 4, "provision-cert",
	    "cid-pid", "0x18001", "0x03ff"));
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 4, "provision-cert",
	    "cid-pid", "0x8001", "notanumber"));

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 3, "provision-cert",
	    "require", "roots.pem"));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1, "provision-cert"));
	ATF_CHECK_MSG(strstr(reply, "mode=require") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "roots=roots.pem") != NULL, "%s", reply);

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 4, "provision-cert",
	    "cid-pid", "0x8001", "0x03ff"));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 3, "provision-cert",
	    "policies", "off"));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1, "provision-cert"));
	ATF_CHECK_MSG(strstr(reply, "cid-pid=required") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "policies=optional") != NULL, "%s", reply);
	ATF_CHECK_EQ(-1, verb(nd, reply, sizeof(reply), 2, "provision-cert",
	    "bogus"));

	/*
	 * PB-GATT carries no record retrieval in this implementation, so a
	 * PB-GATT attempt is refused while certificate-based provisioning is
	 * enabled rather than run without the certificate.
	 */
	ATF_REQUIRE_EQ(25, unhex(
	    "efb2255e6422d330088e09bb015ed707056700010203040b0c", raw,
	    sizeof(raw)));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	ATF_CHECK_EQ(-1, meshd_provision_gatt_begin(nd, "00:11:22:33:44:55", 0,
	    0, uuid, 1));

	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 2, "provision-cert",
	    "off"));
	ATF_REQUIRE_EQ(0, verb(nd, reply, sizeof(reply), 1, "provision-cert"));
	ATF_CHECK_MSG(strstr(reply, "mode=off") != NULL, "%s", reply);
}

ATF_TP_ADD_TCS(tp)
{

	/* Provisioning record transfer, Provisionee side. */
	ATF_TP_ADD_TC(tp, records_get_list_sample);
	ATF_TP_ADD_TC(tp, record_request_response_sample);
	ATF_TP_ADD_TC(tp, record_not_present);
	ATF_TP_ADD_TC(tp, record_offset_out_of_bounds);
	ATF_TP_ADD_TC(tp, records_after_invite_unexpected_pdu);
	ATF_TP_ADD_TC(tp, record_request_prohibited_frag_max);
	ATF_TP_ADD_TC(tp, unprov_beacon_oob_bits);
	ATF_TP_ADD_TC(tp, records_verbs);
	/* Certificate-based provisioning, Provisioner side. */
	ATF_TP_ADD_TC(tp, cert_oob_public_key_end_to_end);
	ATF_TP_ADD_TC(tp, cert_multi_fragment_retrieval);
	ATF_TP_ADD_TC(tp, cert_uuid_mismatch_refused);
	ATF_TP_ADD_TC(tp, cert_unknown_root_refused);
	ATF_TP_ADD_TC(tp, cert_expired_refused);
	ATF_TP_ADD_TC(tp, cert_profile_key_usage_refused);
	ATF_TP_ADD_TC(tp, cert_profile_ca_true_refused);
	ATF_TP_ADD_TC(tp, cert_root_in_chain_refused);
	ATF_TP_ADD_TC(tp, cert_no_downgrade_without_peer_oob_bit);
	ATF_TP_ADD_TC(tp, cert_absent_require_versus_try);
	ATF_TP_ADD_TC(tp, cert_response_mismatch_refused);
	ATF_TP_ADD_TC(tp, cert_verbs);
	return (atf_no_error());
}
