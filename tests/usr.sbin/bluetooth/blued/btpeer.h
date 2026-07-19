/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * btpeer.h - a hardware-free virtual remote BLE peer.
 *
 * btpeer is the far end of a link: it rides one side of an hci_emu link
 * (tests/.../hci_emulator.c) and speaks, on top of L2CAP LE fixed channels
 * (ATT CID 0x0004, SMP CID 0x0006 - Core Spec Vol 3 Part A Section 2.1),
 * the CLIENT or SERVER (accessory) side of ATT/GATT and an SMP peer.  It is
 * the userspace analogue of a controller-emulator "bthost": it lets the real
 * blued daemon-side protocol code (att.c client, att_server*.c, gatt.c,
 * smp*.c) be driven end to end with no kernel, netgraph, or radio.
 *
 * ORACLE: every PDU btpeer emits is hand-encoded from the Bluetooth Core
 * Specification (<= 5.2), Vol 3 Part F (ATT), Part G (GATT), Part H (SMP);
 * NOT captured from the implementation under test.
 *
 * Transport: btpeer transmits by feeding a typed ACL packet into its emu
 * (which the emu link delivers out the peer controller's output callback)
 * and receives by being that emu's output callback.  A single L2CAP B-frame
 * (Vol 3 Part A Section 3.1) rides in each ACL start fragment; PDUs here stay
 * under the default 27-octet LE ACL payload so no fragmentation is needed.
 */

#ifndef _BLUED_BTPEER_H_
#define _BLUED_BTPEER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct hci_emu;
struct btpeer;

/* Sizing limits for the peer's own (accessory) attribute database. */
#define BTPEER_MAX_ATTRS	48
#define BTPEER_VAL_STORE	1024
#define BTPEER_MAX_DISC		32

/* Permissions for a peer-server attribute (btpeer_add_attr). */
#define BTPEER_PERM_READ	0x01
#define BTPEER_PERM_WRITE	0x02
#define BTPEER_PERM_READ_ENC	0x04	/* read requires an encrypted link */
#define BTPEER_PERM_WRITE_ENC	0x08	/* write requires an encrypted link */

/*
 * Results of GATT discovery when btpeer acts as the client against OUR
 * server.  Layout mirrors the Core Spec response record formats.
 */
struct btpeer_service {
	uint16_t	start;		/* Attribute Handle */
	uint16_t	end;		/* End Group Handle */
	uint16_t	uuid16;		/* 16-bit service UUID */
};

struct btpeer_char {
	uint16_t	decl;		/* declaration handle */
	uint16_t	value;		/* Characteristic Value handle */
	uint8_t		props;		/* Characteristic Properties */
	uint16_t	uuid16;		/* Characteristic UUID (16-bit) */
};

struct btpeer_desc {
	uint16_t	handle;
	uint16_t	uuid16;
};

/*
 * Notification/indication callback fired when btpeer, acting as the client,
 * receives a Handle Value Notification (0x1B) or Indication (0x1D) from OUR
 * server.  For an indication btpeer has already sent the Confirmation (0x1E).
 * A Multiple Handle Value Notification (0x23, Vol 3 Part F 3.4.7.4) is
 * delivered as one callback per {handle,value} tuple it carries, each with
 * indication == false.
 */
typedef void (*btpeer_notify_cb)(void *arg, uint16_t handle,
    const uint8_t *value, uint16_t len, bool indication);

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */
struct btpeer	*btpeer_new(struct hci_emu *emu);
void		 btpeer_free(struct btpeer *bp);

/*
 * The emu link's connection must already be established before the first
 * transfer; btpeer learns its connection handle lazily, but this lets a test
 * pin it (and confirm a connection exists).  Returns 0 on success.
 */
int		 btpeer_bind_conn(struct btpeer *bp);

/*
 * Reset the peer's per-connection ATT bearer state for a reconnection (a new
 * L2CAP bearer, Vol 3 Part F 3.2.8 / 3.4.2): drop the cached connection handle
 * so the next transfer re-binds the freshly-allocated handle, restore the ATT
 * default MTU, and clear in-flight transaction state.
 */
void		 btpeer_reset_bearer(struct btpeer *bp);

/* Local (peer) MTU advertised in the Exchange MTU Response / Request. */
void		 btpeer_set_mtu(struct btpeer *bp, uint16_t mtu);

/* ----------------------------------------------------------------
 * btpeer as GATT/ATT CLIENT (drives OUR att_server).  Synchronous: the emu
 * link delivers the whole request/response round trip inline.
 * ---------------------------------------------------------------- */

/* Exchange MTU (Vol 3 Part F Section 3.4.2). */
int	btpeer_gatt_exchange_mtu(struct btpeer *bp, uint16_t client_mtu,
	    uint16_t *server_mtu);

/* Primary service discovery via Read By Group Type (Vol 3 Part G 4.4.1). */
int	btpeer_gatt_discover_services(struct btpeer *bp,
	    struct btpeer_service *out, int max, int *count);

/* Characteristic discovery via Read By Type (Vol 3 Part G 4.6.1). */
int	btpeer_gatt_discover_chars(struct btpeer *bp, uint16_t start,
	    uint16_t end, struct btpeer_char *out, int max, int *count);

/* Descriptor discovery via Find Information (Vol 3 Part G 4.7.1). */
int	btpeer_gatt_discover_descs(struct btpeer *bp, uint16_t start,
	    uint16_t end, struct btpeer_desc *out, int max, int *count);

/* Read Request / Read Blob Request (Vol 3 Part F 3.4.4.3 / 3.4.4.5). */
int	btpeer_gatt_read(struct btpeer *bp, uint16_t handle,
	    uint8_t *buf, size_t buflen, size_t *outlen);
int	btpeer_gatt_read_blob(struct btpeer *bp, uint16_t handle,
	    uint16_t offset, uint8_t *buf, size_t buflen, size_t *outlen);

/*
 * Find By Type Value (Vol 3 Part F 3.4.3.3) - discover primary services by
 * UUID (Vol 3 Part G 4.4.2).  Returns matching {start,end} handle ranges in
 * out[].uuid16 is set to the searched UUID.
 */
int	btpeer_gatt_find_by_type_value(struct btpeer *bp, uint16_t start,
	    uint16_t end, uint16_t type_uuid, const void *value, uint16_t vlen,
	    struct btpeer_service *out, int max, int *count);

/* One Read By Type record: attribute handle + up to 22 value octets. */
struct btpeer_rbt_rec {
	uint16_t	handle;
	uint8_t		val[22];
	uint16_t	vlen;
};

/*
 * Generic Read By Type (Vol 3 Part F 3.4.4.1) over an arbitrary 16-bit type,
 * paging until Attribute Not Found.  Returns handle+value records.
 */
int	btpeer_gatt_read_by_type(struct btpeer *bp, uint16_t start,
	    uint16_t end, uint16_t type_uuid, struct btpeer_rbt_rec *out,
	    int max, int *count);

/* Read Multiple Request (Vol 3 Part F 3.4.4.7): concatenated values. */
int	btpeer_gatt_read_multiple(struct btpeer *bp, const uint16_t *handles,
	    int nhandles, uint8_t *buf, size_t buflen, size_t *outlen);

/*
 * Read Multiple Variable Request (Vol 3 Part F 3.4.4.9, an Enhanced-ATT /
 * BT 5.2 feature also reachable on the fixed ATT channel).  The response is a
 * Length-Value tuple list: for each requested handle a 2-octet Value Length
 * (LE) followed by that many value octets.  The raw tuple list (starting at
 * the first Length field, i.e. the response payload after the opcode) is copied
 * verbatim into buf so a test can assert the exact wire format.
 */
int	btpeer_gatt_read_multiple_variable(struct btpeer *bp,
	    const uint16_t *handles, int nhandles, uint8_t *buf, size_t buflen,
	    size_t *outlen);

/*
 * Signed Write Command (ATT 0xD2, Vol 3 Part F 3.4.5.4 / signing algorithm
 * Vol 3 Part H 2.4.5).  Builds opcode | handle | value | SignCounter(4,LE) |
 * MAC(8) where the 64-bit MAC is the least-significant 8 octets of
 * AES-CMAC(CSRK, opcode||handle||value||SignCounter).  csrk is supplied in
 * little-endian (wire) order, matching what OUR side stored from the peer's
 * key distribution.  No response is defined (it is a command); returns 0 once
 * the PDU is delivered.  Drives OUR att_server signed-write verify + replay
 * path (att_server_dispatch.c ATT_OP_LEGACY_SIGNED_WRITE_CMD).
 */
int	btpeer_gatt_signed_write(struct btpeer *bp, uint16_t handle,
	    const void *data, uint16_t len, const uint8_t csrk[16],
	    uint32_t counter);

/*
 * Prepare Write Request (Vol 3 Part F 3.4.6.1): queue one value part; the
 * server echoes handle/offset/value in the Prepare Write Response, which is
 * captured (btpeer_last_prepare_echo).
 */
int	btpeer_gatt_prepare_write(struct btpeer *bp, uint16_t handle,
	    uint16_t offset, const void *data, uint16_t len);

/* Execute Write Request (Vol 3 Part F 3.4.6.3): flags 0x00 cancel, 0x01 write. */
int	btpeer_gatt_execute_write(struct btpeer *bp, uint8_t flags);

/*
 * Reliable / long write (Vol 3 Part G 4.9.4 / 4.9.5): split data into
 * (mtu-5)-octet parts, Prepare each (verifying the echo), then Execute.
 */
int	btpeer_gatt_write_long(struct btpeer *bp, uint16_t handle,
	    const void *data, uint16_t len);

/* Fields of the most recent Prepare Write Response echo. */
int	btpeer_last_prepare_echo(const struct btpeer *bp, uint16_t *handle,
	    uint16_t *offset, uint8_t *buf, size_t buflen, size_t *outlen);

/* Write Request / Write Command (Vol 3 Part F 3.4.5.1 / 3.4.5.3). */
int	btpeer_gatt_write(struct btpeer *bp, uint16_t handle,
	    const void *data, uint16_t len);
int	btpeer_gatt_write_cmd(struct btpeer *bp, uint16_t handle,
	    const void *data, uint16_t len);

/* Subscribe by writing a CCCD (0x2902) value (Vol 3 Part G 3.3.3.3). */
int	btpeer_gatt_subscribe(struct btpeer *bp, uint16_t cccd_handle,
	    uint16_t cccd_value);

/*
 * After a client call returns nonzero, retrieve the ATT Error Response
 * (Vol 3 Part F 3.4.1.1) fields, if the failure was an error response.
 * Returns 1 if an error response was captured, 0 otherwise.
 */
int	btpeer_last_att_error(const struct btpeer *bp, uint8_t *req_op,
	    uint16_t *handle, uint8_t *code);

void	btpeer_on_notify(struct btpeer *bp, btpeer_notify_cb cb, void *arg);

/* ----------------------------------------------------------------
 * btpeer as GATT SERVER (accessory): OUR client discovers / reads / writes
 * the peer's own attribute database.  This is the "peer is the keyboard"
 * direction for HOGP.
 * ---------------------------------------------------------------- */

/* Add a raw attribute; returns the assigned handle (0 on failure). */
uint16_t btpeer_add_attr(struct btpeer *bp, uint16_t uuid16, uint8_t perms,
	    const void *value, uint16_t len);

/* Convenience builders returning the value handle (or service/cccd handle). */
uint16_t btpeer_add_service(struct btpeer *bp, uint16_t svc_uuid);
uint16_t btpeer_add_characteristic(struct btpeer *bp, uint16_t char_uuid,
	    uint8_t props, uint8_t perms, const void *value, uint16_t len);
uint16_t btpeer_add_cccd(struct btpeer *bp);

/* Mutate / observe a stored attribute value. */
int	btpeer_set_value(struct btpeer *bp, uint16_t handle,
	    const void *value, uint16_t len);
int	btpeer_get_value(const struct btpeer *bp, uint16_t handle,
	    uint8_t *buf, size_t buflen, size_t *outlen);
int	btpeer_get_cccd(const struct btpeer *bp, uint16_t handle,
	    uint16_t *value);

/* Peer server pushes a Notification / Indication to OUR client. */
int	btpeer_server_notify(struct btpeer *bp, uint16_t handle,
	    const void *value, uint16_t len);
int	btpeer_server_indicate(struct btpeer *bp, uint16_t handle,
	    const void *value, uint16_t len);

/*
 * Arm a notification: when OUR client next enables notifications on the
 * given CCCD handle (Write Request with bit 0 set), the peer server, after
 * sending the Write Response, immediately pushes value_handle's value_len
 * bytes as a Handle Value Notification.  Models a HID device streaming a
 * keystroke on subscribe.
 */
int	btpeer_arm_notify_on_subscribe(struct btpeer *bp, uint16_t cccd_handle,
	    uint16_t value_handle, const void *value, uint16_t len);

/* ----------------------------------------------------------------
 * SMP peer (Vol 3 Part H).  btpeer acts as the pairing RESPONDER for LE
 * Legacy Just Works: it answers OUR smp_pair() initiator.  Feed it the
 * addresses so it can compute c1 with the identical arguments both sides use.
 * ---------------------------------------------------------------- */
void	btpeer_smp_set_addrs(struct btpeer *bp,
	    const uint8_t peer_addr[6], uint8_t peer_addr_type,
	    const uint8_t init_addr[6], uint8_t init_addr_type);

/* Set the peer's fixed Pairing Random (for determinism); default is fixed. */
void	btpeer_smp_set_srand(struct btpeer *bp, const uint8_t srand[16]);

/* True once the peer completed the SMP exchange and derived the STK. */
bool	btpeer_smp_done(const struct btpeer *bp);

/* Copy the peer-derived STK (Vol 3 Part H 2.2.4).  Returns 0 if available. */
int	btpeer_smp_get_stk(const struct btpeer *bp, uint8_t stk[16]);

/* ----------------------------------------------------------------
 * Full SMP pairing-method matrix (Vol 3 Part H).  btpeer can act as the
 * pairing RESPONDER (answering OUR smp_pair initiator) or as the INITIATOR
 * (driving OUR smp_respond responder), in LE Legacy or LE Secure Connections,
 * across every association model (Just Works, Passkey Entry, Numeric
 * Comparison, OOB).  ECDH is performed through OpenSSL, but SMP crypto calls
 * the production smp_c1/s1/f4/f5/f6/g2 primitives.  This makes btpeer a
 * protocol-driving harness, not an independent crypto oracle; callers must
 * use separate published-vector/OpenSSL checks for expected cryptography.
 * ---------------------------------------------------------------- */
enum btpeer_smp_role {
	BTPEER_SMP_RESPONDER = 0,	/* answer OUR smp_pair() initiator */
	BTPEER_SMP_INITIATOR = 1,	/* drive OUR smp_respond() responder */
};

enum btpeer_smp_method {
	BTPEER_SMP_JUST_WORKS = 0,	/* Vol 3 Part H 2.3.5.2 / 2.3.5.6.2 */
	BTPEER_SMP_PASSKEY = 1,		/* Vol 3 Part H 2.3.5.3 / 2.3.5.6.3 */
	BTPEER_SMP_NUMERIC = 2,		/* SC only, Vol 3 Part H 2.3.5.6.2 */
	BTPEER_SMP_OOB = 3,		/* Vol 3 Part H 2.3.5.4 / 2.3.5.6.4 */
};

/*
 * Mid-flow fault injection (Vol 3 Part H 3.5.5 / 2.3.5.6).  At a chosen
 * handshake STAGE the peer replaces the PDU it would normally send with a
 * spec-defined fault, driving OUR Security Manager down each of its
 * abort / negotiation-failure arms.  inject_stage == BTPEER_SMP_STAGE_NONE
 * disables injection.  The stage is generic across association models: the
 * configured method decides which flow runs, and the peer injects at the
 * first time it is about to emit a PDU of that stage's opcode (so for the SC
 * Passkey 20-round loop it fires on the first round).
 */
enum btpeer_smp_stage {
	BTPEER_SMP_STAGE_NONE = 0,
	BTPEER_SMP_STAGE_PUBKEY,		/* Pairing Public Key (0x0C) */
	BTPEER_SMP_STAGE_CONFIRM,		/* Pairing Confirm (0x03) */
	BTPEER_SMP_STAGE_RANDOM,		/* Pairing Random (0x04) */
	BTPEER_SMP_STAGE_DHCHECK,		/* Pairing DHKey Check (0x0D) */
};

enum btpeer_smp_inject {
	BTPEER_SMP_INJECT_NONE = 0,
	BTPEER_SMP_INJECT_WRONG_OPCODE,	/* full-length PDU, wrong opcode */
	BTPEER_SMP_INJECT_TRUNCATED,	/* correct opcode, too-short PDU */
	BTPEER_SMP_INJECT_FAIL,		/* mid-flow Pairing Failed(reason) */
	BTPEER_SMP_INJECT_OFF_CURVE,	/* PUBKEY stage: off-curve P-256 key */
};

struct btpeer_smp_cfg {
	enum btpeer_smp_role	role;
	enum btpeer_smp_method	method;
	bool		sc;		/* LE Secure Connections */
	uint8_t		io_cap;		/* SMP_IO_* advertised by the peer */
	bool		mitm;		/* set the AuthReq MITM bit */
	bool		bonding;	/* set the AuthReq Bonding bit */
	uint8_t		max_key_size;	/* 7..16 (default 16) */
	uint8_t		local_key_dist;	/* keys the peer distributes (SMP_KEY_DIST_*) */
	uint8_t		remote_key_dist;/* keys the peer asks OUR side to send */
	uint32_t	passkey;	/* fixed passkey for Passkey Entry */
	/* Optional caller-owned deterministic key-distribution fixtures. */
	bool		have_local_ltk;
	uint8_t		local_ltk[16];
	bool		have_local_irk;
	uint8_t		local_irk[16];
	bool		have_local_csrk;
	uint8_t		local_csrk[16];
	/* Negative-path knobs (spec 3.5.5 failures). */
	bool		force_confirm_mismatch;	/* corrupt our confirm value */
	bool		force_numeric_reject;	/* reject Numeric Comparison */
	bool		force_dhkey_mismatch;	/* corrupt our DHKey check (Eb/Ea) */
	uint8_t		force_fail_reason;	/* if !=0, reply Pairing Failed up front */
	/* Mid-flow fault injection (see enums above). */
	uint8_t		inject_stage;		/* enum btpeer_smp_stage */
	uint8_t		inject_action;		/* enum btpeer_smp_inject */
	uint8_t		inject_reason;		/* Pairing Failed reason for INJECT_FAIL */
	/*
	 * Key-distribution fault (Vol 3 Part H 3.6): if !=0, when the peer
	 * distributes a key PDU of this opcode it sends it TRUNCATED (a lone
	 * opcode octet) so OUR receive-side length guard drops it.
	 */
	uint8_t		inject_kd_trunc_opcode;
};

/* Apply a pairing configuration.  Call after btpeer_smp_set_addrs(). */
void	btpeer_smp_configure(struct btpeer *bp, const struct btpeer_smp_cfg *cfg);

/*
 * OOB material exchanged "out of band".  For legacy OOB set the shared TK.
 * For SC OOB, supply the peer's own random (rb) and the DUT's OOB
 * {confirm(Ca), random(ra)} that the test also handed to OUR smp_conn.oob.
 */
void	btpeer_smp_set_oob_legacy_tk(struct btpeer *bp, const uint8_t tk[16]);
void	btpeer_smp_set_oob_sc(struct btpeer *bp, const uint8_t local_random[16],
	    const uint8_t peer_confirm[16], const uint8_t peer_random[16]);

/*
 * SC OOB confirm helper: given the peer's SC public-key x-coordinate (LE) and
 * random rb, compute Cb = f4(PKbx, PKbx, rb, 0) (Vol 3 Part H 2.3.5.6.4) so a
 * test can hand OUR smp_conn.oob the peer's confirm.  Returns 0 on success.
 * The peer's public key becomes available after btpeer_smp_configure(); use
 * btpeer_smp_get_oob_pubkey_x() to fetch it.
 */
int	btpeer_smp_get_oob_pubkey_x(struct btpeer *bp, uint8_t pkx_le[32]);

/* As INITIATOR, send the Pairing Request to kick off pairing.  Returns 0. */
int	btpeer_smp_start(struct btpeer *bp);

/* Results after the exchange has been pumped. */
bool	btpeer_smp_bonded(const struct btpeer *bp);	/* reached key material */
bool	btpeer_smp_is_sc(const struct btpeer *bp);
bool	btpeer_smp_is_mitm(const struct btpeer *bp);
int	btpeer_smp_get_ltk(const struct btpeer *bp, uint8_t ltk[16]);
uint8_t	btpeer_smp_fail_reason(const struct btpeer *bp);	/* 0 = none */

/* Keys the peer received from OUR side's key distribution (Vol 3 Part H 3.6). */
bool	btpeer_smp_got_peer_irk(const struct btpeer *bp, uint8_t irk[16]);
bool	btpeer_smp_got_peer_identity(const struct btpeer *bp,
	    uint8_t *addr_type, uint8_t addr[6]);
bool	btpeer_smp_got_peer_csrk(const struct btpeer *bp, uint8_t csrk[16]);

#endif /* _BLUED_BTPEER_H_ */
