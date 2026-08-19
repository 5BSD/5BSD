/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_SMP_H_
#define _BLUED_SMP_H_

#include <stdint.h>
#include <stdbool.h>
#include <time.h>		/* struct timespec (cumulative pairing timer) */

/* SMP opcodes (Core Spec Vol 3 Part H Section 3.3) */
#define SMP_PAIRING_REQUEST		0x01
#define SMP_PAIRING_RESPONSE		0x02
#define SMP_PAIRING_CONFIRM		0x03
#define SMP_PAIRING_RANDOM		0x04
#define SMP_PAIRING_FAILED		0x05
#define SMP_ENCRYPTION_INFORMATION	0x06
#define SMP_CENTRAL_IDENTIFICATION	0x07
#define SMP_IDENTITY_INFORMATION	0x08
#define SMP_IDENTITY_ADDRESS_INFO	0x09
#define SMP_LEGACY_SIGNING_INFORMATION		0x0A	/* Core 6.3: previously used */
/* Source compatibility only; new code must name the removed feature. */
#define SMP_SIGNING_INFORMATION		SMP_LEGACY_SIGNING_INFORMATION
#define SMP_SECURITY_REQUEST		0x0B
#define SMP_PAIRING_PUBLIC_KEY		0x0C
#define SMP_PAIRING_DHKEY_CHECK		0x0D
#define SMP_PAIRING_KEYPRESS_NOTIFY	0x0E

/* IO capabilities (Core Spec Vol 3 Part H Section 2.3.2) */
#define SMP_IO_DISPLAY_ONLY		0x00
#define SMP_IO_DISPLAY_YESNO		0x01
#define SMP_IO_KEYBOARD_ONLY		0x02
#define SMP_IO_NO_INPUT_NO_OUTPUT	0x03
#define SMP_IO_KEYBOARD_DISPLAY		0x04

/* Core Vol 6, Part B, Section 1.3.2, Table 1.2: Address[47:46]. */
#define SMP_RANDOM_ADDRESS_TYPE_MASK	0xc0
#define SMP_RANDOM_ADDRESS_RANDOM_MASK	0x3f
#define SMP_RANDOM_ADDRESS_RESOLVABLE	0x40

/* Core Vol 3, Part H, Section 3.6.5 Identity Address Information wire values. */
#define SMP_ID_ADDR_PUBLIC		0x00
#define SMP_ID_ADDR_STATIC_RANDOM	0x01

/* Keypress Notification types (Core Spec Vol 3 Part H Section 3.5.8) */
#define SMP_KEYPRESS_STARTED		0x00
#define SMP_KEYPRESS_DIGIT_ENTERED	0x01
#define SMP_KEYPRESS_DIGIT_ERASED	0x02
#define SMP_KEYPRESS_CLEARED		0x03
#define SMP_KEYPRESS_COMPLETED		0x04

/* Auth request flags */
#define SMP_AUTH_BONDING		0x01
#define SMP_AUTH_MITM			0x04
#define SMP_AUTH_SC			0x08
#define SMP_AUTH_KEYPRESS		0x10	/* Keypress Notification support */
#define SMP_AUTH_CT2			0x20	/* Cross-Transport Key Derivation h7 */

/*
 * Minimum-security-for-pairing policy levels (Core Spec Vol 3 Part H
 * §2.3.5.1 association models, Part C §10.2.1 LE security modes).  A pairing
 * that cannot reach the configured floor is rejected with Pairing Failed
 * before any key is derived.  Ordered by increasing strength; each level
 * subsumes the ones below it:
 *   NONE - no floor: accept whatever association the peer offers.
 *   ENC  - an encrypted (bonded) link is required; any association model
 *          qualifies (all LE pairing yields an encrypted link).
 *   AUTH - MITM-authenticated pairing required: reject unauthenticated
 *          Just Works.
 *   SC   - LE Secure Connections required: reject LE legacy pairing; being
 *          the strongest level it is also authenticated.
 * Numeric values are the on-the-wire policy encoding shared with config.c.
 */
#define SMP_SEC_NONE			0
#define SMP_SEC_ENC			1
#define SMP_SEC_AUTH			2
#define SMP_SEC_SC			3

/* Key distribution flags */
#define SMP_KEY_DIST_ENC_KEY		0x01	/* LTK + EDIV + Rand */
#define SMP_KEY_DIST_ID_KEY		0x02	/* IRK + Address */
#define SMP_KEY_DIST_LEGACY_SIGN_KEY		0x04	/* Core 6.3: previously used */
#define SMP_KEY_DIST_LINK_KEY		0x08	/* derive BR/EDR key from SC LTK */
/* Source compatibility only; new code must name the removed feature. */
#define SMP_KEY_DIST_SIGN_KEY		SMP_KEY_DIST_LEGACY_SIGN_KEY

/* SMP pairing failure reasons */
#define SMP_ERR_PASSKEY_ENTRY_FAILED	0x01
#define SMP_ERR_OOB_NOT_AVAILABLE	0x02
#define SMP_ERR_AUTH_REQUIREMENTS	0x03
#define SMP_ERR_CONFIRM_VALUE_FAILED	0x04
#define SMP_ERR_PAIRING_NOT_SUPPORTED	0x05
#define SMP_ERR_ENCRYPTION_KEY_SIZE	0x06
#define SMP_ERR_CMD_NOT_SUPPORTED	0x07
#define SMP_ERR_UNSPECIFIED_REASON	0x08
#define SMP_ERR_REPEATED_ATTEMPTS	0x09
#define SMP_ERR_INVALID_PARAMETERS	0x0A
#define SMP_ERR_DHKEY_CHECK_FAILED	0x0B
#define SMP_ERR_NUMERIC_COMP_FAILED	0x0C
#define SMP_ERR_BREDR_PAIRING_IN_PROGRESS 0x0D
#define SMP_ERR_CROSS_TRANSPORT_NOT_ALLOWED 0x0E
#define SMP_ERR_KEY_REJECTED		0x0F
#define SMP_ERR_BUSY			0x10

/*
 * OOB data for LE Legacy Pairing.
 * The TK (Temporary Key) is a 128-bit random value exchanged OOB.
 */
struct smp_oob_legacy {
	uint8_t	tk[16];
};

/*
 * OOB data for LE Secure Connections.
 * Each side generates {confirm, random} and exchanges them OOB.
 * Core Spec Vol 3 Part H Section 2.3.5.6.4
 */
struct smp_oob_sc {
	uint8_t	confirm[16];	/* peer's OOB confirm value (Ca/Cb) */
	uint8_t	random[16];	/* peer's OOB random value (ra/rb) */
	uint8_t	local_random[16]; /* our OOB random value (for f6 DHKey check) */
};

/*
 * OOB data container -- set on smp_conn before calling smp_pair/smp_respond.
 * If oob_legacy is non-NULL, legacy OOB is available.
 * If oob_sc is non-NULL, SC OOB is available.
 */
struct smp_oob_data {
	struct smp_oob_legacy	*legacy;
	struct smp_oob_sc	*sc;
};

/*
 * CCCD persistence entry.
 * Core Spec Vol 3 Part G Section 2.4.5.1: the server shall
 * persistently record the CCCD value for a bonded device.
 */
#define SMP_MAX_CCCDS	16

struct smp_cccd_entry {
	uint16_t	handle;		/* attribute handle of CCCD */
	uint16_t	value;		/* CCCD value (notifications/indications) */
};

/*
 * Bond key storage.
 * One entry per bonded device.
 */
struct smp_bond {
	uint8_t		addr[6];	/* device address */
	uint8_t		addr_type;	/* public or random */
	uint8_t		ltk[16];	/* Long Term Key */
	uint64_t	rand;		/* Random number */
	uint16_t	ediv;		/* Encrypted Diversifier */
	uint8_t		irk[16];	/* Identity Resolving Key */
	uint8_t		link_key[16];	/* BR/EDR Link Key (derived via CTKD) */
	char		name[32];	/* GAP Device Name (from 0x2A00) */
	uint8_t		db_hash[16];	/* last known GATT Database Hash */
	bool		has_ltk;
	bool		has_irk;
	uint8_t		csrk[16];	/* Connection Signature Resolving Key */
	bool		has_csrk;	/* csrk is valid */
	uint32_t	peer_sign_counter; /* last verified sign counter */
	bool		has_link_key;	/* link_key derived via CTKD */
	bool		is_sc;		/* paired with LE Secure Connections */
	bool		is_mitm;	/* pairing used MITM-protected association model */
	bool		has_name;
	bool		has_db_hash;	/* db_hash is valid for GATT caching */
	uint8_t		num_cccds;
	struct smp_cccd_entry cccds[SMP_MAX_CCCDS];

	/* GATT handle cache (avoids rediscovery when db_hash matches) */
	bool		has_handle_cache;
	uint16_t	hid_svc_start;		/* HID Service start handle */
	uint16_t	hid_svc_end;		/* HID Service end handle */
	uint16_t	bat_svc_start;		/* Battery Service start handle */
	uint16_t	bat_svc_end;		/* Battery Service end handle */
	uint16_t	report_map_handle;
	uint16_t	hid_info_handle;
	uint16_t	protocol_mode_handle;
	/*
	 * HID Control Point value handle (finding 68).  Cached so a cache-hit
	 * reconnect can issue the Exit-Suspend write without rediscovery; 0 when
	 * the peer exposes no control point.  report_map_handles[] holds the
	 * Report Map value handle of each HID service instance (multi-instance
	 * HOGP) so the full report map can be restored on a cache hit;
	 * num_report_maps is how many are valid (instance 0 mirrors the legacy
	 * report_map_handle above).
	 */
	uint16_t	hid_ctrl_handle;
	uint16_t	report_map_handles[4];
	uint8_t		num_report_maps;
	uint8_t		_hogp_pad0;
	uint16_t	report_handles[16];	/* Input/Output/Feature report value handles */
	uint16_t	report_cccd_handles[16]; /* Corresponding CCCD handles */
	uint8_t		report_types[16];	/* Report type (Input=1, Output=2, Feature=3) */
	uint8_t		report_ids[16];
	int		num_reports;
	uint16_t	battery_level_handle;
	uint16_t	battery_cccd_handle;

	/* Negotiated encryption key size in octets (7-16). */
	uint8_t		key_size;
};

#define SMP_MAX_BONDS	32

/* Save reached rename commit point, but post-rename durability/fd refresh
 * failed.  Callers must report failure but must not roll back memory. */
#define SMP_BOND_DB_COMMIT_UNCERTAIN	(-2)

struct smp_bond_db {
	struct smp_bond	bonds[SMP_MAX_BONDS];
	int		count;
	int		fd;		/* bond storage file fd */
	int		dir_fd;		/* Directory fd for atomic renameat saves */
	char		file_name[64];	/* bond file basename within dir_fd */
	uint8_t		local_irk[16];	/* persisted local IRK for RPA resolution */
	bool		has_local_irk;	/* local_irk has been loaded or generated */
	uint8_t		local_csrk[16];	/* persisted local CSRK for Signed Writes */
	bool		has_local_csrk;	/* local_csrk has been loaded or generated */
	uint8_t		bond_secret[32]; /* cached per-database encryption root */
	bool		has_bond_secret;
	pthread_mutex_t	*lock;		/* optional: points to blued_g.bond_db_lock */
};

/*
 * Passkey callback for user interaction.
 * Called during Passkey Entry pairing.
 *
 * If 'display' is true, the daemon generated the passkey and
 * the callback should display it to the user.
 * If 'display' is false, the callback should prompt the user
 * to enter the passkey displayed on the peripheral and return
 * it via *passkey_out.
 *
 * Returns 0 on success, -1 on cancel.
 */
typedef int (*smp_passkey_cb_t)(uint32_t *passkey_out, bool display,
    void *arg);

/*
 * Numeric Comparison callback.
 * Displays the 6-digit value and asks the user to confirm it matches
 * the value shown on the peer device.  Returns 0 if confirmed, -1 to reject.
 */
typedef int (*smp_numcmp_cb_t)(uint32_t value, void *arg);

/*
 * Inbound Keypress Notification callback (Core Spec Vol 3 Part H §3.5.8).
 * Fired for every Keypress Notification received from the peer during Passkey
 * Entry (started / digit entered / digit erased / cleared / completed, the
 * SMP_KEYPRESS_* codes).  Informational only: it does not alter protocol state.
 * NULL leaves the historical behaviour (consume + log, no app surface).
 */
typedef void (*smp_keypress_cb_t)(uint8_t type, void *arg);

/*
 * SMP connection state.
 */
struct smp_conn {
	int		fd;		/* L2CAP SMP socket (CID 0x0006) */
	int		hci_fd;		/* raw HCI socket for encryption */
	uint16_t	con_handle;	/* HCI connection handle */
	uint8_t		local_addr[6];
	uint8_t		local_addr_type;
	uint8_t		remote_addr[6];
	uint8_t		remote_addr_type;
	struct smp_bond_db *bond_db;
	smp_passkey_cb_t passkey_cb;	/* passkey UI callback */
	void		*passkey_cb_arg;
	smp_numcmp_cb_t	numcmp_cb;	/* numeric comparison callback */
	void		*numcmp_cb_arg;
	struct smp_oob_data *oob;	/* OOB data, or NULL if none */
	smp_keypress_cb_t keypress_cb;	/* inbound Keypress Notification sink */
	void		*keypress_cb_arg;
	uint8_t		io_capability;	/* IO capability to use in pairing */
	uint8_t		min_key_size;	/* minimum encryption key size (7-16) */
	/*
	 * De-hardcoded SMP AuthReq / key-distribution policy (Core Spec Vol 3
	 * Part H §3.5.1, §3.6.1).  Historically these were literals baked into
	 * the Pairing Request/Response; they are now fields so config defaults
	 * (seeded to the previous literal values -- so no behaviour change
	 * unless an operator overrides them) and runtime setters can drive them,
	 * mirroring NimBLE ble_hs_cfg.sm_mitm/sm_bonding/sm_sc/sm_our_key_dist/
	 * sm_their_key_dist and the common Bondable/SecureConnections controls.
	 * smp_open()/smp_open_accepted() seed the previous defaults:
	 * require_mitm=bondable=sc_enabled=keypress=true,
	 * our_key_dist=their_key_dist=ENC|ID|SIGN.
	 */
	bool		require_mitm;	/* set SMP_AUTH_MITM in AuthReq */
	bool		bondable;	/* set SMP_AUTH_BONDING in AuthReq */
	bool		sc_enabled;	/* set SMP_AUTH_SC in AuthReq */
	bool		keypress;	/* set SMP_AUTH_KEYPRESS in AuthReq */
	bool		kp_negotiated;	/* S-m7: both sides set KEYPRESS in AuthReq
					 * (preq[3]&pres[3]); gates inbound
					 * Keypress Notification delivery */
	uint8_t		our_key_dist;	/* keys WE distribute (SMP_KEY_DIST_*) */
	uint8_t		their_key_dist;	/* keys we REQUEST (SMP_KEY_DIST_*) */
	uint8_t		neg_key_size;	/* negotiated enc key size (7-16); 16
					 * until Phase 1 completes.  Core Spec
					 * Vol 3 Part H §2.3.4 */
	bool		sc_only;	/* reject legacy pairing if true */
	/*
	 * Operator pairable gate (the common adapter pairable control).  When true the
	 * responder declines an incoming Pairing Request with "Pairing Not
	 * Supported" (Core Spec Vol 3 Part H §3.5.1).  Defaults false (accept)
	 * via the zeroing in smp_open()/smp_open_accepted().
	 */
	bool		reject_pairing;
	uint8_t		min_pairing_security;	/* policy floor: SMP_SEC_* */
	/*
	 * Cumulative SMP pairing timer (Core Spec Vol 3 Part H §3.4).  A
	 * single monotonic deadline armed once when the pairing procedure
	 * begins (Pairing Request/Response) and re-checked before/after every
	 * SMP recv in all five pairing flows.  pair_armed distinguishes an
	 * armed timer at virtual-clock t=0 (tests) from an unarmed one.
	 */
	struct timespec	pair_start;	/* monotonic instant pairing began */
	bool		pair_armed;	/* pair_start holds a valid deadline */
};

/* smp.c — crypto primitives (Core Spec Vol 3 Part H Section 2.2) */
void	smp_swap_buf(uint8_t *dst, const uint8_t *src, size_t len);
int	smp_aes128(const uint8_t key[16], const uint8_t in[16],
	    uint8_t out[16]) __attribute__((warn_unused_result));
int	smp_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
	    uint8_t mac[16]);
int	smp_c1(const uint8_t k[16], const uint8_t r[16],
	    const uint8_t preq[7], const uint8_t pres[7],
	    uint8_t iat, const uint8_t ia[6],
	    uint8_t rat, const uint8_t ra[6],
	    uint8_t confirm[16]);
int	smp_s1(const uint8_t k[16], const uint8_t r1[16],
	    const uint8_t r2[16], uint8_t stk[16]);
void	smp_mask_key(uint8_t key[16], uint8_t key_size);
int	smp_f4(const uint8_t u[32], const uint8_t v[32],
	    const uint8_t x[16], uint8_t z, uint8_t out[16]);
int	smp_f5(const uint8_t w[32], const uint8_t n1[16],
	    const uint8_t n2[16], const uint8_t a1[7],
	    const uint8_t a2[7], uint8_t mackey[16], uint8_t ltk[16]);
int	smp_f6(const uint8_t w[16], const uint8_t n1[16],
	    const uint8_t n2[16], const uint8_t r[16],
	    const uint8_t iocap[3], const uint8_t a1[7],
	    const uint8_t a2[7], uint8_t out[16]);
int	smp_g2(const uint8_t u[32], const uint8_t v[32],
	    const uint8_t x[16], const uint8_t y[16], uint32_t *out);
int	smp_h6(const uint8_t w[16], const uint8_t keyid[4],
	    uint8_t out[16]);
int	smp_h7(const uint8_t salt[16], const uint8_t w[16],
	    uint8_t out[16]);

/* smp.c — initiator (central) */
int	smp_open(struct smp_conn *sc, const uint8_t *addr, uint8_t addr_type,
	    const uint8_t *local_addr, uint8_t local_addr_type,
	    int hci_fd, uint16_t con_handle, struct smp_bond_db *db);
void	smp_close(struct smp_conn *sc);
int	smp_pair(struct smp_conn *sc);
int	smp_encrypt_with_ltk(struct smp_conn *sc, const struct smp_bond *bond);
struct smp_bond *smp_find_bond(struct smp_bond_db *db,
	    const uint8_t *addr, uint8_t addr_type);

/* smp.c — responder (peripheral) */
int	smp_open_accepted(struct smp_conn *sc, int fd,
	    const uint8_t *local_addr, uint8_t local_addr_type,
	    const uint8_t *remote_addr, uint8_t remote_addr_type,
	    int hci_fd, uint16_t con_handle, struct smp_bond_db *db);
int	smp_respond(struct smp_conn *sc);

/* OOB helpers */
int	smp_generate_sc_oob(uint8_t local_confirm[16],
	    uint8_t local_random[16], const uint8_t local_pk_x[32]);
/*
 * Generate local SC OOB data tied to a fresh ephemeral installed for the next
 * SC pairing (smp_sc.c); smp_sc_oob_clear_local() drops it afterwards.
 */
int	smp_sc_oob_generate_local(uint8_t confirm[16], uint8_t random[16],
	    uint8_t pkx_le[32]);
void	smp_sc_oob_clear_local(void);

/* IO capability pairing method selection (Core Spec Vol 3 Part H §2.3.5.1) */
int	smp_select_model(uint8_t init_io, uint8_t resp_io, bool sc);

/*
 * For the Passkey Entry model, decide whether this device displays the
 * passkey (true) or inputs it (false), given our IO capability, the peer's,
 * and whether we are the initiator (Core Spec Vol 3 Part H Table 2.8).
 */
bool	smp_passkey_we_display(uint8_t our_io, uint8_t peer_io,
	    bool is_initiator);

/*
 * Minimum-security-for-pairing policy decision.  Returns true if a
 * pairing whose association is 'authenticated' (MITM) and/or uses LE Secure
 * Connections ('use_sc') satisfies the configured 'floor' (SMP_SEC_*).
 */
bool	smp_policy_permits(uint8_t floor, bool authenticated, bool use_sc);

/*
 * Validate the per-machine identity root used to derive the bond-DB key
 * (fail-closed).  Trailing NUL/newline/space are ignored.  Returns 0 if a
 * significant byte remains, -1 to refuse (the bond path must not derive or
 * trust bonds from an empty/absent identity root).
 */
int	smp_bond_identity_root_ok(const char *root, size_t len);

/*
 * Enable atomic bond-DB persistence.  'dir_fd' is a directory fd whose
 * capability rights permit openat/fsync/renameat/unlinkat; 'path' supplies the
 * bond file, whose basename is stored and written via temp + fsync + rename.
 * Saving is refused until an atomic target is configured.
 */
void	smp_bond_db_set_atomic(struct smp_bond_db *db, int dir_fd,
	    const char *path);

/* RPA resolution and generation (Core Spec Vol 3 Part H §2.2.2) */
bool	smp_rpa_matches(const uint8_t irk[16], const uint8_t addr[6]);
int	smp_generate_rpa(const uint8_t irk[16], uint8_t rpa[6]);

/* Bond persistence */
int	smp_bond_db_load(struct smp_bond_db *db, int fd);
int	smp_bond_db_save(struct smp_bond_db *db);
int	smp_bond_db_store(struct smp_bond_db *db, const struct smp_bond *bond);
int	smp_bond_db_commit_bond(struct smp_bond_db *, struct smp_bond *,
	    const struct smp_bond *);

/*
 * Replace only the key material of an already-stored bond, matched by
 * identity address, preserving the rest of the record (GATT handle cache,
 * CCCD subscriptions, sign counter, device name, DB hash).  Implements the
 * key swap of a BLE key refresh / controlled re-bond (Core Spec Vol 3 Part H
 * §2.4): the single ltk[]/irk[]/csrk[] slots mean the old keys are gone the
 * instant the new ones land, so the previous LTK cannot survive the swap.
 * Returns 0 if a bond was updated, -1 if no bond matched (a first pairing,
 * not a refresh — the caller should store it as a new bond).
 */
int	smp_bond_db_replace_keys(struct smp_bond_db *db,
	    const struct smp_bond *bond);

/*
 * Bond import/export for backup, restore, and cross-machine migration (PC4).
 *
 * A single bond record is serialized into a versioned, self-describing binary
 * blob that carries the full key material (LTK/rand/EDIV, IRK, CSRK, sign
 * counter, is_sc/is_mitm/key_size) and metadata (name, GATT handle cache,
 * CCCDs) needed to reconstruct the bond on another host.  The record reuses the
 * same raw struct smp_bond layout the bond DB persists on disk, wrapped in a
 * magic + version + struct-size header so a decoder can length-gate before it
 * dereferences any field (Core Spec Vol 3 Part H §3.6 distributes exactly these
 * SMP keys; §2.4.5 the sign counter; Vol 3 Part G §2.4.5.1 the CCCDs).
 *
 * SECURITY: the record contains raw key bytes.  Callers gate export/import on
 * the privileged tier and never log the record contents.
 */
#define SMP_BOND_REC_MAGIC	"BREC"
#define SMP_BOND_REC_MAGIC_LEN	4
/* v2 adds the HOGP hid_ctrl_handle + multi-instance report-map handles. */
#define SMP_BOND_REC_VERSION	2
/* magic(4) + version(4 LE) + struct_size(4 LE) + raw struct smp_bond */
#define SMP_BOND_REC_HDR	(SMP_BOND_REC_MAGIC_LEN + 4 + 4)
#define SMP_BOND_REC_LEN	(SMP_BOND_REC_HDR + (size_t)sizeof(struct smp_bond))

/*
 * Serialize one bond into a portable export record.  Returns the number of
 * bytes written (== SMP_BOND_REC_LEN) on success, or 0 if the output buffer is
 * too small (no partial write).  Emits raw key material -- callers must gate.
 */
size_t	smp_bond_export_record(const struct smp_bond *bond, uint8_t *out,
	    size_t outsz);

/*
 * Parse and validate an export record produced by smp_bond_export_record().
 * Version-checked and length-gated (the record length must match exactly, so a
 * truncated or oversized blob is rejected before any field is read), then every
 * field is validated (address type, key size, CCCD/report counts, boolean
 * flags).  On success fills *out and returns 0.  On any failure returns -1 and
 * *out is left indeterminate -- the caller must discard it and leave the bond
 * DB untouched.
 */
int	smp_bond_import_record(const uint8_t *rec, size_t len,
	    struct smp_bond *out);

/*
 * Insert a fully-formed (already validated) bond into the database, matched by
 * identity address+type.  If a bond for that identity exists its whole record
 * is replaced in place -- a single struct assignment, so there is never a
 * window with no keys and no delete-then-insert.  Otherwise the bond is
 * appended, bounded by SMP_MAX_BONDS: a full DB is NOT evicted (a restore must
 * not silently drop another peer's keys) but rejected.  Persists the DB on
 * success.  The CALLER MUST HOLD the bond-DB lock (this does not lock, mirroring
 * the in-place bond edits in ctl.c).  Returns 0 if an existing bond was
 * replaced, 1 if a new bond was appended, -1 if the DB is full.
 */
int	smp_bond_db_import(struct smp_bond_db *db, const struct smp_bond *bond);

/*
 * Persist an advanced Signed-Write replay counter into the bond record.
 * Core Spec Vol 3 Part H §2.4.5 / erratum 26047: the accepted SignCounter
 * must survive reconnect so the replay window does not reset to the stale
 * stored value.  The ATT server calls this after accepting a signed write,
 * keyed by the peer CSRK it already holds (ac->peer_csrk).  Only updates the
 * bond when counter is strictly newer, then persists the DB.
 */
int	smp_bond_persist_sign_counter(struct smp_bond_db *db,
	    const uint8_t csrk[16], uint32_t counter);

/* Signed Write verification (Core Spec Vol 3 Part H §2.4.5) */
bool	smp_verify_signature(const uint8_t csrk[16], const uint8_t *msg,
	    size_t msg_len, const uint8_t mac[8], uint32_t counter);

/* Cross-Transport Key Derivation (Core Spec Vol 3 Part H §2.4.2.4) */
int	smp_ctkd_derive_link_key(struct smp_bond *bond, bool ct2);
/* Reverse direction, Core Spec Vol 3 Part H §2.4.2.5. */
int	smp_ctkd_derive_ltk(struct smp_bond *bond, bool ct2);

/* CCCD persistence for bonded devices (Core Spec Vol 3 Part G §2.4.5.1) */
struct att_conn;	/* forward declaration */
void	smp_bond_save_cccds(struct smp_bond *bond, const struct att_conn *ac);
void	smp_bond_restore_cccds(const struct smp_bond *bond, struct att_conn *ac);

#endif /* _BLUED_SMP_H_ */
