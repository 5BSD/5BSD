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
#define SMP_SIGNING_INFORMATION		0x0A	/* removed in BT 5.1; received and discarded */
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

/* Key distribution flags */
#define SMP_KEY_DIST_ENC_KEY		0x01	/* LTK + EDIV + Rand */
#define SMP_KEY_DIST_ID_KEY		0x02	/* IRK + Address */
#define SMP_KEY_DIST_SIGN_KEY		0x04	/* CSRK */

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
	uint16_t	report_handles[16];	/* Input/Output/Feature report value handles */
	uint16_t	report_cccd_handles[16]; /* Corresponding CCCD handles */
	uint8_t		report_types[16];	/* Report type (Input=1, Output=2, Feature=3) */
	uint8_t		report_ids[16];
	int		num_reports;
	uint16_t	battery_level_handle;
	uint16_t	battery_cccd_handle;
};

#define SMP_MAX_BONDS	32

struct smp_bond_db {
	struct smp_bond	bonds[SMP_MAX_BONDS];
	int		count;
	int		fd;		/* bond storage file fd */
	uint8_t		local_irk[16];	/* persisted local IRK for RPA resolution */
	bool		has_local_irk;	/* local_irk has been loaded or generated */
	uint8_t		local_csrk[16];	/* persisted local CSRK for Signed Writes */
	bool		has_local_csrk;	/* local_csrk has been loaded or generated */
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
	uint8_t		io_capability;	/* IO capability to use in pairing */
	uint8_t		min_key_size;	/* minimum encryption key size (7-16) */
	bool		sc_only;	/* reject legacy pairing if true */
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
void	smp_f4(const uint8_t u[32], const uint8_t v[32],
	    const uint8_t x[16], uint8_t z, uint8_t out[16]);
void	smp_f5(const uint8_t w[32], const uint8_t n1[16],
	    const uint8_t n2[16], const uint8_t a1[7],
	    const uint8_t a2[7], uint8_t mackey[16], uint8_t ltk[16]);
void	smp_f6(const uint8_t w[16], const uint8_t n1[16],
	    const uint8_t n2[16], const uint8_t r[16],
	    const uint8_t iocap[3], const uint8_t a1[7],
	    const uint8_t a2[7], uint8_t out[16]);
uint32_t smp_g2(const uint8_t u[32], const uint8_t v[32],
	    const uint8_t x[16], const uint8_t y[16]);
void	smp_h6(const uint8_t w[16], const uint8_t keyid[4],
	    uint8_t out[16]);
void	smp_h7(const uint8_t salt[16], const uint8_t w[16],
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

/* IO capability pairing method selection (Core Spec Vol 3 Part H §2.3.5.1) */
int	smp_select_model(uint8_t init_io, uint8_t resp_io, bool sc);

/* RPA resolution and generation (Core Spec Vol 3 Part H §2.2.2) */
bool	smp_rpa_matches(const uint8_t irk[16], const uint8_t addr[6]);
void	smp_generate_rpa(const uint8_t irk[16], uint8_t rpa[6]);

/* Bond persistence */
int	smp_bond_db_load(struct smp_bond_db *db, int fd);
int	smp_bond_db_save(struct smp_bond_db *db);
void	smp_bond_db_store(struct smp_bond_db *db, const struct smp_bond *bond);

/* Signed Write verification (Core Spec Vol 3 Part H §2.4.5) */
bool	smp_verify_signature(const uint8_t csrk[16], const uint8_t *msg,
	    size_t msg_len, const uint8_t mac[8], uint32_t counter);

/* Cross-Transport Key Derivation (Core Spec Vol 3 Part H §2.4.2.4) */
int	smp_ctkd_derive_link_key(struct smp_bond *bond, bool ct2);

/* CCCD persistence for bonded devices (Core Spec Vol 3 Part G §2.4.5.1) */
struct att_conn;	/* forward declaration */
void	smp_bond_save_cccds(struct smp_bond *bond, const struct att_conn *ac);
void	smp_bond_restore_cccds(const struct smp_bond *bond, struct att_conn *ac);

#endif /* _BLUED_SMP_H_ */
