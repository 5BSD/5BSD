/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BTLED_SMP_H_
#define _BTLED_SMP_H_

#include <stdint.h>
#include <stdbool.h>

/* SMP opcodes (Core Spec Vol 3 Part H Section 3.3) */
#define SMP_PAIRING_REQUEST		0x01
#define SMP_PAIRING_RESPONSE		0x02
#define SMP_PAIRING_CONFIRM		0x03
#define SMP_PAIRING_RANDOM		0x04
#define SMP_PAIRING_FAILED		0x05
#define SMP_ENCRYPTION_INFORMATION	0x06
#define SMP_MASTER_IDENTIFICATION	0x07
#define SMP_IDENTITY_INFORMATION	0x08
#define SMP_IDENTITY_ADDRESS_INFO	0x09
#define SMP_SIGNING_INFORMATION		0x0A
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

/* Auth request flags */
#define SMP_AUTH_BONDING		0x01
#define SMP_AUTH_MITM			0x04
#define SMP_AUTH_SC			0x08

/* Key distribution flags */
#define SMP_KEY_DIST_ENC_KEY		0x01	/* LTK + EDIV + Rand */
#define SMP_KEY_DIST_ID_KEY		0x02	/* IRK + Address */

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
	bool		has_ltk;
	bool		has_irk;
	bool		is_sc;		/* paired with LE Secure Connections */
};

#define SMP_MAX_BONDS	32

struct smp_bond_db {
	struct smp_bond	bonds[SMP_MAX_BONDS];
	int		count;
	int		fd;		/* bond storage file fd */
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
};

/* smp.c */
int	smp_open(struct smp_conn *sc, const uint8_t *addr, uint8_t addr_type,
	    const uint8_t *local_addr, uint8_t local_addr_type,
	    int hci_fd, uint16_t con_handle, struct smp_bond_db *db);
void	smp_close(struct smp_conn *sc);
int	smp_pair(struct smp_conn *sc);
int	smp_encrypt_with_ltk(struct smp_conn *sc, const struct smp_bond *bond);
struct smp_bond *smp_find_bond(struct smp_bond_db *db,
	    const uint8_t *addr, uint8_t addr_type);

/* Bond persistence */
int	smp_bond_db_load(struct smp_bond_db *db, int fd);
int	smp_bond_db_save(struct smp_bond_db *db);

#endif /* _BTLED_SMP_H_ */
