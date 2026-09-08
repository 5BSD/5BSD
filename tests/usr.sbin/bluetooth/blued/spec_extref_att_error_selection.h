/*
 * EXTERNAL REFERENCE ORACLE: ATT error-code selection for a denied service
 * request.
 *
 * Hand-written.  This is a decision table, not a block of sample data, so
 * there is nothing to extract mechanically.  Every value and every claim below
 * is traceable to a named external source; nothing here was derived from
 * blued, and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * docs/bluetooth-conformance.md ranks "which exact ATT error is returned for
 * each failure class" as the single largest uncovered requirement region
 * (items 1-6 of its ranked gap list).  The rule that governs it is NOT in the
 * ATT specification where a reader would look for it: Vol 3, Part F, Section
 * 3.2.5 states the permission rules independently and never addresses
 * precedence or the unencrypted case.  The governing text is in the GAP
 * specification, Vol 3, Part C, Section 10.3.1 and Table 10.2.
 *
 * The distinguishing input is NOT which permission bit the attribute carries.
 * It is whether a key (LTK or STK) EXISTS for the peer.  A table driven only
 * by permission bits gets the unencrypted row wrong in both directions.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 3, Part C, Section 10.3.1 (text lines 66576-66590), verbatim:
 *     "The local device's security database specifies the security settings
 *      required to accept a service request. If no encryption is required, the
 *      service request shall be accepted. If encryption is required the local
 *      device shall send an error code as defined in Table 10.2."
 *     "If neither an LTK nor an STK is available, the service request shall be
 *      rejected with the error code "Insufficient Authentication".
 *      Note: When the link is not encrypted, the error code "Insufficient
 *      Authentication" does not indicate that MITM protection is required."
 *     "If an LTK or an STK is available and encryption is required (LE security
 *      mode 1) but encryption is not enabled, the service request shall be
 *      rejected with the error code "Insufficient Encryption". If the
 *      encryption is enabled with a key size that is too short then the service
 *      request shall be rejected with the error code "Encryption Key Size Too
 *      Short.""
 *
 *   Vol 3, Part C, Section 10.3.1 (text lines 66591-66600), verbatim:
 *     "If an authenticated pairing is required but only an unauthenticated
 *      pairing has occurred and the link is currently encrypted, the service
 *      request shall be rejected with the error code "Insufficient
 *      Authentication.""
 *     "Note: When unauthenticated pairing has occurred and the link is
 *      currently encrypted, the error code "Insufficient Authentication"
 *      indicates that MITM protection is required."
 *     "If LE Secure Connections pairing is required but LE legacy pairing has
 *      occurred and the link is currently encrypted, the service request shall
 *      be rejected with the error code "Insufficient Authentication"."
 *
 *   Vol 3, Part C, Table 10.2 "Local device responds to a service request"
 *     (text lines 66617-66665).  Transcribed in full below.
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 *   Zephyr, github.com/zephyrproject-rtos/zephyr, snapshot commit
 *   2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/gatt.c:3211-3221 -- selects the code from the
 *     link's key state, not from the permission bit alone.
 *   Apache NimBLE, github.com/apache/mynewt-nimble, snapshot commit
 *   1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     nimble/host/src/ble_att_svr.c:303-322 -- performs a persistent-store LTK
 *     lookup specifically in order to choose between 0x05 and 0x0F.
 *   BlueZ, git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot commit
 *   92305dc06ab8a6d89af2dae1d725cc4d51462ad1:
 *     src/shared/gatt-server.c -- selects from the permission bits and does NOT
 *     consult key state.  BlueZ DIVERGES from the spec here.
 *
 * NOTE THE ASYMMETRY, IT IS THE POINT OF THIS FILE: two of the three
 * references implement the table, and the one that does not is the one 5BSD
 * was previously compared against.  A comparison against BlueZ alone cannot
 * detect an error in this area.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_ATT_ERROR_SELECTION_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_ATT_ERROR_SELECTION_H

#include <stdint.h>

/*
 * ATT error codes, Core 6.3, Vol 3, Part F, Table 3.4 (text lines 69820-69850).
 * Reproduced here so the table below is self-contained.
 */
#define BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION	0x05
#define BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHORIZATION	0x08
#define BT_EXTREF_ATT_ERR_ATTRIBUTE_NOT_LONG		0x0b
#define BT_EXTREF_ATT_ERR_ENCRYPTION_KEY_SIZE_TOO_SHORT	0x0c
#define BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION	0x0f

/* "Request succeeds" -- no error response is sent. */
#define BT_EXTREF_ATT_REQUEST_SUCCEEDS			0x00

/* The row selector: the local device's access requirement for the service. */
enum bt_extref_att_access_req {
	BT_EXTREF_ATT_ACCESS_NONE		= 0,
	BT_EXTREF_ATT_ACCESS_ENC_NO_MITM	= 1,
	BT_EXTREF_ATT_ACCESS_ENC_MITM		= 2,
	BT_EXTREF_ATT_ACCESS_ENC_MITM_SC	= 3
};

/*
 * The column selector: "Local Device Pairing Status".  Note that the first
 * column is a statement about KEY EXISTENCE, not about the current link.
 */
enum bt_extref_att_pairing_status {
	/* "No LTK No STK" */
	BT_EXTREF_ATT_PAIRING_NO_KEY		= 0,
	/*
	 * "Unauthenticated LTK (with or without LE Secure Connections) or
	 *  Unauthenticated STK"
	 */
	BT_EXTREF_ATT_PAIRING_UNAUTH		= 1,
	/*
	 * "Authenticated LTK without LE Secure Connections or Authenticated
	 *  STK"
	 */
	BT_EXTREF_ATT_PAIRING_AUTH_NO_SC	= 2,
	/* "Authenticated LTK with Secure Connections" */
	BT_EXTREF_ATT_PAIRING_AUTH_SC		= 3
};

/*
 * Table 10.2, UNENCRYPTED block (Core 6.3 text lines 66638-66653).
 *
 * Read this block carefully.  Across the whole block the MITM and Secure
 * Connections distinctions make NO difference to the error code -- all three
 * "Encryption..." rows are identical.  The only thing that varies is the
 * column, i.e. whether a key exists.  This is exactly the distinction that a
 * permission-bit-driven implementation does not make.
 *
 * Indexed [access requirement][pairing status].
 */
static const uint8_t bt_extref_att_err_unencrypted[4][4] = {
	/* None */
	{ BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS },
	/* Encryption, No MITM Protection */
	{ BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION },
	/* Encryption, MITM Protection */
	{ BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION },
	/* Encryption, MITM Protection, Secure Connections */
	{ BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_ENCRYPTION }
};

/*
 * Table 10.2, ENCRYPTED block (Core 6.3 text lines 66654-66664).
 *
 * Here, and ONLY here, does the MITM / Secure Connections distinction select
 * Insufficient Authentication.
 *
 * The [*][BT_EXTREF_ATT_PAIRING_NO_KEY] column is marked "N/A (Not possible to
 * be encrypted without LTK)" in the printed table.  It is encoded below as
 * 0xff, which is not a valid ATT error code, so that a test that reaches it is
 * asserting on an unreachable state and fails loudly rather than silently
 * comparing against a plausible-looking value.
 */
#define BT_EXTREF_ATT_TABLE_10_2_NOT_APPLICABLE		0xff

static const uint8_t bt_extref_att_err_encrypted[4][4] = {
	/* None */
	{ BT_EXTREF_ATT_TABLE_10_2_NOT_APPLICABLE,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS },
	/* Encryption, No MITM Protection */
	{ BT_EXTREF_ATT_TABLE_10_2_NOT_APPLICABLE,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS },
	/* Encryption, MITM Protection */
	{ BT_EXTREF_ATT_TABLE_10_2_NOT_APPLICABLE,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS },
	/* Encryption, MITM Protection, Secure Connections */
	{ BT_EXTREF_ATT_TABLE_10_2_NOT_APPLICABLE,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	  BT_EXTREF_ATT_REQUEST_SUCCEEDS }
};

/*
 * Key size.  Section 10.3.1 places this test only on the ENCRYPTED side: "If
 * the encryption is enabled with a key size that is too short then the service
 * request shall be rejected with the error code "Encryption Key Size Too
 * Short.""  There is no key-size error in the unencrypted block, because no
 * key size is in effect yet.  Set to 1 to record that ordering.
 */
#define BT_EXTREF_ATT_KEY_SIZE_CHECK_ONLY_WHEN_ENCRYPTED	1

/*
 * Which references implement Table 10.2.  1 = implements the table (selects on
 * key existence), 0 = selects on permission bits alone.
 *
 * Zephyr host/gatt.c:3211-3221; NimBLE ble_att_svr.c:303-322;
 * BlueZ src/shared/gatt-server.c.
 */
#define BT_EXTREF_ATT_ERRSEL_ZEPHYR_IMPLEMENTS_TABLE_10_2	1
#define BT_EXTREF_ATT_ERRSEL_NIMBLE_IMPLEMENTS_TABLE_10_2	1
#define BT_EXTREF_ATT_ERRSEL_BLUEZ_IMPLEMENTS_TABLE_10_2	0

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_ATT_ERROR_SELECTION_H */
