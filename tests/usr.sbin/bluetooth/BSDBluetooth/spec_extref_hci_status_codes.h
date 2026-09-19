/*
 * EXTERNAL REFERENCE ORACLE: HCI controller status codes, and which of them a
 * host must treat as "this controller lacks an optional capability" rather
 * than as a hard failure.
 *
 * Hand-written.  This is a decision table, not sample data.  Every value and
 * every claim below is traceable to a named external source; nothing here was
 * derived from blued, and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * The failure mode this table guards against is the one that makes a daemon
 * "work with one controller and not another": an OPTIONAL command is issued
 * unconditionally, the controller answers with a status meaning "I do not have
 * that", and the host treats the nonzero status as fatal and aborts a startup
 * or a connection that could have proceeded without the feature.
 *
 * Two distinct mechanisms are involved and they are easy to conflate:
 *
 *   (a) ASKING FIRST.  Vol 4, Part E, Section 7.4.2 defines
 *       HCI_Read_Local_Supported_Commands, a 64-octet bitmap with one bit per
 *       command.  This is the mechanism the references use to decide whether
 *       to issue an optional command at all.
 *
 *   (b) DEGRADING AFTER.  If a command is issued anyway, the status codes
 *       below distinguish "unsupported" from "genuinely broken".
 *
 * A host that does neither must treat EVERY nonzero status as fatal, which is
 * exactly the pattern that fails on one adapter and not another.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 1, Part F, Table 1.1 "List of possible error codes"
 *   (text lines 18848-18930).  Transcribed below.
 *
 *   Vol 1, Part F, Section 1 (text lines 18845-18847), verbatim:
 *     "A Host shall consider any error code that it does not explicitly
 *      understand equivalent to the error code Unspecified Error (0x1F)."
 *   -- note the direction: unknown codes degrade to 0x1F, they are NOT to be
 *   treated as success.
 *
 *   Vol 1, Part F, Section 2.1 "Unknown HCI Command (0x01)"
 *   (text lines 18951-18955), verbatim:
 *     "The Unknown HCI Command error code indicates that the Controller does
 *      not understand the HCI Command packet opcode that the Host sent. The
 *      opcode given might not correspond to any of the opcodes specified in
 *      this document, or any vendor-specific opcodes, or the command may have
 *      not been implemented."
 *   -- "or the command may have not been implemented" is the load-bearing
 *   clause: 0x01 is the specified way a controller says "optional command
 *   absent", so a host that maps 0x01 to a hard error is refusing the
 *   spec's own capability signal.
 *
 *   Vol 1, Part F, Section 2.2 "Unknown Connection Identifier (0x02)"
 *   (text lines 18956-18959), verbatim:
 *     "The Unknown Connection Identifier error code indicates that a command
 *      was sent from the Host that should identify a connection, but that
 *      connection does not exist or does not identify the correct type of
 *      connection."
 *   -- i.e. 0x02 means the link is already gone; it is an expected race on any
 *   per-connection command, not a controller fault.
 *
 * REFERENCE IMPLEMENTATIONS
 * -------------------------
 *   Zephyr, github.com/zephyrproject-rtos/zephyr, snapshot commit
 *   2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/hci_core.c:3609-3615 reads the Supported Commands
 *     bitmap into bt_dev.supported_commands; :3696 installs it during init.
 *     Every optional command is then gated on a bit test, e.g. :344 and :2254
 *     (BT_CMD_TEST(..., 10, 5)), :620 (27, 7), :3905 (41, 5), :5291 (27, 3).
 *     Zephyr therefore rarely has to interpret a failure status at all --
 *     it does not issue the command.
 *
 *   Apache NimBLE, github.com/apache/mynewt-nimble, snapshot commit
 *   1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     nimble/host/src/ble_hs_startup.c:53 reads Local Version Information and
 *     :411 calls it first in startup; ble_hs_hci.c:648
 *     (ble_hs_hci_get_hci_version) exposes it, and startup gates optional
 *     commands on the version (ble_hs_startup.c:206, :354, :424).  A DIFFERENT
 *     capability axis from Zephyr's, for the same purpose.
 *
 *   BlueZ, git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot commit
 *   92305dc06ab8a6d89af2dae1d725cc4d51462ad1:
 *     reads the same bitmap: tools/btinfo.c:140
 *     (BT_HCI_CMD_READ_LOCAL_COMMANDS), tools/hciconfig.c:1099
 *     (hci_read_local_commands), tools/hci-tester.c:278.  BlueZ's per-command
 *     gating for the managed adapter lives in the Linux kernel.
 *
 * ALL THREE REFERENCES QUERY A CAPABILITY AXIS BEFORE ISSUING OPTIONAL
 * COMMANDS.  They disagree about WHICH axis (Zephyr and BlueZ: the Supported
 * Commands bitmap; NimBLE: the HCI version).  They do not disagree about
 * whether to ask.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_HCI_STATUS_CODES_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_HCI_STATUS_CODES_H

#include <stdint.h>

/*
 * Core 6.3, Vol 1, Part F, Table 1.1, transcribed from text lines 18848-18930.
 * Only the codes in the range a 5.2 host can observe are given names here;
 * the table is complete through 0x48, which is the last assigned code.
 */
#define BT_EXTREF_HCI_SUCCESS					0x00
#define BT_EXTREF_HCI_ERR_UNKNOWN_HCI_COMMAND			0x01
#define BT_EXTREF_HCI_ERR_UNKNOWN_CONNECTION_IDENTIFIER		0x02
#define BT_EXTREF_HCI_ERR_HARDWARE_FAILURE			0x03
#define BT_EXTREF_HCI_ERR_PAGE_TIMEOUT				0x04
#define BT_EXTREF_HCI_ERR_AUTHENTICATION_FAILURE		0x05
#define BT_EXTREF_HCI_ERR_PIN_OR_KEY_MISSING			0x06
#define BT_EXTREF_HCI_ERR_MEMORY_CAPACITY_EXCEEDED		0x07
#define BT_EXTREF_HCI_ERR_CONNECTION_TIMEOUT			0x08
#define BT_EXTREF_HCI_ERR_CONNECTION_LIMIT_EXCEEDED		0x09
#define BT_EXTREF_HCI_ERR_SYNC_CONNECTION_LIMIT_EXCEEDED	0x0a
#define BT_EXTREF_HCI_ERR_CONNECTION_ALREADY_EXISTS		0x0b
#define BT_EXTREF_HCI_ERR_COMMAND_DISALLOWED			0x0c
#define BT_EXTREF_HCI_ERR_REJECTED_LIMITED_RESOURCES		0x0d
#define BT_EXTREF_HCI_ERR_REJECTED_SECURITY_REASONS		0x0e
#define BT_EXTREF_HCI_ERR_REJECTED_UNACCEPTABLE_BD_ADDR		0x0f
#define BT_EXTREF_HCI_ERR_CONNECTION_ACCEPT_TIMEOUT		0x10
#define BT_EXTREF_HCI_ERR_UNSUPPORTED_FEATURE_OR_PARAM		0x11
#define BT_EXTREF_HCI_ERR_INVALID_HCI_COMMAND_PARAMETERS	0x12
#define BT_EXTREF_HCI_ERR_REMOTE_USER_TERMINATED		0x13
#define BT_EXTREF_HCI_ERR_REMOTE_TERMINATED_LOW_RESOURCES	0x14
#define BT_EXTREF_HCI_ERR_REMOTE_TERMINATED_POWER_OFF		0x15
#define BT_EXTREF_HCI_ERR_TERMINATED_BY_LOCAL_HOST		0x16
#define BT_EXTREF_HCI_ERR_REPEATED_ATTEMPTS			0x17
#define BT_EXTREF_HCI_ERR_PAIRING_NOT_ALLOWED			0x18
#define BT_EXTREF_HCI_ERR_UNKNOWN_LMP_PDU			0x19
#define BT_EXTREF_HCI_ERR_UNSUPPORTED_REMOTE_FEATURE		0x1a
#define BT_EXTREF_HCI_ERR_INVALID_LMP_OR_LL_PARAMETERS		0x1e
#define BT_EXTREF_HCI_ERR_UNSPECIFIED_ERROR			0x1f
#define BT_EXTREF_HCI_ERR_UNSUPPORTED_LL_PARAMETER_VALUE	0x20
#define BT_EXTREF_HCI_ERR_LL_RESPONSE_TIMEOUT			0x22
#define BT_EXTREF_HCI_ERR_LL_PROCEDURE_COLLISION		0x23
#define BT_EXTREF_HCI_ERR_INSTANT_PASSED			0x28
#define BT_EXTREF_HCI_ERR_DIFFERENT_TRANSACTION_COLLISION	0x2a
#define BT_EXTREF_HCI_ERR_PARAMETER_OUT_OF_MANDATORY_RANGE	0x30
#define BT_EXTREF_HCI_ERR_CONTROLLER_BUSY			0x3a
#define BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS	0x3b
#define BT_EXTREF_HCI_ERR_ADVERTISING_TIMEOUT			0x3c
#define BT_EXTREF_HCI_ERR_CONNECTION_TERMINATED_MIC_FAILURE	0x3d
#define BT_EXTREF_HCI_ERR_CONNECTION_FAILED_TO_BE_ESTABLISHED	0x3e
#define BT_EXTREF_HCI_ERR_UNKNOWN_ADVERTISING_IDENTIFIER		0x42
#define BT_EXTREF_HCI_ERR_LIMIT_REACHED				0x43
#define BT_EXTREF_HCI_ERR_OPERATION_CANCELLED_BY_HOST		0x44

/* Last code assigned in Table 1.1 (Insufficient Channels). */
#define BT_EXTREF_HCI_ERR_LAST_ASSIGNED				0x48

/*
 * Vol 1, Part F, Section 1: a Host shall treat an error code it does not
 * understand as equivalent to Unspecified Error.  Encoded so a test can assert
 * the mapping rather than restate it.
 */
#define BT_EXTREF_HCI_UNKNOWN_CODE_MAPS_TO	BT_EXTREF_HCI_ERR_UNSPECIFIED_ERROR

/*
 * Disposition classes for a status returned to a command the host issued.
 * These name the ACTION a host should take; they are not spec terms, but each
 * assignment below is justified by the spec text quoted in the file header or
 * by the section cited alongside the row.
 */
enum bt_extref_hci_disposition {
	/* The command worked. */
	BT_EXTREF_HCI_DISP_OK			= 0,
	/*
	 * The controller lacks the capability.  The host should continue
	 * WITHOUT the feature.  Aborting here is the defect this table exists
	 * to catch.
	 */
	BT_EXTREF_HCI_DISP_DEGRADE		= 1,
	/*
	 * A transient condition tied to controller state or an in-flight
	 * procedure.  The host may retry, or retry after the blocking
	 * procedure completes.
	 */
	BT_EXTREF_HCI_DISP_RETRY		= 2,
	/*
	 * An expected race, normally "the object this command names is already
	 * gone".  The host should treat the command as moot, not as an error.
	 */
	BT_EXTREF_HCI_DISP_EXPECTED_RACE	= 3,
	/*
	 * A genuine fault: the host built a bad command, or the controller is
	 * broken.  This is the only class that justifies failing the operation
	 * outright.
	 */
	BT_EXTREF_HCI_DISP_FATAL		= 4
};

/*
 * The rows that matter for capability degradation, with the justification for
 * each disposition.
 */
struct bt_extref_hci_status_row {
	uint8_t				code;
	enum bt_extref_hci_disposition	disposition;
	const char			*why;
};

static const struct bt_extref_hci_status_row bt_extref_hci_status_table[] = {
	{ BT_EXTREF_HCI_SUCCESS, BT_EXTREF_HCI_DISP_OK,
	  "Vol 1 Part F Table 1.1: Success." },

	{ BT_EXTREF_HCI_ERR_UNKNOWN_HCI_COMMAND, BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 1 Part F 2.1: '...or the command may have not been "
	  "implemented.'  This is the specified signal for an absent optional "
	  "command; it is never a reason to abort." },

	{ BT_EXTREF_HCI_ERR_UNKNOWN_CONNECTION_IDENTIFIER,
	  BT_EXTREF_HCI_DISP_EXPECTED_RACE,
	  "Vol 1 Part F 2.2: the connection does not exist.  On any "
	  "per-connection command this races a Disconnection Complete that the "
	  "host has not processed yet." },

	{ BT_EXTREF_HCI_ERR_MEMORY_CAPACITY_EXCEEDED,
	  BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 4 Part E 7.8.38 (LE Add Device To Resolving List) returns this "
	  "when the resolving list is full.  The host should fall back to "
	  "host-side resolution for the excess entry, not fail." },

	{ BT_EXTREF_HCI_ERR_COMMAND_DISALLOWED, BT_EXTREF_HCI_DISP_RETRY,
	  "Vol 1 Part F 2.12: the command is not allowed in the controller's "
	  "current state.  Typically 'stop scanning/advertising first', which "
	  "the host can do and then retry." },

	{ BT_EXTREF_HCI_ERR_UNSUPPORTED_FEATURE_OR_PARAM,
	  BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 1 Part F 2.17: the controller understands the command but not "
	  "this feature or parameter value.  A host that offered an optional "
	  "parameter should retry without it or proceed without the feature." },

	{ BT_EXTREF_HCI_ERR_INVALID_HCI_COMMAND_PARAMETERS,
	  BT_EXTREF_HCI_DISP_FATAL,
	  "Vol 1 Part F 2.18: the host built a command the controller cannot "
	  "parse.  Unlike 0x11 this indicts the HOST, and is the status a "
	  "mis-encoded variable-length command produces." },

	{ BT_EXTREF_HCI_ERR_UNSUPPORTED_REMOTE_FEATURE,
	  BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 1 Part F 2.26: the PEER lacks the feature.  Also the code the "
	  "Link Layer sends when a procedure needed the Host but the "
	  "corresponding event was masked -- Vol 6 Part B 5.1.7.2." },

	{ BT_EXTREF_HCI_ERR_UNSUPPORTED_LL_PARAMETER_VALUE,
	  BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 6 Part B 5.1.7.2: the peer's Link Layer rejected the requested "
	  "parameters.  The procedure failed; the link did not." },

	{ BT_EXTREF_HCI_ERR_LL_PROCEDURE_COLLISION, BT_EXTREF_HCI_DISP_RETRY,
	  "Vol 6 Part B 5.3: two procedures collided.  Explicitly retryable "
	  "once the winning procedure completes." },

	{ BT_EXTREF_HCI_ERR_DIFFERENT_TRANSACTION_COLLISION,
	  BT_EXTREF_HCI_DISP_RETRY,
	  "Vol 1 Part F 2.42: collision with a different transaction; retry." },

	{ BT_EXTREF_HCI_ERR_CONTROLLER_BUSY, BT_EXTREF_HCI_DISP_RETRY,
	  "Vol 1 Part F 2.58: the controller is busy and cannot process the "
	  "command now.  Retry is the specified remedy." },

	{ BT_EXTREF_HCI_ERR_UNACCEPTABLE_CONNECTION_PARAMETERS,
	  BT_EXTREF_HCI_DISP_DEGRADE,
	  "Vol 6 Part B 5.1.7.2: the peer's Host rejected the requested "
	  "connection parameters.  The existing parameters remain in force." },

	{ BT_EXTREF_HCI_ERR_UNKNOWN_ADVERTISING_IDENTIFIER,
	  BT_EXTREF_HCI_DISP_EXPECTED_RACE,
	  "Vol 4 Part E 7.8.60: the advertising handle is not in use.  On a "
	  "removal or disable this means the work is already done." },

	{ BT_EXTREF_HCI_ERR_HARDWARE_FAILURE, BT_EXTREF_HCI_DISP_FATAL,
	  "Vol 1 Part F 2.3: the controller has failed." },

	{ BT_EXTREF_HCI_ERR_UNSPECIFIED_ERROR, BT_EXTREF_HCI_DISP_FATAL,
	  "Vol 1 Part F 2.31, and the mandated mapping for any code the host "
	  "does not understand (Vol 1 Part F 1)." }
};

#define BT_EXTREF_HCI_STATUS_TABLE_LEN \
	(sizeof(bt_extref_hci_status_table) / \
	 sizeof(bt_extref_hci_status_table[0]))

/*
 * Whether the reference reads a capability axis before issuing an optional
 * command, and which one.  0 = no query in this tree, 1 = HCI version,
 * 2 = Supported Commands bitmap.
 *
 * Vol 4, Part E, Section 7.4.2 is the Supported Commands bitmap;
 * Section 7.4.1 is Local Version Information.
 */
#define BT_EXTREF_HCI_CAPQUERY_ZEPHYR	2	/* hci_core.c:3609-3615, :3696 */
#define BT_EXTREF_HCI_CAPQUERY_NIMBLE	1	/* ble_hs_startup.c:53, :411 */
#define BT_EXTREF_HCI_CAPQUERY_BLUEZ	2	/* btinfo.c:140, hciconfig.c:1099 */

/* OCFs of the two capability queries, OGF 0x04 (Informational Parameters). */
#define BT_EXTREF_HCI_OCF_READ_LOCAL_VERSION_INFORMATION	0x0001
#define BT_EXTREF_HCI_OCF_READ_LOCAL_SUPPORTED_COMMANDS	0x0002

/* Size of the Supported_Commands return parameter, Vol 4 Part E 7.4.2. */
#define BT_EXTREF_HCI_SUPPORTED_COMMANDS_OCTETS		64

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_HCI_STATUS_CODES_H */
