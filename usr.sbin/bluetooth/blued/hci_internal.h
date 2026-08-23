/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_HCI_INTERNAL_H_
#define _BLUED_HCI_INTERNAL_H_

/*
 * Internal declarations shared between the hci_*.c translation units
 * that were split from the original hci_util.c.
 *
 * Nothing in this header is part of the public API — consumers of
 * HCI utilities should include "hci_util.h" only.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

struct ble_scan_result;
struct bt_devreq;

/* Core 6.3 Vol 4, Part E, Section 7.7.8: 12 meaningful bits, 0x0000-0x0EFF. */
#define BLUED_HCI_CONNECTION_HANDLE_MAX	0x0eff

/* Core 6.3 Vol 4, Part E, Section 7.7.8 Encryption_Key_Size range. */
#define BLUED_HCI_ENCRYPTION_KEY_SIZE_MIN	7
#define BLUED_HCI_ENCRYPTION_KEY_SIZE_MAX	16

/* Core 6.3 Vol 4, Part E, Section 7.3.69 Event_Mask_Page_2. */
#define BLUED_HCI_OCF_SET_EVENT_MASK_PAGE_2	0x0063
#define BLUED_HCI_EVENT_MASK_PAGE2_APTO		(UINT64_C(1) << 23)
#define BLUED_HCI_EVENT_MASK_PAGE2_ENCRYPTION_V2	(UINT64_C(1) << 25)
#define BLUED_HCI_EVENT_MASK_PAGE2_DEFAULT		\
	(BLUED_HCI_EVENT_MASK_PAGE2_APTO |		\
	 BLUED_HCI_EVENT_MASK_PAGE2_ENCRYPTION_V2)

/*
 * Advertising-report parsers (defined in hci_scan.c).  Exposed here --
 * rather than kept file-static -- so the unit tests and fuzz harnesses
 * can drive them directly on attacker-controlled advertising bytes.
 *
 * hci_parse_ad:              walk one AD structure (length/type/value).
 * hci_parse_ad_fields:       extract name/manufacturer/UUIDs from AD data.
 * hci_parse_ext_adv_report:  parse one LE Extended Advertising Report.
 */
const uint8_t *hci_parse_ad(const uint8_t *data, size_t len, uint8_t *type,
    const uint8_t **value, uint8_t *vlen);
void	hci_parse_ad_fields(const uint8_t *ad, size_t ad_len,
	    struct ble_scan_result *sr);
size_t	hci_parse_ext_adv_report(const uint8_t *p, size_t remain,
	    struct ble_scan_result *sr);

/*
 * Select the own_address_type used by the Observer/Central scan roles
 * (defined in hci_scan.c).  0x00 = public identity; 0x02 = Resolvable
 * Private Address with public fallback, used when LE privacy is enabled
 * so scanning does not transmit the public identity address.
 */
void	hci_scan_set_own_address_type(int hci_fd, uint8_t own_addr_type);

/*
 * Mutex protecting the shared HCI socket fd against concurrent
 * bt_devreq / bt_devrecv callers from different threads.
 */
pthread_mutex_t *hci_devreq_mutex(int fd);

/*
 * Internal bt_devreq wrapper with BTSnoop logging.
 * Caller must hold hci_mtx.
 */
int	hci_devreq_logged_locked(int fd, struct bt_devreq *r, int timeout);

/*
 * Wrapper around bt_devreq() that logs outgoing HCI commands and
 * their responses to BTSnoop when capture is active.
 * Serialises all HCI command/response pairs through hci_mtx.
 */
int	hci_devreq_logged(int fd, struct bt_devreq *r, int timeout);

/*
 * HCI Set Event Mask Page 2 (Core Spec Vol 4 Part E Section 7.3.69).
 * Implemented in hci_misc.c; page-2 bit 23 is Authenticated Payload
 * Timeout Expired.  Declared here (not in hci_util.h) because it is
 * programmed once at adapter init alongside the page-1 mask.
 */
int	hci_set_event_mask_page2(int hci_fd, uint64_t mask);

/* ----------------------------------------------------------------
 * LE Isochronous (ISO) control-plane callers (BT 5.2).
 *
 * The ISO command encoders in hci_misc.c (LE Set CIG Parameters,
 * LE Setup ISO Data Path, ...) carry the on-wire byte layout; these
 * higher-level callers build spec-legal parameter blocks and drive
 * those encoders so a CIG/CIS/BIG reaches an established state with a
 * data path.  blued owns the raw HCI control socket, so CIG
 * provisioning and ISO data-path setup are daemon responsibilities;
 * the kernel ISO socket (ng_btsocket_iso) is the data plane only.
 * Declared here (not in hci_util.h) because they are daemon-internal
 * orchestration over the public encoders.
 * Core Spec Vol 4 Part E §7.8.97, §7.8.109.
 * ---------------------------------------------------------------- */

/* Data_Path_Direction, §7.8.109. */
#define HCI_ISO_DIR_INPUT	0x00	/* Host -> Controller (source) */
#define HCI_ISO_DIR_OUTPUT	0x01	/* Controller -> Host (sink) */
/*
 * Remove ISO Data Path (Core 6.3 Vol 4 Part E Section 7.8.110) takes a
 * Data_Path_Direction BITMASK, not the Setup ISO Data Path enum above:
 * bit0 = remove input path, bit1 = remove output path (0x00 is invalid).
 */
#define HCI_ISO_REMOVE_INPUT	0x01
#define HCI_ISO_REMOVE_OUTPUT	0x02

/* Data_Path_ID 0x00 routes ISO data over the HCI transport, §7.8.109. */
#define HCI_ISO_PATH_HCI	0x00

/*
 * One per-CIS configuration record for LE Set CIG Parameters (§7.8.97).
 * hci_le_setup_cig() serialises an array of these into the 9-octet
 * per-CIS wire records the command carries.
 */
struct hci_cis_param {
	uint8_t		cis_id;
	uint16_t	max_sdu_c_to_p;
	uint16_t	max_sdu_p_to_c;
	uint8_t		phy_c_to_p;
	uint8_t		phy_p_to_c;
	uint8_t		rtn_c_to_p;
	uint8_t		rtn_p_to_c;
};

/*
 * Provision a CIG: serialise the per-CIS records and issue LE Set CIG
 * Parameters (§7.8.97).  Returns the assigned CIG_ID, CIS_Count and the
 * per-CIS connection handles the Controller allocated.
 */
int	hci_le_setup_cig(int hci_fd, uint8_t cig_id,
	    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
	    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
	    uint16_t max_latency_c, uint16_t max_latency_p,
	    uint8_t cis_count, const struct hci_cis_param *cises,
	    uint8_t *out_cig_id, uint8_t *out_cis_count,
	    uint16_t *out_cis_handles);

/*
 * Set up an HCI-transport ISO data path on an established CIS/BIS handle
 * in one direction: Data_Path_ID 0x00 (HCI), Transparent coding format,
 * zero controller delay, no codec configuration (§7.8.109).
 */
int	hci_le_setup_iso_hci_path(int hci_fd, uint16_t con_handle,
	    uint8_t direction);

/*
 * Kind of established isochronous stream, selecting which data-path
 * direction(s) to set up on it once the corresponding lifecycle event
 * (LE CIS Established / Create BIG Complete / BIG Sync Established)
 * arrives.
 */
enum hci_iso_stream_kind {
	HCI_ISO_STREAM_CIS,		/* bidirectional: input + output */
	HCI_ISO_STREAM_BIS_SOURCE,	/* broadcaster: input (Host->Ctlr) */
	HCI_ISO_STREAM_BIS_SINK,	/* synchronized rx: output (Ctlr->Host) */
};

/*
 * Set up the HCI-transport ISO data path(s) appropriate to a newly
 * established isochronous stream.  Returns the number of directions
 * successfully set up (0 on total failure), so a partial CIS (one
 * direction unconfigured) still reports progress (§7.8.109).
 */
int	hci_le_setup_iso_stream_paths(int hci_fd, uint16_t con_handle,
	    enum hci_iso_stream_kind kind);

#endif /* _BLUED_HCI_INTERNAL_H_ */
