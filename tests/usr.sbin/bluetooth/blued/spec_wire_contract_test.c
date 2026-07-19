/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Independent Bluetooth wire-contract oracles.
 *
 * The expected values in this file are literals transcribed from Bluetooth
 * Core Specification 6.3.  Do not replace them with aliases from the headers:
 * the purpose of this test is to catch a shared error between those headers
 * and tests of code that consumes them.
 *
 * ATT:   Vol 3, Part F, Table 3.1 and Table 3.4.
 * SMP:   Vol 3, Part H, Sections 3.3, 3.5.5, 3.5.8 and 3.6.1.
 * L2CAP: Vol 3, Part A, Sections 2.1, 4.1, 4.22, 4.24, 4.25 and 4.27.
 * HCI:   Vol 4, Part E, Sections 5.4, 7.7 and 7.8.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stddef.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "hci_internal.h"
#include "hci_util.h"
#include "smp.h"
#include "spec_oracles.h"

#define CHECK_LITERAL(symbol, literal) \
	ATF_CHECK_EQ_MSG((literal), (symbol), #symbol " differs from the spec")
#define CHECK_SPEC_ORACLE(symbol, literal) CHECK_LITERAL(symbol, literal);

ATF_TC_WITHOUT_HEAD(att_wire_literals);
ATF_TC_BODY(att_wire_literals, tc)
{
	BT_CORE63_ATT_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_ATT_ERROR_ORACLES(CHECK_SPEC_ORACLE)
}

/*
 * Removed-feature compatibility values are not current ATT/GATT features.
 * Core 6.3 Vol 1 Part E §2.4.2 defines "Previously used"; Vol 3 Part F
 * Table 3.42 identifies opcode 0xD2, Vol 3 Part G Table 3.5 identifies
 * Characteristic Properties bit 0x40, Vol 3 Part H Table 3.3/Figure 3.11
 * identify SMP 0x0A/key bit 0x04, and Vol 3 Part A Table 2.1 identifies CID
 * 0x0003 that way.  Keeping these separate stops legacy support from being
 * mistaken for a current-Core normative oracle.
 */
ATF_TC_WITHOUT_HEAD(legacy_removed_values);
ATF_TC_BODY(legacy_removed_values, tc)
{
	BT_CORE63_PREVIOUSLY_USED_ORACLES(CHECK_SPEC_ORACLE)
}

ATF_TC_WITHOUT_HEAD(smp_wire_literals);
ATF_TC_BODY(smp_wire_literals, tc)
{
	BT_CORE63_SMP_COMMAND_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_SMP_FAILURE_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_SMP_KEY_DIST_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_SMP_SCALAR_ORACLES(CHECK_SPEC_ORACLE)
	CHECK_LITERAL(SMP_RANDOM_ADDRESS_TYPE_MASK,
	    BT_CORE63_RANDOM_ADDRESS_TYPE_MASK);
	CHECK_LITERAL(SMP_RANDOM_ADDRESS_RESOLVABLE,
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE);
	CHECK_LITERAL(SMP_ID_ADDR_PUBLIC, BT_CORE63_SMP_ID_ADDR_PUBLIC);
	CHECK_LITERAL(SMP_ID_ADDR_STATIC_RANDOM,
	    BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM);
}

/* Core 6.3 Vol 3 Part G §3.3.1.1, Table 3.5. */
ATF_TC_WITHOUT_HEAD(gatt_characteristic_property_literals);
ATF_TC_BODY(gatt_characteristic_property_literals, tc)
{
	BT_CORE63_GATT_PROPERTY_ORACLES(CHECK_SPEC_ORACLE)
}

ATF_TC_WITHOUT_HEAD(l2cap_wire_literals);
ATF_TC_BODY(l2cap_wire_literals, tc)
{

	BT_CORE63_L2CAP_CID_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_L2CAP_COMMAND_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_L2CAP_RESULT_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_L2CAP_RECONFIG_RESULT_ORACLES(CHECK_SPEC_ORACLE)
	BT_ASSIGNED_EATT_PSM_ORACLES(CHECK_SPEC_ORACLE)

	/* Core 6.3 Vol 3 Part A §§4.22, 4.24, 4.25, 4.27 wire sizes. */
	CHECK_LITERAL(sizeof(ng_l2cap_le_credit_con_req_cp),
	    BT_CORE63_L2CAP_LE_CREDIT_CON_REQ_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_le_credit_con_rsp_cp),
	    BT_CORE63_L2CAP_LE_CREDIT_CON_RSP_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_flow_control_credit_cp),
	    BT_CORE63_L2CAP_FLOW_CREDIT_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_credit_con_req_cp),
	    BT_CORE63_L2CAP_CREDIT_CON_REQ_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_credit_con_rsp_cp),
	    BT_CORE63_L2CAP_CREDIT_CON_RSP_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_credit_reconfig_req_cp),
	    BT_CORE63_L2CAP_RECONFIG_REQ_SIZE);
	CHECK_LITERAL(sizeof(ng_l2cap_credit_reconfig_rsp_cp),
	    BT_CORE63_L2CAP_RECONFIG_RSP_SIZE);
}

ATF_TC_WITHOUT_HEAD(hci_wire_literals);
ATF_TC_BODY(hci_wire_literals, tc)
{

	BT_CORE63_HCI_PACKET_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_HCI_EVENT_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_HCI_LE_SUBEVENT_ORACLES(CHECK_SPEC_ORACLE)
	BT_CORE63_HCI_COMMAND_ORACLES(CHECK_SPEC_ORACLE)
	CHECK_LITERAL(BLUED_HCI_CONNECTION_HANDLE_MAX,
	    BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX);
	CHECK_LITERAL(BLUED_HCI_EVENT_MASK_PAGE2_DEFAULT,
	    BT_CORE63_HCI_EVENT_MASK_PAGE2_DEFAULT);
	CHECK_LITERAL(BLUED_HCI_OCF_SET_EVENT_MASK_PAGE_2,
	    BT_CORE63_HCI_SET_EVENT_MASK_PAGE2_OCF);
	CHECK_LITERAL(LE_FEAT_ENCRYPTION, BT_CORE63_LE_FEAT_ENCRYPTION);
	CHECK_LITERAL(LE_FEAT_CONN_PARAM_REQ, BT_CORE63_LE_FEAT_CONN_PARAM_REQ);
	CHECK_LITERAL(LE_FEAT_2M_PHY, BT_CORE63_LE_FEAT_2M_PHY);
	CHECK_LITERAL(LE_FEAT_CONN_CTE_REQ, BT_CORE63_LE_FEAT_CONN_CTE_REQ);
	CHECK_LITERAL(LE_FEAT_CONNLESS_CTE_RX,
	    BT_CORE63_LE_FEAT_CONNLESS_CTE_RX);
	CHECK_LITERAL(LE_FEAT_POWER_CONTROL, BT_CORE63_LE_FEAT_POWER_CONTROL);
	CHECK_LITERAL(LE_FEAT_PATH_LOSS_MONITORING,
	    BT_CORE63_LE_FEAT_PATH_LOSS_MONITORING);
	CHECK_LITERAL(LE_FEAT_CONN_SUBRATING,
	    BT_CORE63_LE_FEAT_CONN_SUBRATING);
	CHECK_LITERAL(LE_EVTMASK_CONNLESS_IQ_REPORT,
	    BT_CORE63_LE_EVTMASK_CONNLESS_IQ_REPORT);
	CHECK_LITERAL(LE_EVTMASK_CONN_IQ_REPORT,
	    BT_CORE63_LE_EVTMASK_CONN_IQ_REPORT);
	CHECK_LITERAL(LE_EVTMASK_CTE_REQ_FAILED,
	    BT_CORE63_LE_EVTMASK_CTE_REQ_FAILED);
	CHECK_LITERAL(LE_EVTMASK_PATH_LOSS_THRESH,
	    BT_CORE63_LE_EVTMASK_PATH_LOSS_THRESH);
	CHECK_LITERAL(LE_EVTMASK_TX_POWER_REPORT,
	    BT_CORE63_LE_EVTMASK_TX_POWER_REPORT);
	CHECK_LITERAL(LE_EVTMASK_SUBRATE_CHANGE,
	    BT_CORE63_LE_EVTMASK_SUBRATE_CHANGE);
	CHECK_LITERAL(BLE_SCAN_ADDR_ANONYMOUS,
	    BT_CORE63_EXT_ADV_ADDR_ANONYMOUS);
	CHECK_LITERAL(NG_HCI_OCF_LE_SET_SCAN_PARAMETERS,
	    BT_CORE63_LE_SET_SCAN_PARAMETERS_OCF);
	CHECK_LITERAL(sizeof(ng_hci_le_set_scan_parameters_cp),
	    BT_CORE63_LE_SCAN_PARAMETERS_SIZE);
	CHECK_LITERAL(BLUED_HCI_OWN_ADDR_PUBLIC,
	    BT_CORE63_LE_OWN_ADDR_PUBLIC);
	CHECK_LITERAL(BLUED_HCI_OWN_ADDR_RANDOM,
	    BT_CORE63_LE_OWN_ADDR_RANDOM);
	CHECK_LITERAL(BLUED_HCI_OWN_ADDR_RPA_PUBLIC_FALLBACK,
	    BT_CORE63_LE_OWN_ADDR_RPA_PUBLIC_FALLBACK);
	CHECK_LITERAL(BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK,
	    BT_CORE63_LE_OWN_ADDR_RPA_RANDOM_FALLBACK);
	CHECK_LITERAL(NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS,
	    BT_CORE63_LE_SET_ADV_PARAMETERS_OCF);
	CHECK_LITERAL(sizeof(ng_hci_le_set_advertising_parameters_cp),
	    BT_CORE63_LE_ADV_PARAMETERS_SIZE);
	CHECK_LITERAL(offsetof(ng_hci_le_set_advertising_parameters_cp,
	    advertising_type), BT_CORE63_LE_ADV_TYPE_OFFSET);
	CHECK_LITERAL(offsetof(ng_hci_le_set_advertising_parameters_cp,
	    direct_address_type), BT_CORE63_LE_ADV_PEER_ADDRESS_TYPE_OFFSET);
	CHECK_LITERAL(offsetof(ng_hci_le_set_advertising_parameters_cp,
	    direct_address), BT_CORE63_LE_ADV_PEER_ADDRESS_OFFSET);
	CHECK_LITERAL(sizeof(ng_hci_le_set_ext_adv_params_cp),
	    BT_CORE63_LE_EXT_ADV_PARAMETERS_SIZE);
	CHECK_LITERAL(offsetof(ng_hci_le_set_ext_adv_params_cp,
	    advertising_event_properties),
	    BT_CORE63_LE_EXT_ADV_EVENT_PROPERTIES_OFFSET);
	CHECK_LITERAL(offsetof(ng_hci_le_set_ext_adv_params_cp,
	    peer_address_type), BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_TYPE_OFFSET);
	CHECK_LITERAL(offsetof(ng_hci_le_set_ext_adv_params_cp, peer_address),
	    BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_OFFSET);
	CHECK_LITERAL(BLUED_HCI_ADV_TYPE_UNDIRECTED,
	    BT_CORE63_LE_ADV_TYPE_UNDIRECTED);
	CHECK_LITERAL(BLUED_HCI_ADV_TYPE_DIRECTED_HIGH,
	    BT_CORE63_LE_ADV_TYPE_DIRECTED_HIGH);
	CHECK_LITERAL(BLUED_HCI_ADV_TYPE_DIRECTED_LOW,
	    BT_CORE63_LE_ADV_TYPE_DIRECTED_LOW);
	CHECK_LITERAL(BLUED_HCI_EXT_ADV_PROP_CONNECTABLE,
	    BT_CORE63_LE_EXT_ADV_PROP_CONNECTABLE);
	CHECK_LITERAL(BLUED_HCI_EXT_ADV_PROP_DIRECTED,
	    BT_CORE63_LE_EXT_ADV_PROP_DIRECTED);
	CHECK_LITERAL(BLUED_HCI_EXT_ADV_PROP_HIGH_DUTY_DIRECTED,
	    BT_CORE63_LE_EXT_ADV_PROP_HIGH_DUTY_DIRECTED);
	CHECK_LITERAL(BLUED_HCI_EXT_ADV_PROP_LEGACY,
	    BT_CORE63_LE_EXT_ADV_PROP_LEGACY);
	CHECK_LITERAL(BLUED_HCI_EXT_ADV_PROP_ANONYMOUS,
	    BT_CORE63_LE_EXT_ADV_PROP_ANONYMOUS);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, att_wire_literals);
	ATF_TP_ADD_TC(tp, legacy_removed_values);
	ATF_TP_ADD_TC(tp, smp_wire_literals);
	ATF_TP_ADD_TC(tp, gatt_characteristic_property_literals);
	ATF_TP_ADD_TC(tp, l2cap_wire_literals);
	ATF_TP_ADD_TC(tp, hci_wire_literals);
	return (atf_no_error());
}
