# Generate test-only C oracles directly from the Bluetooth Core 6.3 text.
# The implementation-symbol mapping contains names only; all values are parsed
# from the normative tables and validated before output.

function hex2dec(s,    i, c, n, digits) {
	digits = "0123456789ABCDEF"
	s = toupper(substr(s, 3))
	n = 0
	for (i = 1; i <= length(s); i++) {
		c = index(digits, substr(s, i, 1)) - 1
		n = n * 16 + c
	}
	return n
}

function vec_all_hex(from,    i) {
	for (i = from; i <= NF; i++)
		if ($i !~ /^[0-9A-Fa-f]+$/)
			return 0
	return NF >= from
}

function vec_add(key, from, expected,    i) {
	for (i = from; i <= NF; i++)
		vector[key] = vector[key] tolower($i)
	if (length(vector[key]) < expected) {
		vector_pending = key
		vector_expected = expected
	} else if (length(vector[key]) == expected) {
		vector_pending = ""
		vector_expected = 0
	} else {
		print "overlong Core vector " key > "/dev/stderr"
		exit 1
	}
}

function nth_hex(line, wanted,    rest, found, value) {
	rest = line
	found = 0
	while (match(rest, /0x[0-9A-Fa-f]+/)) {
		found++
		value = substr(rest, RSTART + 2, RLENGTH - 2)
		if (found == wanted)
			return tolower(value)
		rest = substr(rest, RSTART + RLENGTH)
	}
	return ""
}

function assoc_parse_base(row, line,    rest, count, token) {
	rest = line
	while (match(rest, /(Just Works|Passkey Entry|Passkey En-)/)) {
		token = substr(rest, RSTART, RLENGTH)
		count++
		assoc_legacy[row, count] = (token == "Just Works" ? 0 : 1)
		assoc_sc[row, count] = assoc_legacy[row, count]
		rest = substr(rest, RSTART + RLENGTH)
	}
	assoc_count[row] = count
}

BEGIN {
	err_symbol[1] = "ATT_ERR_INVALID_HANDLE"
	err_symbol[2] = "ATT_ERR_READ_NOT_PERMITTED"
	err_symbol[3] = "ATT_ERR_WRITE_NOT_PERMITTED"
	err_symbol[4] = "ATT_ERR_INVALID_PDU"
	err_symbol[5] = "ATT_ERR_INSUFF_AUTHEN"
	err_symbol[6] = "ATT_ERR_REQ_NOT_SUPPORTED"
	err_symbol[7] = "ATT_ERR_INVALID_OFFSET"
	err_symbol[8] = "ATT_ERR_INSUFF_AUTHOR"
	err_symbol[9] = "ATT_ERR_PREPARE_QUEUE_FULL"
	err_symbol[10] = "ATT_ERR_ATTR_NOT_FOUND"
	err_symbol[11] = "ATT_ERR_ATTR_NOT_LONG"
	err_symbol[12] = "ATT_ERR_INSUFF_ENC_KEY_SIZE"
	err_symbol[13] = "ATT_ERR_INVALID_ATTR_LEN"
	err_symbol[14] = "ATT_ERR_UNLIKELY_ERROR"
	err_symbol[15] = "ATT_ERR_INSUFF_ENCRYPTION"
	err_symbol[16] = "ATT_ERR_UNSUPPORTED_GROUP_TYPE"
	err_symbol[17] = "ATT_ERR_INSUFF_RESOURCES"
	err_symbol[18] = "ATT_ERR_DATABASE_OUT_OF_SYNC"
	err_symbol[19] = "ATT_ERR_VALUE_NOT_ALLOWED"

	att_map["ATT_ERROR_RSP"] = "ATT_OP_ERROR_RSP"
	att_map["ATT_EXCHANGE_MTU_REQ"] = "ATT_OP_MTU_REQ"
	att_map["ATT_EXCHANGE_MTU_RSP"] = "ATT_OP_MTU_RSP"
	att_map["ATT_FIND_INFORMATION_REQ"] = "ATT_OP_FIND_INFO_REQ"
	att_map["ATT_FIND_INFORMATION_RSP"] = "ATT_OP_FIND_INFO_RSP"
	att_map["ATT_FIND_BY_TYPE_VALUE_REQ"] = "ATT_OP_FIND_BY_TYPE_VALUE_REQ"
	att_map["ATT_FIND_BY_TYPE_VALUE_RSP"] = "ATT_OP_FIND_BY_TYPE_VALUE_RSP"
	att_map["ATT_READ_BY_TYPE_REQ"] = "ATT_OP_READ_BY_TYPE_REQ"
	att_map["ATT_READ_BY_TYPE_RSP"] = "ATT_OP_READ_BY_TYPE_RSP"
	att_map["ATT_READ_REQ"] = "ATT_OP_READ_REQ"
	att_map["ATT_READ_RSP"] = "ATT_OP_READ_RSP"
	att_map["ATT_READ_BLOB_REQ"] = "ATT_OP_READ_BLOB_REQ"
	att_map["ATT_READ_BLOB_RSP"] = "ATT_OP_READ_BLOB_RSP"
	att_map["ATT_READ_MULTIPLE_REQ"] = "ATT_OP_READ_MULTIPLE_REQ"
	att_map["ATT_READ_MULTIPLE_RSP"] = "ATT_OP_READ_MULTIPLE_RSP"
	att_map["ATT_READ_BY_GROUP_TYPE_REQ"] = "ATT_OP_READ_BY_GROUP_TYPE_REQ"
	att_map["ATT_READ_BY_GROUP_TYPE_RSP"] = "ATT_OP_READ_BY_GROUP_TYPE_RSP"
	att_map["ATT_WRITE_REQ"] = "ATT_OP_WRITE_REQ"
	att_map["ATT_WRITE_RSP"] = "ATT_OP_WRITE_RSP"
	att_map["ATT_WRITE_CMD"] = "ATT_OP_WRITE_CMD"
	att_map["ATT_PREPARE_WRITE_REQ"] = "ATT_OP_PREPARE_WRITE_REQ"
	att_map["ATT_PREPARE_WRITE_RSP"] = "ATT_OP_PREPARE_WRITE_RSP"
	att_map["ATT_EXECUTE_WRITE_REQ"] = "ATT_OP_EXECUTE_WRITE_REQ"
	att_map["ATT_EXECUTE_WRITE_RSP"] = "ATT_OP_EXECUTE_WRITE_RSP"
	att_map["ATT_READ_MULTIPLE_VARIABLE_REQ"] = "ATT_OP_READ_MULTIPLE_VARIABLE_REQ"
	att_map["ATT_READ_MULTIPLE_VARIABLE_RSP"] = "ATT_OP_READ_MULTIPLE_VARIABLE_RSP"
	att_map["ATT_MULTIPLE_HANDLE_VALUE_NTF"] = "ATT_OP_MULTIPLE_HANDLE_VALUE_NTF"
	att_map["ATT_HANDLE_VALUE_NTF"] = "ATT_OP_HANDLE_NOTIFY"
	att_map["ATT_HANDLE_VALUE_IND"] = "ATT_OP_HANDLE_IND"
	att_map["ATT_HANDLE_VALUE_CFM"] = "ATT_OP_HANDLE_CFM"

	smp_command_symbol[1] = "SMP_PAIRING_REQUEST"
	smp_command_symbol[2] = "SMP_PAIRING_RESPONSE"
	smp_command_symbol[3] = "SMP_PAIRING_CONFIRM"
	smp_command_symbol[4] = "SMP_PAIRING_RANDOM"
	smp_command_symbol[5] = "SMP_PAIRING_FAILED"
	smp_command_symbol[6] = "SMP_ENCRYPTION_INFORMATION"
	smp_command_symbol[7] = "SMP_CENTRAL_IDENTIFICATION"
	smp_command_symbol[8] = "SMP_IDENTITY_INFORMATION"
	smp_command_symbol[9] = "SMP_IDENTITY_ADDRESS_INFO"
	smp_command_symbol[11] = "SMP_SECURITY_REQUEST"
	smp_command_symbol[12] = "SMP_PAIRING_PUBLIC_KEY"
	smp_command_symbol[13] = "SMP_PAIRING_DHKEY_CHECK"
	smp_command_symbol[14] = "SMP_PAIRING_KEYPRESS_NOTIFY"

	smp_failure_symbol[1] = "SMP_ERR_PASSKEY_ENTRY_FAILED"
	smp_failure_symbol[2] = "SMP_ERR_OOB_NOT_AVAILABLE"
	smp_failure_symbol[3] = "SMP_ERR_AUTH_REQUIREMENTS"
	smp_failure_symbol[4] = "SMP_ERR_CONFIRM_VALUE_FAILED"
	smp_failure_symbol[5] = "SMP_ERR_PAIRING_NOT_SUPPORTED"
	smp_failure_symbol[6] = "SMP_ERR_ENCRYPTION_KEY_SIZE"
	smp_failure_symbol[7] = "SMP_ERR_CMD_NOT_SUPPORTED"
	smp_failure_symbol[8] = "SMP_ERR_UNSPECIFIED_REASON"
	smp_failure_symbol[9] = "SMP_ERR_REPEATED_ATTEMPTS"
	smp_failure_symbol[10] = "SMP_ERR_INVALID_PARAMETERS"
	smp_failure_symbol[11] = "SMP_ERR_DHKEY_CHECK_FAILED"
	smp_failure_symbol[12] = "SMP_ERR_NUMERIC_COMP_FAILED"
	smp_failure_symbol[13] = "SMP_ERR_BREDR_PAIRING_IN_PROGRESS"
	smp_failure_symbol[14] = "SMP_ERR_CROSS_TRANSPORT_NOT_ALLOWED"
	smp_failure_symbol[15] = "SMP_ERR_KEY_REJECTED"
	smp_failure_symbol[16] = "SMP_ERR_BUSY"
	smp_io_symbol[0] = "SMP_IO_DISPLAY_ONLY"
	smp_io_symbol[1] = "SMP_IO_DISPLAY_YESNO"
	smp_io_symbol[2] = "SMP_IO_KEYBOARD_ONLY"
	smp_io_symbol[3] = "SMP_IO_NO_INPUT_NO_OUTPUT"
	smp_io_symbol[4] = "SMP_IO_KEYBOARD_DISPLAY"
	smp_keypress_symbol[0] = "SMP_KEYPRESS_ENTRY_STARTED"
	smp_keypress_symbol[1] = "SMP_KEYPRESS_DIGIT_ENTERED"
	smp_keypress_symbol[2] = "SMP_KEYPRESS_DIGIT_ERASED"
	smp_keypress_symbol[3] = "SMP_KEYPRESS_CLEARED"
	smp_keypress_symbol[4] = "SMP_KEYPRESS_ENTRY_COMPLETED"

	l2cap_command_symbol[1] = "NG_L2CAP_CMD_REJ"
	l2cap_command_symbol[2] = "NG_L2CAP_CON_REQ"
	l2cap_command_symbol[3] = "NG_L2CAP_CON_RSP"
	l2cap_command_symbol[4] = "NG_L2CAP_CFG_REQ"
	l2cap_command_symbol[5] = "NG_L2CAP_CFG_RSP"
	l2cap_command_symbol[6] = "NG_L2CAP_DISCON_REQ"
	l2cap_command_symbol[7] = "NG_L2CAP_DISCON_RSP"
	l2cap_command_symbol[8] = "NG_L2CAP_ECHO_REQ"
	l2cap_command_symbol[9] = "NG_L2CAP_ECHO_RSP"
	l2cap_command_symbol[10] = "NG_L2CAP_INFO_REQ"
	l2cap_command_symbol[11] = "NG_L2CAP_INFO_RSP"
	l2cap_command_symbol[18] = "NG_L2CAP_CMD_PARAM_UPDATE_REQUEST"
	l2cap_command_symbol[19] = "NG_L2CAP_CMD_PARAM_UPDATE_RESPONSE"
	l2cap_command_symbol[20] = "NG_L2CAP_LE_CREDIT_CON_REQ"
	l2cap_command_symbol[21] = "NG_L2CAP_LE_CREDIT_CON_RSP"
	l2cap_command_symbol[22] = "NG_L2CAP_FLOW_CONTROL_CREDIT"
	l2cap_command_symbol[23] = "NG_L2CAP_CREDIT_CON_REQ"
	l2cap_command_symbol[24] = "NG_L2CAP_CREDIT_CON_RSP"
	l2cap_command_symbol[25] = "NG_L2CAP_CREDIT_RECONFIG_REQ"
	l2cap_command_symbol[26] = "NG_L2CAP_CREDIT_RECONFIG_RSP"
	l2cap_result_symbol[0] = "NG_L2CAP_LE_COC_SUCCESS"
	l2cap_result_symbol[2] = "NG_L2CAP_LE_COC_SPSM_NOT_SUPPORTED"
	l2cap_result_symbol[4] = "NG_L2CAP_LE_COC_NO_RESOURCES"
	l2cap_result_symbol[5] = "NG_L2CAP_LE_COC_INSUFF_AUTHEN"
	l2cap_result_symbol[6] = "NG_L2CAP_LE_COC_INSUFF_AUTHOR"
	l2cap_result_symbol[7] = "NG_L2CAP_LE_COC_INSUFF_ENC_KEY"
	l2cap_result_symbol[8] = "NG_L2CAP_LE_COC_INSUFF_ENC"
	l2cap_result_symbol[9] = "NG_L2CAP_LE_COC_INVALID_SCID"
	l2cap_result_symbol[10] = "NG_L2CAP_LE_COC_SCID_IN_USE"
	l2cap_result_symbol[11] = "NG_L2CAP_LE_COC_UNACCEPTABLE_PARAMS"
	l2cap_result_symbol[12] = "NG_L2CAP_LE_COC_INVALID_PARAMS"
	l2cap_result_symbol[13] = "NG_L2CAP_LE_COC_PENDING_NO_INFO"
	l2cap_result_symbol[14] = "NG_L2CAP_LE_COC_PENDING_AUTHEN"
	l2cap_result_symbol[15] = "NG_L2CAP_LE_COC_PENDING_AUTHOR"
	l2cap_reconfig_symbol[0] = "NG_L2CAP_RECONFIG_SUCCESS"
	l2cap_reconfig_symbol[1] = "NG_L2CAP_RECONFIG_MTU_REDUCTION"
	l2cap_reconfig_symbol[2] = "NG_L2CAP_RECONFIG_MPS_REDUCTION_MULTI"
	l2cap_reconfig_symbol[3] = "NG_L2CAP_RECONFIG_INVALID_DCID"
	l2cap_reconfig_symbol[4] = "NG_L2CAP_RECONFIG_UNACCEPTABLE_PARAMS"
	hci_event_symbol[1] = "NG_HCI_EVENT_DISCON_COMPL"
	hci_event_symbol[2] = "NG_HCI_EVENT_ENCRYPTION_CHANGE"
	hci_event_symbol[3] = "NG_HCI_EVENT_ENCRYPTION_CHANGE_V2"
	hci_event_symbol[4] = "NG_HCI_EVENT_COMMAND_COMPL"
	hci_event_symbol[5] = "NG_HCI_EVENT_COMMAND_STATUS"
	hci_event_symbol[6] = "NG_HCI_EVENT_NUM_COMPL_PKTS"
	hci_event_symbol[7] = "NG_HCI_EVENT_LE"
	hci_event_symbol[8] = "NG_HCI_EVENT_AUTH_PAYLOAD_TIMEOUT"
	hci_subevent_symbol[1] = "NG_HCI_LEEV_CON_COMPL"
	hci_subevent_symbol[2] = "NG_HCI_LEEV_ADVREP"
	hci_subevent_symbol[3] = "NG_HCI_LEEV_EXT_ADVREP"
	hci_subevent_symbol[4] = "NG_HCI_LEEV_CIS_ESTABLISHED"
	hci_subevent_symbol[5] = "NG_HCI_LEEV_CIS_REQUEST"
	hci_subevent_symbol[6] = "NG_HCI_LEEV_CREATE_BIG_COMPL"
	hci_subevent_symbol[7] = "NG_HCI_LEEV_BIG_SYNC_EST"
	hci_subevent_symbol[8] = "NG_HCI_LEEV_PATH_LOSS_THRESHOLD"
	hci_subevent_symbol[9] = "NG_HCI_LEEV_TX_POWER_REPORTING"
	hci_subevent_symbol[10] = "NG_HCI_LEEV_SUBRATE_CHANGE"
	hci_command_symbol[1] = "NG_HCI_OCF_LE_SET_EVENT_MASK"
	hci_command_symbol[2] = "NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS"
	hci_command_symbol[3] = "NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS"
	hci_command_symbol[4] = "NG_HCI_OCF_LE_SET_PERIODIC_ADV_PARAMS"
	hci_command_symbol[5] = "NG_HCI_OCF_LE_SET_CIG_PARAMS"
	hci_command_symbol[6] = "NG_HCI_OCF_LE_CREATE_CIS"
	hci_command_symbol[7] = "NG_HCI_OCF_LE_ACCEPT_CIS_REQUEST"
	hci_command_symbol[8] = "NG_HCI_OCF_LE_CREATE_BIG"
	hci_command_symbol[9] = "NG_HCI_OCF_LE_SETUP_ISO_DATA_PATH"
	hci_command_symbol[10] = "NG_HCI_OCF_LE_SET_DEFAULT_SUBRATE"
	hci_command_symbol[11] = "NG_HCI_OCF_LE_SUBRATE_REQUEST"
}

/The Error Code parameter shall be set to one of the following values:/ {
	in_errors = 1
	next
}
in_errors && /Table 3.4: Error codes/ { in_errors = 0 }
in_errors && match($0, /0x[0-9A-F][0-9A-F]/) && error_count < 19 {
	value = substr($0, RSTART, RLENGTH)
	error_count++
	expected = sprintf("0x%02X", error_count)
	if (value != expected) {
		print "unexpected ATT error sequence: " value " expected " expected > "/dev/stderr"
		exit 1
	}
	error_value[error_count] = tolower(value)
}

/3\.4\.8[[:space:]]+Attribute Opcode summary/ { want_att = 1 }
want_att && /Attribute PDU Name/ { in_att = 1; next }
in_att && /Table 3.42: Attribute Protocol summary/ { in_att = 0; want_att = 0 }
in_att && $1 ~ /^ATT_/ && $2 ~ /^0x[0-9A-F][0-9A-F]$/ {
	if (!($1 in att_map)) {
		print "unmapped ATT table name: " $1 > "/dev/stderr"
		exit 1
	}
	att_count++
	att_symbol[att_count] = att_map[$1]
	att_value[att_count] = tolower($2)
}

/3\.4\.2\.1[[:space:]]+ATT_EXCHANGE_MTU_REQ/ { in_att_mtu_req = 1 }
in_att_mtu_req && $1 == "Attribute" && $2 == "Opcode" && $3 == "1" &&
    $4 == "0x02" { att_mtu_req_opcode = tolower($4); att_mtu_req_opcode_size = $3 }
in_att_mtu_req && $1 == "Client" && $2 == "Rx" && $3 == "MTU" && $4 == "2" {
	att_mtu_req_value_size = $4
}
in_att_mtu_req && /Table 3.5: Format of ATT_EXCHANGE_MTU_REQ PDU/ { in_att_mtu_req = 0 }
/3\.4\.2\.2[[:space:]]+ATT_EXCHANGE_MTU_RSP/ { in_att_mtu_rsp = 1 }
in_att_mtu_rsp && $1 == "Attribute" && $2 == "Opcode" && $3 == "1" &&
    $4 == "0x03" { att_mtu_rsp_opcode = tolower($4); att_mtu_rsp_opcode_size = $3 }
in_att_mtu_rsp && $1 == "Server" && $2 == "Rx" && $3 == "MTU" && $4 == "2" {
	att_mtu_rsp_value_size = $4
}
in_att_mtu_rsp && /Table 3.6: Format of ATT_EXCHANGE_MTU_RSP PDU/ { in_att_mtu_rsp = 0 }
$1 == "ATT_MTU" && $2 == "23" { att_default_mtu = $2 }
/minimum ATT_MTU for an Enhanced ATT bearer is 64 octets/ {
	eatt_min_mtu = 64
}
/Bluetooth_Base_UUID and has/ { want_bluetooth_base_uuid = 2 }
want_bluetooth_base_uuid > 0 && /value 00000000-0000-1000-8000-00805F9B34FB/ {
	bluetooth_base_uuid = "0000000000001000800000805f9b34fb"
	want_bluetooth_base_uuid = 0
}
want_bluetooth_base_uuid > 0 { want_bluetooth_base_uuid-- }
/Handle\(s\) and 16-bit Bluetooth[[:space:]]+0x01/ {
	att_find_info_uuid16_format = "0x" nth_hex($0, 1)
}
/Handle\(s\) and 128-bit UUID\(s\)[[:space:]]+0x02/ {
	att_find_info_uuid128_format = "0x" nth_hex($0, 1)
}
/0x00.*Cancel all prepared writes/ {
	att_execute_cancel = "0x" nth_hex($0, 1)
}
/0x01.*Immediately write all pending prepared values/ {
	att_execute_commit = "0x" nth_hex($0, 1)
}

/Note: Attribute Opcode 0xD2 is previously used/ { saw_legacy_att = 1 }

/3\.3\.1\.1[[:space:]]+Characteristic Properties/ { want_gatt = 1 }
want_gatt && /Properties[[:space:]]+Value[[:space:]]+Description/ { in_gatt = 1; next }
in_gatt && /Table 3.5: Characteristic Properties bit field/ { in_gatt = 0; want_gatt = 0 }
in_gatt && $1 == "Broadcast" && $2 == "0x01" { gatt[1] = tolower($2) }
in_gatt && $1 == "Read" && $2 == "0x02" { gatt[2] = tolower($2) }
in_gatt && $1 == "Write" && $2 == "Without" && $3 == "0x04" { gatt[3] = tolower($3) }
in_gatt && $1 == "Write" && $2 == "0x08" { gatt[4] = tolower($2) }
in_gatt && $1 == "Notify" && $2 == "0x10" { gatt[5] = tolower($2) }
in_gatt && $1 == "Indicate" && $2 == "0x20" { gatt[6] = tolower($2) }
in_gatt && $1 == "0x40" && $2 == "Previously" { gatt[7] = tolower($1) }
in_gatt && $1 == "Extended" && $2 == "0x80" { gatt[8] = tolower($2) }

/Table 3.3 lists[[:space:]]*$/ { want_smp_commands = 1 }
want_smp_commands && $1 == "Code" && $2 == "Description" {
	in_smp_commands = 1
	next
}
in_smp_commands && /Table 3.3: SMP command codes/ {
	in_smp_commands = 0
	want_smp_commands = 0
}
in_smp_commands && $1 ~ /^0x[0-9A-F][0-9A-F]$/ {
	n = hex2dec($1)
	if (n >= 1 && n <= 14) {
		smp_command_value[n] = tolower($1)
		if (n == 10 && $2 == "Previously")
			saw_legacy_smp = 1
	}
}

/^7\.7\.8[[:space:]]+Encryption Change event/ { in_encryption_change = 1 }
in_encryption_change && /^7\.7\.9[[:space:]]+/ { in_encryption_change = 0 }
in_encryption_change && /Size: 2 octets \(12 bits meaningful\)/ {
	saw_encryption_change_handle_width = 1
	hci_encryption_handle_size = 2
}
in_encryption_change && /Range: 0x0000 to 0x0EFF/ {
	hci_encryption_handle_min = "0x" nth_hex($0, 1)
	hci_encryption_handle_max = "0x" nth_hex($0, 2)
}
in_encryption_change && /^Status:/ && /Size: 1 octet/ {
	hci_encryption_status_size = 1
}
in_encryption_change && /^Encryption_Enabled:/ && /Size: 1 octet/ {
	hci_encryption_enabled_size = 1
	in_encryption_enabled_values = 1
}
in_encryption_enabled_values && $1 == "0x00" { hci_encryption_off = tolower($1) }
in_encryption_enabled_values && $1 == "0x01" { hci_encryption_le_on = tolower($1) }
in_encryption_enabled_values && $1 == "0x02" { hci_encryption_bredr_on = tolower($1) }
in_encryption_enabled_values && $1 == "All" && $2 == "other" && $3 == "values" {
	saw_encryption_enabled_reserved = 1
}
in_encryption_change && /^Encryption_Key_Size:/ && /Size: 1 octet/ {
	hci_encryption_key_size_size = 1
	in_encryption_enabled_values = 0
}

/^7\.3\.69[[:space:]]+Set Event Mask Page 2 command/ { in_event_mask_page2 = 1 }
in_event_mask_page2 && /^7\.3\.70[[:space:]]+/ { in_event_mask_page2 = 0 }
in_event_mask_page2 && $1 == "HCI_Set_Event_Mask_Page_2" && $2 == "0x0063" {
	hci_page2_ocf = tolower($2)
}
in_event_mask_page2 && $1 == "23" &&
    $2 == "HCI_Authenticated_Payload_Timeout_Expired" {
	hci_page2_apto_bit = $1
}
in_event_mask_page2 && $1 == "25" && $2 == "HCI_Encryption_Change" &&
    $3 == "event" && $4 == "[v2]" {
	hci_page2_encryption_v2_bit = $1
}

/^7\.8\.1[[:space:]]+LE Set Event Mask command/ { in_le_event_mask = 1 }
in_le_event_mask && /^7\.8\.2[[:space:]]+/ { in_le_event_mask = 0 }
in_le_event_mask && $1 ~ /^[0-9]+$/ && $2 ~ /^HCI_LE_/ {
	if ($2 == "HCI_LE_Connectionless_IQ_Report") le_event_bit["CONNLESS_IQ"] = $1
	if ($2 == "HCI_LE_Connection_IQ_Report") le_event_bit["CONN_IQ"] = $1
	if ($2 == "HCI_LE_CTE_Request_Failed") le_event_bit["CTE_FAILED"] = $1
	if ($2 == "HCI_LE_Path_Loss_Threshold") le_event_bit["PATH_LOSS"] = $1
	if ($2 == "HCI_LE_Transmit_Power_Reporting") le_event_bit["TX_POWER"] = $1
	if ($2 == "HCI_LE_Subrate_Change") le_event_bit["SUBRATE"] = $1
}

/bit positions for each Link Layer feature shall be as shown in Table 4\.9/ {
	in_le_features = 1
}
in_le_features && /Table 4\.9: FeatureSet field/ { in_le_features = 0 }
in_le_features && $1 ~ /^[0-9]+$/ {
	if ($1 == 0 && $2 == "LE" && $3 == "Encryption") le_feature_bit["ENCRYPTION"] = $1
	if ($1 == 1 && $2 == "Connection" && $3 == "Parameters") le_feature_bit["CONN_PARAM"] = $1
	if ($1 == 8 && $2 == "LE" && $3 == "2M" && $4 == "PHY") le_feature_bit["2M_PHY"] = $1
	if ($1 == 17 && $2 == "Connection" && $3 == "CTE" && $4 == "Request") le_feature_bit["CONN_CTE_REQ"] = $1
	if ($1 == 20 && $2 == "Connectionless" && $3 == "CTE" && $4 == "Receiver") le_feature_bit["CONNLESS_CTE_RX"] = $1
	if ($1 == 33 && $2 == "LE" && $3 == "Power" && $4 == "Control") le_feature_bit["POWER_CONTROL"] = $1
	if ($1 == 35 && $2 == "LE" && $3 == "Path" && $4 == "Loss") le_feature_bit["PATH_LOSS"] = $1
	if ($1 == 37 && $2 == "Connection" && $3 == "Subrating") le_feature_bit["SUBRATING"] = $1
}

/^7\.7\.65\.13[[:space:]]+LE Extended Advertising Report event/ {
	in_ext_adv_report = 1
}
in_ext_adv_report && /^7\.7\.65\.14[[:space:]]+/ { in_ext_adv_report = 0 }
in_ext_adv_report && /^Event_Type\[i\]:/ && /2 octets/ {
	ext_adv_size["EVENT_TYPE"] = 2
}
in_ext_adv_report && /^Address_Type\[i\]:/ && /1 octet/ {
	ext_adv_size["ADDRESS_TYPE"] = 1
	in_ext_adv_address_types = 1
}
in_ext_adv_address_types && $1 == "0x00" && $2 == "Public" {
	ext_adv_addr_type["PUBLIC"] = tolower($1)
}
in_ext_adv_address_types && $1 == "0x01" && $2 == "Random" {
	ext_adv_addr_type["RANDOM"] = tolower($1)
}
in_ext_adv_address_types && $1 == "0x02" && $2 == "Public" {
	ext_adv_addr_type["PUBLIC_IDENTITY"] = tolower($1)
}
in_ext_adv_address_types && $1 == "0x03" && $2 == "Random" &&
    $3 == "(static)" {
	ext_adv_addr_type["RANDOM_IDENTITY"] = tolower($1)
}
in_ext_adv_address_types && $1 == "0xFF" && $2 == "No" &&
    $3 == "address" {
	ext_adv_addr_type["ANONYMOUS"] = tolower($1)
	in_ext_adv_address_types = 0
}
in_ext_adv_report && /^Address\[i\]:/ && /6 octets/ {
	ext_adv_size["ADDRESS"] = 6
}
in_ext_adv_report && /^Primary_PHY\[i\]:/ && /1 octet/ {
	ext_adv_size["PRIMARY_PHY"] = 1
	in_ext_adv_primary_phys = 1
}
in_ext_adv_primary_phys && $1 == "0x01" && $2 == "Advertiser" &&
    $3 == "PHY" && $4 == "is" && $5 == "LE" && $6 == "1M" {
	ext_adv_primary_phy_1m = tolower($1)
	in_ext_adv_primary_phys = 0
}
in_ext_adv_report && /^Secondary_PHY\[i\]:/ && /1 octet/ {
	ext_adv_size["SECONDARY_PHY"] = 1
}
in_ext_adv_report && /^Advertising_SID\[i\]:/ && /1 octet/ {
	ext_adv_size["ADVERTISING_SID"] = 1
}
in_ext_adv_report && /^TX_Power\[i\]:/ && /1 octet/ {
	ext_adv_size["TX_POWER"] = 1
}
in_ext_adv_report && /^RSSI\[i\]:/ && /1 octet/ {
	ext_adv_size["RSSI"] = 1
}
in_ext_adv_report && /^Periodic_Advertising_Interval\[i\]:/ && /2 octets/ {
	ext_adv_size["PERIODIC_INTERVAL"] = 2
}
in_ext_adv_report && /^Direct_Address_Type\[i\]:/ && /1 octet/ {
	ext_adv_size["DIRECT_ADDRESS_TYPE"] = 1
}
in_ext_adv_report && /^Direct_Address\[i\]:/ && /6 octets/ {
	ext_adv_size["DIRECT_ADDRESS"] = 6
}
in_ext_adv_report && /^Data_Length\[i\]:/ && /1 octet/ {
	ext_adv_size["DATA_LENGTH"] = 1
	in_ext_adv_data_lengths = 1
}
in_ext_adv_data_lengths && $1 == "0" && $2 == "to" && $3 == "229" {
	ext_adv_data_length_min = $1
	ext_adv_data_length_max = $3
	in_ext_adv_data_lengths = 0
}

/^7\.8\.10[[:space:]]+LE Set Scan Parameters command/ {
	in_le_scan_parameters = 1
}
in_le_scan_parameters && /^7\.8\.11[[:space:]]+/ {
	in_le_scan_parameters = 0
}
in_le_scan_parameters && $1 == "HCI_LE_Set_Scan_Parameters" &&
    $2 == "0x000B" {
	le_scan_parameters_ocf = tolower($2)
}
in_le_scan_parameters && /^LE_Scan_Type:/ && /1 octet/ {
	le_scan_parameters_size["SCAN_TYPE"] = 1
}
in_le_scan_parameters && /^LE_Scan_Interval:/ && /2 octets/ {
	le_scan_parameters_size["SCAN_INTERVAL"] = 2
}
in_le_scan_parameters && /^LE_Scan_Window:/ && /2 octets/ {
	le_scan_parameters_size["SCAN_WINDOW"] = 2
}
in_le_scan_parameters && /^Own_Address_Type:/ && /1 octet/ {
	le_scan_parameters_size["OWN_ADDRESS_TYPE"] = 1
	in_le_scan_own_address_types = 1
}
in_le_scan_own_address_types && $1 == "0x00" && $2 == "Public" {
	le_scan_own_address_type["PUBLIC"] = tolower($1)
}
in_le_scan_own_address_types && $1 == "0x01" && $2 == "Random" {
	le_scan_own_address_type["RANDOM"] = tolower($1)
}
in_le_scan_own_address_types && $1 == "0x02" && $2 == "Controller" {
	le_scan_own_address_type["RPA_PUBLIC_FALLBACK"] = tolower($1)
}
in_le_scan_own_address_types && $1 == "0x03" && $2 == "Controller" {
	le_scan_own_address_type["RPA_RANDOM_FALLBACK"] = tolower($1)
}
in_le_scan_own_address_types && $1 == "All" && $2 == "other" &&
    $3 == "values" {
	in_le_scan_own_address_types = 0
}
in_le_scan_parameters && /^Scanning_Filter_Policy:/ && /1 octet/ {
	le_scan_parameters_size["FILTER_POLICY"] = 1
}

/^7\.8\.5[[:space:]]+LE Set Advertising Parameters command/ {
	in_le_adv_parameters = 1
}
in_le_adv_parameters && /^7\.8\.6[[:space:]]+/ { in_le_adv_parameters = 0 }
in_le_adv_parameters && $1 == "HCI_LE_Set_Advertising_Parameters" &&
    $2 == "0x0006" { le_adv_parameters_ocf = tolower($2) }
in_le_adv_parameters && /^Advertising_Interval_Min:/ && /2 octets/ {
	le_adv_parameters_size["INTERVAL_MIN"] = 2
}
in_le_adv_parameters && /Range: 0x0020 to 0x4000/ {
	le_adv_interval_min = "0x" nth_hex($0, 1)
	le_adv_interval_max = "0x" nth_hex($0, 2)
}
in_le_adv_parameters && /^Advertising_Interval_Max:/ && /2 octets/ {
	le_adv_parameters_size["INTERVAL_MAX"] = 2
}
in_le_adv_parameters && /^Advertising_Type:/ && /1 octet/ {
	le_adv_parameters_size["ADV_TYPE"] = 1
	in_le_adv_types = 1
}
in_le_adv_types && $1 == "0x00" && $2 == "Connectable" {
	le_adv_type["UNDIRECTED"] = tolower($1)
}
in_le_adv_types && $1 == "0x01" && $2 == "Connectable" {
	le_adv_type["DIRECTED_HIGH"] = tolower($1)
}
in_le_adv_types && $1 == "0x04" && $2 == "Connectable" {
	le_adv_type["DIRECTED_LOW"] = tolower($1)
	in_le_adv_types = 0
}
in_le_adv_parameters && /^Own_Address_Type:/ && /1 octet/ {
	le_adv_parameters_size["OWN_ADDRESS_TYPE"] = 1
	in_le_adv_own_types = 1
}
in_le_adv_own_types && $1 == "0x00" && $2 == "Public" {
	le_adv_own_type_public = tolower($1)
}
in_le_adv_own_types && $1 == "0x03" && $2 == "Controller" {
	in_le_adv_own_types = 0
}
in_le_adv_parameters && /^Peer_Address_Type:/ && /1 octet/ {
	le_adv_parameters_size["PEER_ADDRESS_TYPE"] = 1
	in_le_adv_peer_types = 1
}
in_le_adv_peer_types && $1 == "0x00" && $2 == "Public" {
	le_adv_peer_type["PUBLIC"] = tolower($1)
}
in_le_adv_peer_types && $1 == "0x01" && $2 == "Random" {
	le_adv_peer_type["RANDOM"] = tolower($1)
	in_le_adv_peer_types = 0
}
in_le_adv_parameters && /^Peer_Address:/ && /6 octets/ {
	le_adv_parameters_size["PEER_ADDRESS"] = 6
}
in_le_adv_parameters && /^Advertising_Channel_Map:/ && /1 octet/ {
	le_adv_parameters_size["CHANNEL_MAP"] = 1
}
in_le_adv_parameters && /^Advertising_Filter_Policy:/ && /1 octet/ {
	le_adv_parameters_size["FILTER_POLICY"] = 1
	in_le_adv_filter_policies = 1
}
in_le_adv_filter_policies && $1 == "0x00" && $2 == "Process" {
	le_adv_filter_policy_all = tolower($1)
	in_le_adv_filter_policies = 0
}

/^7\.8\.53[[:space:]]+LE Set Extended Advertising Parameters command/ {
	in_le_ext_adv_parameters = 1
}
in_le_ext_adv_parameters && /^7\.8\.54[[:space:]]+/ {
	in_le_ext_adv_parameters = 0
}
in_le_ext_adv_parameters && /^Advertising_Handle:/ && /1 octet/ {
	le_ext_adv_size["HANDLE"] = 1
	in_le_ext_adv_handle = 1
}
in_le_ext_adv_handle && /Range: 0x00 to 0xEF/ {
	le_ext_adv_handle_min = "0x" nth_hex($0, 1)
	le_ext_adv_handle_max = "0x" nth_hex($0, 2)
	in_le_ext_adv_handle = 0
}
in_le_ext_adv_parameters && /^Advertising_Event_Properties:/ && /2 octets/ {
	le_ext_adv_size["EVENT_PROPERTIES"] = 2
	in_le_ext_adv_properties = 1
}
in_le_ext_adv_properties && $1 == "0" && $2 == "Connectable" {
	le_ext_adv_property_bit["CONNECTABLE"] = $1
}
in_le_ext_adv_properties && $1 == "2" && $2 == "Directed" {
	le_ext_adv_property_bit["DIRECTED"] = $1
}
in_le_ext_adv_properties && $1 == "3" && $2 == "High" {
	le_ext_adv_property_bit["HIGH_DUTY_DIRECTED"] = $1
}
in_le_ext_adv_properties && $1 == "4" && $2 == "Use" {
	le_ext_adv_property_bit["LEGACY"] = $1
}
in_le_ext_adv_properties && $1 == "5" && $2 == "Omit" {
	le_ext_adv_property_bit["ANONYMOUS"] = $1
	in_le_ext_adv_properties = 0
}
in_le_ext_adv_parameters && /^Primary_Advertising_Interval_Min:/ && /3 octets/ {
	le_ext_adv_size["INTERVAL_MIN"] = 3
}
in_le_ext_adv_parameters && /Range: 0x000020 to 0xFFFFFF/ {
	le_ext_adv_interval_min = "0x" nth_hex($0, 1)
	le_ext_adv_interval_max = "0x" nth_hex($0, 2)
}
in_le_ext_adv_parameters && /^Primary_Advertising_Interval_Max:/ && /3 octets/ {
	le_ext_adv_size["INTERVAL_MAX"] = 3
}
in_le_ext_adv_parameters && /^Primary_Advertising_Channel_Map:/ && /1 octet/ {
	le_ext_adv_size["CHANNEL_MAP"] = 1
	in_le_ext_adv_channel_map = 1
}
in_le_ext_adv_channel_map && $1 ~ /^[012]$/ && $2 == "Channel" {
	le_ext_adv_channel_bit[$1] = $1
}
in_le_ext_adv_channel_map && $1 == "All" && $2 == "other" {
	in_le_ext_adv_channel_map = 0
}
in_le_ext_adv_parameters && /^Own_Address_Type:/ && /1 octet/ {
	le_ext_adv_size["OWN_ADDRESS_TYPE"] = 1
	in_le_ext_adv_own_types = 1
}
in_le_ext_adv_own_types && $1 == "0x00" && $2 == "Public" {
	le_ext_adv_own_type_public = tolower($1)
}
in_le_ext_adv_own_types && $1 == "0x03" && $2 == "Controller" {
	in_le_ext_adv_own_types = 0
}
in_le_ext_adv_parameters && /^Peer_Address_Type:/ && /1 octet/ {
	le_ext_adv_size["PEER_ADDRESS_TYPE"] = 1
	in_le_ext_adv_peer_types = 1
}
in_le_ext_adv_peer_types && $1 == "0x00" && $2 == "Public" {
	le_ext_adv_peer_type_public = tolower($1)
}
in_le_ext_adv_peer_types && $1 == "0x01" && $2 == "Random" {
	le_ext_adv_peer_type_random = tolower($1)
	in_le_ext_adv_peer_types = 0
}
in_le_ext_adv_parameters && /^Peer_Address:/ && /6 octets/ {
	le_ext_adv_size["PEER_ADDRESS"] = 6
}
in_le_ext_adv_parameters && /^Advertising_Filter_Policy:/ && /1 octet/ {
	le_ext_adv_size["FILTER_POLICY"] = 1
	in_le_ext_adv_filter_policies = 1
}
in_le_ext_adv_filter_policies && $1 == "0x00" && $2 == "Process" {
	le_ext_adv_filter_policy_all = tolower($1)
	in_le_ext_adv_filter_policies = 0
}
in_le_ext_adv_parameters && /^Advertising_TX_Power:/ && /1 octet/ {
	le_ext_adv_size["TX_POWER"] = 1
	in_le_ext_adv_tx_power = 1
}
in_le_ext_adv_tx_power && $1 == "0x7F" && $2 == "Host" {
	le_ext_adv_tx_power_no_preference = tolower($1)
	in_le_ext_adv_tx_power = 0
}
in_le_ext_adv_parameters && /^Primary_Advertising_PHY:/ && /1 octet/ {
	le_ext_adv_size["PRIMARY_PHY"] = 1
	in_le_ext_adv_primary_phys = 1
}
in_le_ext_adv_primary_phys && $1 == "0x01" && $2 == "Primary" {
	le_ext_adv_primary_phy_1m = tolower($1)
	in_le_ext_adv_primary_phys = 0
}
in_le_ext_adv_parameters && /^Secondary_Advertising_Max_Skip:/ && /1 octet/ {
	le_ext_adv_size["SECONDARY_MAX_SKIP"] = 1
}
in_le_ext_adv_parameters && /^Secondary_Advertising_PHY:/ && /1 octet/ {
	le_ext_adv_size["SECONDARY_PHY"] = 1
	in_le_ext_adv_secondary_phys = 1
}
in_le_ext_adv_secondary_phys && $1 == "0x01" && $2 == "Secondary" {
	le_ext_adv_secondary_phy_1m = tolower($1)
	in_le_ext_adv_secondary_phys = 0
}
in_le_ext_adv_parameters && /^Advertising_SID:/ && /1 octet/ {
	le_ext_adv_size["SID"] = 1
}
in_le_ext_adv_parameters && /^Scan_Request_Notification_Enable:/ && /1 octet/ {
	le_ext_adv_size["SCAN_REQUEST_NOTIFY"] = 1
}

# Figure 3.11 is rendered as five lines by pdftotext.  Require the complete
# field order and all widths before deriving the masks below.
/^[[:space:]]+Previously[[:space:]]*$/ { want_key_dist_layout = 1 }
want_key_dist_layout && /EncKey[[:space:]]+IdKey[[:space:]]+LinkKey[[:space:]]+RFU/ {
	saw_key_dist_labels = 1
}
saw_key_dist_labels && /^[[:space:]]+used[[:space:]]*$/ {
	saw_key_dist_previous_label = 1
}
saw_key_dist_previous_label && /\(1 bit\)[[:space:]]+\(1 bit\)[[:space:]]+\(1 bit\)[[:space:]]+\(4 bits\)/ {
	saw_key_dist_main_widths = 1
}
saw_key_dist_main_widths && /^[[:space:]]+\(1 bit\)[[:space:]]*$/ {
	saw_key_dist_previous_width = 1
}

/The reason codes are defined in[[:space:]]*$/ { want_smp_failures = 1 }
want_smp_failures && $1 == "Value" && $2 == "Name" {
	in_smp_failures = 1
	next
}
in_smp_failures && /Table 3.7: Pairing Failed reason codes/ {
	in_smp_failures = 0
	want_smp_failures = 0
}
in_smp_failures && $1 ~ /^0x[0-9A-F][0-9A-F]$/ {
	n = hex2dec($1)
	if (n >= 1 && n <= 16)
		smp_failure_value[n] = tolower($1)
}

/^Notification Type can take one of the following values:/ {
	in_smp_keypress_types = 1
	next
}
in_smp_keypress_types && /Table 3.8: Notification Type/ {
	in_smp_keypress_types = 0
}
in_smp_keypress_types && $1 ~ /^[0-4]$/ {
	smp_keypress_value[$1 + 0] = sprintf("0x%02x", $1 + 0)
}
in_smp_keypress_types && $1 == "5" && $2 == "to" && $3 == "255" &&
    $4 == "Reserved" {
	smp_keypress_reserved_first = $1 + 0
	smp_keypress_reserved_last = $3 + 0
}

$1 == "0x00" && $2 == "DisplayOnly" { smp_io_value[0] = tolower($1) }
$1 == "0x01" && $2 == "DisplayYesNo" { smp_io_value[1] = tolower($1) }
$1 == "0x02" && $2 == "KeyboardOnly" { smp_io_value[2] = tolower($1) }
$1 == "0x03" && $2 == "NoInputNoOutput" { smp_io_value[3] = tolower($1) }
$1 == "0x04" && $2 == "KeyboardDisplay" { smp_io_value[4] = tolower($1) }
$1 == "0x05" && $2 == "to" && $3 == "0xFF" && $4 == "Reserved" {
	smp_io_reserved_first = tolower($1)
	smp_io_reserved_last = tolower($3)
}
/AddrType shall be set to 0x00\. If$/ {
	smp_identity_addr_public = "0x" nth_hex($0, 1)
}
/static random device address then AddrType shall be set to 0x01\.$/ {
	smp_identity_addr_static_random = "0x" nth_hex($0, 1)
}
$1 == "Bonding_Flags" && $2 == "MITM" && $3 == "SC" &&
    $4 == "Keypress" && $5 == "CT2" && $6 == "RFU" {
	saw_smp_authreq_layout = 1
	want_smp_authreq_widths = 1
	next
}
want_smp_authreq_widths && $1 == "(2" && $2 == "bits)" &&
    $3 == "(1" && $4 == "bit)" && $5 == "(1" && $6 == "bit)" &&
    $7 == "(1" && $8 == "bit)" && $9 == "(1" && $10 == "bit)" &&
    $11 == "(2" && $12 == "bits)" {
	saw_smp_authreq_widths = 1
	want_smp_authreq_widths = 0
}
$1 == "support." && $2 == "The" && $3 == "maximum" && $4 == "key" &&
    $5 == "size" && $6 == "shall" && $7 == "be" && $8 == "in" &&
    $9 == "the" && $10 == "range" && $12 == "to" && $14 == "octets." {
	smp_key_size_min = $11
	smp_key_size_max = $13
}

$1 == "EncKey" && $2 == "IdKey" && $3 == "LinkKey" && $4 == "RFU" {
	saw_smp_keydist = 1
}

/The CID name space for ACL-U logical links is as follows:/ { in_acl_cids = 1 }
in_acl_cids && /Table 2.1: CID name space on ACL-U logical links/ { in_acl_cids = 0 }
in_acl_cids && $1 == "0x0001" && $2 == "L2CAP" { saw_cid_signal = 1 }
in_acl_cids && $1 == "0x0002" && $2 == "Connectionless" { saw_cid_clt = 1 }
in_acl_cids && $1 == "0x0003" && $2 == "Previously" { saw_cid_legacy_a2mp = 1 }
in_acl_cids && $1 == "0x0040" && $2 == "to" { saw_cid_first = 1 }

/The CID name space for LE-U logical links is as follows:/ { in_le_cids = 1 }
in_le_cids && /Table 2.3: CID name space on LE-U logical links/ { in_le_cids = 0 }
in_le_cids && $1 == "0x0004" && $2 == "Attribute" { saw_cid_att = 1 }
in_le_cids && $1 == "0x0005" && $2 == "L2CAP" { saw_cid_lesig = 1 }
in_le_cids && $1 == "0x0006" && $2 == "Security" { saw_cid_smp = 1 }
in_le_cids && $1 == "0x0040" && $2 == "to" && $3 == "0x007F" { saw_cid_le_range = 1 }

/Table 4.2 lists the codes defined by this document/ { want_l2cap_commands = 1 }
want_l2cap_commands && $1 == "Code" && $2 == "Description" {
	in_l2cap_commands = 1
	next
}
in_l2cap_commands && /Table 4.2: Signaling command codes/ {
	in_l2cap_commands = 0
	want_l2cap_commands = 0
}
in_l2cap_commands && $1 ~ /^0x[0-9A-F][0-9A-F]$/ {
	n = hex2dec($1)
	if (n in l2cap_command_symbol)
		l2cap_command_value[n] = tolower($1)
}

/Table 4.17 defines[[:space:]]*$/ { want_l2cap_results = 1 }
want_l2cap_results && $1 == "Value" && $2 == "Description" {
	in_l2cap_results = 1
	next
}
in_l2cap_results && /Table 4.17: Result values/ {
	in_l2cap_results = 0
	want_l2cap_results = 0
}
in_l2cap_results && $1 ~ /^0x[0-9A-F][0-9A-F][0-9A-F][0-9A-F]$/ {
	n = hex2dec($1)
	if (n in l2cap_result_symbol)
		l2cap_result_value[n] = tolower($1)
}

/Figure 4.24: L2CAP_CREDIT_BASED_RECONFIGURE_RSP/ { want_reconfig_results = 1 }
want_reconfig_results && $1 == "Value" && $2 == "Description" {
	in_reconfig_results = 1
	next
}
in_reconfig_results && /Table 4.18: Result values for the L2CAP_CREDIT_BASED_RECONFIGURE_RSP/ {
	in_reconfig_results = 0
	want_reconfig_results = 0
}
in_reconfig_results && $1 ~ /^0x[0-9A-F][0-9A-F][0-9A-F][0-9A-F]$/ {
	n = hex2dec($1)
	if (n in l2cap_reconfig_symbol)
		l2cap_reconfig_value[n] = tolower($1)
}

$1 == "HCI_Disconnection_Complete" && $2 == "0x05" { hci_event[1] = tolower($2) }
$1 == "HCI_Encryption_Change" && $2 == "[v1]" && $3 == "0x08" { hci_event[2] = tolower($3) }
$1 == "HCI_Encryption_Change" && $2 == "[v2]" && $3 == "0x59" { hci_event[3] = tolower($3) }
$1 == "HCI_Command_Complete" && $2 == "0x0E" { hci_event[4] = tolower($2) }
$1 == "HCI_Command_Status" && $2 == "0x0F" { hci_event[5] = tolower($2) }
$1 == "HCI_Number_Of_Completed_Packets" && $2 == "0x13" { hci_event[6] = tolower($2) }
$0 ~ /Code of all LE Meta events shall be 0x3E/ { hci_event[7] = "0x3e" }
$1 == "HCI_Authenticated_Payload_Timeout_Expired" && $2 == "0x57" { hci_event[8] = tolower($2) }

$1 == "0x01" && $0 ~ /HCI_LE_Connection_Complete event/ { hci_subevent[1] = tolower($1) }
$1 == "0x02" && $0 ~ /HCI_LE_Advertising_Report event/ { hci_subevent[2] = tolower($1) }
$1 == "0x0D" && $0 ~ /HCI_LE_Extended_Advertising_Report event/ { hci_subevent[3] = tolower($1) }
$1 == "0x19" && $0 ~ /HCI_LE_CIS_Established \[v1\] event/ { hci_subevent[4] = tolower($1) }
$1 == "0x1A" && $0 ~ /HCI_LE_CIS_Request event/ { hci_subevent[5] = tolower($1) }
$1 == "0x1B" && $0 ~ /HCI_LE_Create_BIG_Complete event/ { hci_subevent[6] = tolower($1) }
$1 == "0x1D" && $0 ~ /HCI_LE_BIG_Sync_Established event/ { hci_subevent[7] = tolower($1) }
$1 == "0x20" && $0 ~ /HCI_LE_Path_Loss_Threshold event/ { hci_subevent[8] = tolower($1) }
$1 == "0x21" && $0 ~ /HCI_LE_Transmit_Power_Reporting event/ { hci_subevent[9] = tolower($1) }
$1 == "0x23" && $0 ~ /HCI_LE_Subrate_Change event/ { hci_subevent[10] = tolower($1) }

$1 == "HCI" && $2 == "Event" && $3 == "packet" && $4 == "0x04" { hci_packet = tolower($4) }
$1 == "HCI_LE_Set_Event_Mask" && $2 == "[v1]" && $3 == "0x0001" { hci_command[1] = tolower($3) }
$1 == "HCI_LE_Set_Extended_-" && $2 == "0x0036" { hci_command[2] = tolower($2) }
$1 == "HCI_LE_Set_Extended_Scan_Parameters" && $2 == "0x0041" { hci_command[3] = tolower($2) }
$1 == "HCI_LE_Set_Periodic_-" && $2 == "0x003E" { hci_command[4] = tolower($2) }
$1 == "HCI_LE_Set_CIG_Parameters" && $2 == "0x0062" { hci_command[5] = tolower($2) }
$1 == "HCI_LE_Create_CIS" && $2 == "0x0064" { hci_command[6] = tolower($2) }
$1 == "HCI_LE_Accept_CIS_Request" && $2 == "0x0066" { hci_command[7] = tolower($2) }
$1 == "HCI_LE_Create_BIG" && $2 == "0x0068" { hci_command[8] = tolower($2) }
$1 == "HCI_LE_Setup_ISO_Data_Path" && $2 == "0x006E" { hci_command[9] = tolower($2) }
$1 == "HCI_LE_Set_Default_Subrate" && $2 == "0x007D" { hci_command[10] = tolower($2) }
$1 == "HCI_LE_Subrate_Request" && $2 == "0x007E" { hci_command[11] = tolower($2) }

$1 == "Address" && $2 == "[47:46]" && $3 == "Sub-Type" {
	in_random_address_types = 1
	random_address_mask = 3 * 64
	next
}
in_random_address_types && $1 == "0b00" && $2 == "Non-resolvable" {
	random_address_type[1] = 0 * 64
	next
}
in_random_address_types && $1 == "0b01" && $2 == "Resolvable" {
	random_address_type[2] = 1 * 64
	next
}
in_random_address_types && $1 == "0b10" && $2 == "Reserved" {
	random_address_type[3] = 2 * 64
	next
}
in_random_address_types && $1 == "0b11" && $2 == "Static" {
	random_address_type[4] = 3 * 64
	in_random_address_types = 0
	next
}

/^2\.2\.3[[:space:]]+Confirm value generation function c1 for LE legacy pairing$/ {
	legacy_vector_section = "C1"
	next
}

/^2\.2\.6[[:space:]]+LE Secure Connections confirm value generation function f4$/ {
	in_f4_definition = 1
	next
}
in_f4_definition && /Z is zero \(i\.e\. 8 bits of zeros\)/ {
	f4_z_numeric_oob = "0x00"
	next
}
in_f4_definition && $1 == "0x81" && /passkey bit is 0/ {
	f4_z_passkey_one = "0x" nth_hex($0, 1)
	f4_z_passkey_zero = "0x" nth_hex($0, 2)
	next
}
/^2\.2\.7[[:space:]]+LE Secure Connections key generation function f5$/ {
	in_f4_definition = 0
}
legacy_vector_section == "C1" && /8-bit iat.* is 0x/ {
	legacy["C1_IAT"] = nth_hex($0, 1)
	legacy["C1_RAT"] = nth_hex($0, 2)
	legacy_want_preq = 1
	next
}
legacy_vector_section == "C1" && legacy_want_preq && /56 bit pres is 0x/ {
	legacy["C1_PREQ"] = nth_hex($0, 1)
	legacy["C1_PRES"] = nth_hex($0, 2)
	legacy_want_preq = 0
	next
}
legacy_vector_section == "C1" && /48-bit ia is 0x/ {
	legacy["C1_IA"] = nth_hex($0, 1)
	legacy["C1_RA"] = nth_hex($0, 2)
	next
}
legacy_vector_section == "C1" && /128-bit k is 0x/ {
	legacy["C1_KEY"] = nth_hex($0, 1)
	legacy_want_c1_r = 1
	next
}
legacy_vector_section == "C1" && legacy_want_c1_r && /128-bit value r is 0x/ {
	legacy["C1_R"] = nth_hex($0, 1)
	legacy_want_c1_r = 0
	next
}
legacy_vector_section == "C1" && /function is 0x/ {
	legacy["C1_OUT"] = nth_hex($0, 1)
	next
}

/^2\.2\.4[[:space:]]+Key generation function s1 for LE legacy pairing$/ {
	legacy_vector_section = "S1"
	next
}
legacy_vector_section == "S1" && /128-bit value r1 is 0x/ {
	legacy["S1_R1"] = nth_hex($0, 1)
	next
}
legacy_vector_section == "S1" && /128-bit value r2 is$/ { legacy_want_s1_r2 = 1; next }
legacy_vector_section == "S1" && legacy_want_s1_r2 && /^[[:space:]]*0x/ {
	legacy["S1_R2"] = nth_hex($0, 1)
	legacy_want_s1_r2 = 0
	next
}
legacy_vector_section == "S1" && /^For example if the 128-bit value k is$/ {
	legacy_want_s1_key = 1
	next
}
legacy_vector_section == "S1" && legacy_want_s1_key && /^[[:space:]]*0x/ {
	legacy["S1_KEY"] = nth_hex($0, 1)
	legacy_want_s1_key = 0
	next
}
legacy_vector_section == "S1" && /output from the key generation function s1 is/ {
	legacy_want_s1_out = 1
	next
}
legacy_vector_section == "S1" && legacy_want_s1_out && /0x/ {
	legacy["S1_OUT"] = nth_hex($0, 1)
	legacy_want_s1_out = 0
	next
}
/^2\.2\.5[[:space:]]+Function AES-CMAC$/ { legacy_vector_section = "" }

/^2\.3\.5\.6\.1[[:space:]]+Public key exchange$/ {
	in_sc_debug_key = 1
	next
}
/^2\.3\.5\.3[[:space:]]+LE legacy pairing - Passkey Entry$/ {
	in_legacy_passkey = 1
	next
}
in_legacy_passkey && /then TK shall be$/ {
	want_legacy_passkey_tk = 1
	next
}
in_legacy_passkey && want_legacy_passkey_tk && $1 ~ /^0x[0-9A-Fa-f]+\.$/ {
	value = $1
	sub(/^0x/, "", value)
	sub(/\.$/, "", value)
	vector["LEGACY_PASSKEY_TK"] = tolower(value)
	want_legacy_passkey_tk = 0
	next
}
/^2\.3\.5\.4[[:space:]]/ { in_legacy_passkey = 0 }
in_sc_debug_key && $1 == "Public" && $2 == "key" && $3 == "(X):" &&
    vec_all_hex(4) { vec_add("SC_DEBUG_X", 4, 64); next }
in_sc_debug_key && $1 == "Public" && $2 == "key" && $3 == "(Y):" &&
    vec_all_hex(4) { vec_add("SC_DEBUG_Y", 4, 64); next }
/^2\.3\.5\.6\.2[[:space:]]/ { in_sc_debug_key = 0 }

$0 ~ /Responder[[:space:]]+DisplayOnly[[:space:]]+Keyboard Only[[:space:]]+Keyboard/ {
	in_assoc_table = 1
	next
}
in_assoc_table && $1 == "Display" && $2 == "Just" {
	assoc_row = (assoc_row < 1 ? 1 : 2)
	assoc_parse_base(assoc_row, $0)
	next
}
in_assoc_table && $1 == "Keyboard" && $2 == "Only" {
	assoc_row = 3
	assoc_parse_base(assoc_row, $0)
	next
}
in_assoc_table && $1 == "NoInput" && $2 == "Just" {
	assoc_row = 4
	assoc_parse_base(assoc_row, $0)
	next
}
in_assoc_table && $1 == "Keyboard" && $2 == "Passkey" {
	assoc_row = (assoc_row < 3 ? 3 : 5)
	assoc_parse_base(assoc_row, $0)
	next
}
in_assoc_table && /Numeric/ {
	rest = $0
	offset = 0
	while (match(rest, /Numeric/)) {
		column_position = offset + RSTART
		column = (column_position < 60 ? 2 : 5)
		assoc_sc[assoc_row, column] = 2
		assoc_numeric_count++
		rest = substr(rest, RSTART + RLENGTH)
		offset = column_position + RLENGTH - 1
	}
}
/Table 2\.8: Mapping of IO capabilities to key generation method/ {
	in_assoc_table = 0
	saw_assoc_table = 1
}

/^D\.1[[:space:]]+AES-CMAC RFC4493 test vectors/ { vector_section = "D1"; next }
/^D\.1\.1[[:space:]]/ { vector_d1_example = 1; next }
/^D\.1\.2[[:space:]]/ { vector_d1_example = 2; next }
/^D\.1\.3[[:space:]]/ { vector_d1_example = 3; next }
/^D\.1\.4[[:space:]]/ { vector_d1_example = 4; next }
/^D\.2 f4 LE SC confirm value generation function/ { vector_section = "D2"; next }
/^D\.3 f5 LE SC key generation function/ { vector_section = "D3"; next }
/^D\.4 f6 LE SC check value generation function/ { vector_section = "D4"; next }
/^D\.5 g2 LE SC numeric comparison generation function/ { vector_section = "D5"; next }
/^D\.6 h6 LE SC link key conversion function/ { vector_section = "D6"; next }
/^D\.7 ah random address hash functions/ { vector_section = "D7"; next }
/^D\.8 h7 LE SC link key conversion function/ { vector_section = "D8"; next }
/^D\.9[[:space:]]/ { vector_section = "D9"; next }
/^D\.10[[:space:]]/ { vector_section = "D10"; next }
/^D\.11[[:space:]]/ { vector_section = "D11"; next }
/^D\.12[[:space:]]/ { vector_section = "D12"; next }
/^Host Controller Interface$/ { vector_section = ""; next }

vector_section == "D1" && $1 == "K" && vec_all_hex(2) { vec_add("D1_KEY", 2, 32); next }
vector_section == "D1" && $1 ~ /^M[0-3]?$/ && vec_all_hex(2) {
	d1_len = (vector_d1_example == 2 ? 32 : (vector_d1_example == 3 ? 80 : 128))
	vec_add("D1_" vector_d1_example "_MSG", 2, d1_len)
	next
}
vector_section == "D1" && $1 == "AES_CMAC" && vec_all_hex(2) {
	vec_add("D1_" vector_d1_example "_OUT", 2, 32)
	next
}

vector_section == "D2" && $1 == "U" && vec_all_hex(2) { vec_add("D2_U", 2, 64); next }
vector_section == "D2" && $1 == "V" && vec_all_hex(2) { vec_add("D2_V", 2, 64); next }
vector_section == "D2" && $1 == "X" && vec_all_hex(2) { vec_add("D2_X", 2, 32); next }
vector_section == "D2" && $1 == "Z" && $2 == "0x00" { vector_d2_z = tolower($2); next }
vector_section == "D2" && $1 == "AES_CMAC" && vec_all_hex(2) { vec_add("D2_OUT", 2, 32); next }

vector_section == "D3" && $1 == "DHKey(W)" && vec_all_hex(2) { vec_add("D3_DHKEY", 2, 64); next }
vector_section == "D3" && $1 == "N1" && vec_all_hex(2) { vec_add("D3_N1", 2, 32); next }
vector_section == "D3" && $1 == "N2" && vec_all_hex(2) { vec_add("D3_N2", 2, 32); next }
vector_section == "D3" && $1 == "A1" && vec_all_hex(2) { vec_add("D3_A1", 2, 14); next }
vector_section == "D3" && $1 == "A2" && vec_all_hex(2) { vec_add("D3_A2", 2, 14); next }
vector_section == "D3" && $1 == "(LTK)" { vector_d3_output = "D3_LTK"; next }
vector_section == "D3" && $1 == "(MacKey)" { vector_d3_output = "D3_MACKEY"; next }
vector_section == "D3" && $1 == "AES_CMAC" && vector_d3_output != "" &&
    vec_all_hex(2) { vec_add(vector_d3_output, 2, 32); vector_d3_output = ""; next }

vector_section == "D4" && $1 == "N1" && vec_all_hex(2) { vec_add("D4_N1", 2, 32); next }
vector_section == "D4" && $1 == "N2" && vec_all_hex(2) { vec_add("D4_N2", 2, 32); next }
vector_section == "D4" && $1 == "MacKey" && vec_all_hex(2) { vec_add("D4_MACKEY", 2, 32); next }
vector_section == "D4" && $1 == "R" && vec_all_hex(2) { vec_add("D4_R", 2, 32); next }
vector_section == "D4" && $1 == "IOcap" && vec_all_hex(2) { vec_add("D4_IOCAP", 2, 6); next }
vector_section == "D4" && $1 == "A1" && vec_all_hex(2) { vec_add("D4_A1", 2, 14); next }
vector_section == "D4" && $1 == "A2" && vec_all_hex(2) { vec_add("D4_A2", 2, 14); next }
vector_section == "D4" && $1 == "AES_CMAC" && vec_all_hex(2) { vec_add("D4_OUT", 2, 32); next }

vector_section == "D5" && $1 == "U" && vec_all_hex(2) { vec_add("D5_U", 2, 64); next }
vector_section == "D5" && $1 == "V" && vec_all_hex(2) { vec_add("D5_V", 2, 64); next }
vector_section == "D5" && $1 == "X" && vec_all_hex(2) { vec_add("D5_X", 2, 32); next }
vector_section == "D5" && $1 == "Y" && vec_all_hex(2) { vec_add("D5_Y", 2, 32); next }
vector_section == "D5" && $1 == "g2" && vec_all_hex(2) { vec_add("D5_OUT", 2, 8); next }

vector_section == "D6" && $1 == "Key" && vec_all_hex(2) { vec_add("D6_KEY", 2, 32); next }
vector_section == "D6" && $1 == "keyID" && vec_all_hex(2) { vec_add("D6_KEYID", 2, 8); next }
vector_section == "D6" && $1 == "AES_CMAC" && vec_all_hex(2) { vec_add("D6_OUT", 2, 32); next }

vector_section == "D7" && $1 == "IRK" && vec_all_hex(2) { vec_add("D7_IRK", 2, 32); next }
vector_section == "D7" && $1 == "prand" && vec_all_hex(2) { vec_add("D7_PRAND", 2, 32); next }
vector_section == "D7" && $1 == "AES_128" && vec_all_hex(2) { vec_add("D7_AES_OUT", 2, 32); next }
vector_section == "D7" && $1 == "ah" && vec_all_hex(2) { vec_add("D7_AH", 2, 6); next }

vector_section == "D8" && $1 == "Key" && vec_all_hex(2) { vec_add("D8_KEY", 2, 32); next }
vector_section == "D8" && $1 == "SALT" && vec_all_hex(2) { vec_add("D8_SALT", 2, 32); next }
vector_section == "D8" && $1 == "AES_CMAC" && vec_all_hex(2) { vec_add("D8_OUT", 2, 32); next }
vector_section == "D9" && $1 == "LTK" && vec_all_hex(2) { vec_add("D9_LTK", 2, 32); next }
vector_section == "D9" && $1 == "Link" && $2 == "Key" && vec_all_hex(3) { vec_add("D9_LINK_KEY", 3, 32); next }
vector_section == "D10" && $1 == "LTK" && vec_all_hex(2) { vec_add("D10_LTK", 2, 32); next }
vector_section == "D10" && $1 == "Link" && $2 == "Key" && vec_all_hex(3) { vec_add("D10_LINK_KEY", 3, 32); next }
vector_section == "D11" && $1 == "Link" && $2 == "Key" && vec_all_hex(3) { vec_add("D11_LINK_KEY", 3, 32); next }
vector_section == "D11" && $1 == "LTK" && vec_all_hex(2) { vec_add("D11_LTK", 2, 32); next }
vector_section == "D12" && $1 == "Link" && $2 == "Key" && vec_all_hex(3) { vec_add("D12_LINK_KEY", 3, 32); next }
vector_section == "D12" && $1 == "LTK" && vec_all_hex(2) { vec_add("D12_LTK", 2, 32); next }

vector_pending != "" && vec_all_hex(1) {
	vec_add(vector_pending, 1, vector_expected)
	next
}

$1 == "Database" && $2 == "Hash" && $3 == "=" && $4 == "AES-CMACk(m)" {
	for (i = 6; i <= NF; i++)
		gatt_hash[++gatt_hash_count] = "0x" tolower($i)
	want_gatt_hash_tail = 1
	next
}
want_gatt_hash_tail {
	for (i = 1; i <= NF; i++)
		gatt_hash[++gatt_hash_count] = "0x" tolower($i)
	want_gatt_hash_tail = 0
}

/Figure 4.18: L2CAP_LE_CREDIT_BASED_CONNECTION_REQ packet/ { saw_l2cap_fig_418 = 1 }
/Figure 4.19: L2CAP_LE_CREDIT_BASED_CONNECTION_RSP packet/ { saw_l2cap_fig_419 = 1 }
/Figure 4.20: L2CAP_FLOW_CONTROL_CREDIT_IND packet/ { saw_l2cap_fig_420 = 1 }
/Figure 4.21: L2CAP_CREDIT_BASED_CONNECTION_REQ packet/ { saw_l2cap_fig_421 = 1 }
/Figure 4.22: L2CAP_CREDIT_BASED_CONNECTION_RSP packet/ { saw_l2cap_fig_422 = 1 }
/Figure 4.23: L2CAP_CREDIT_BASED_RECONFIGURE_REQ packet/ { saw_l2cap_fig_423 = 1 }
/Figure 4.24: L2CAP_CREDIT_BASED_RECONFIGURE_RSP/ { saw_l2cap_fig_424 = 1 }

/^11 ADVERTISING AND SCAN RESPONSE DATA/ { in_ad_structure_format = 1 }
in_ad_structure_format && /^12 GAP SERVICE AND CHARACTERISTICS FOR/ {
	in_ad_structure_format = 0
}
in_ad_structure_format && /Length field of one octet/ {
	ad_structure_length_size = 1
}
in_ad_structure_format && /a Data field of Length octets/ {
	saw_ad_structure_data_length = 1
}
in_ad_structure_format && /first octet of the Data field shall contain the AD type/ {
	ad_structure_type_size = 1
}
in_ad_structure_format && /remaining Length - 1 octets/ {
	saw_ad_structure_payload_length = 1
}

END {
	if (error_count != 19 || att_count != 30 || !saw_legacy_att ||
	    !saw_legacy_smp || !saw_smp_keydist || !saw_cid_signal ||
	    !saw_cid_clt || !saw_cid_legacy_a2mp || !saw_cid_first ||
	    !saw_cid_att || !saw_cid_lesig || !saw_cid_smp ||
	    !saw_cid_le_range || !saw_l2cap_fig_418 || !saw_l2cap_fig_419 ||
	    !saw_l2cap_fig_420 || !saw_l2cap_fig_421 || !saw_l2cap_fig_422 ||
	    !saw_l2cap_fig_423 || !saw_l2cap_fig_424) {
		print "incomplete Core extraction: ATT=" att_count ", errors=" error_count \
		    ", legacy ATT=" saw_legacy_att ", legacy SMP=" saw_legacy_smp \
		    ", SMP keydist=" saw_smp_keydist > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= 26; i++) {
		if ((i in l2cap_command_symbol) && l2cap_command_value[i] == "") {
			print "incomplete L2CAP command extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 0; i <= 15; i++) {
		if ((i in l2cap_result_symbol) && l2cap_result_value[i] == "") {
			print "incomplete L2CAP result extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 0; i <= 4; i++) {
		if (l2cap_reconfig_value[i] == "") {
			print "incomplete L2CAP reconfigure extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 1; i <= 8; i++) {
		if (hci_event[i] == "") {
			print "incomplete HCI event extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 1; i <= 10; i++) {
		if (hci_subevent[i] == "") {
			print "incomplete HCI subevent extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	if (hci_packet == "") {
		print "incomplete HCI packet indicator extraction" > "/dev/stderr"
		exit 1
	}
	if (ad_structure_length_size != 1 || ad_structure_type_size != 1 ||
	    !saw_ad_structure_data_length || !saw_ad_structure_payload_length) {
		print "incomplete Core advertising-data structure extraction" > "/dev/stderr"
		exit 1
	}
	if (!saw_encryption_change_handle_width ||
	    hci_encryption_handle_min != "0x0000" ||
	    hci_encryption_handle_max != "0x0eff" ||
	    hci_encryption_status_size != 1 ||
	    hci_encryption_handle_size != 2 ||
	    hci_encryption_enabled_size != 1 ||
	    hci_encryption_key_size_size != 1 ||
	    hci_encryption_off != "0x00" ||
	    hci_encryption_le_on != "0x01" ||
	    hci_encryption_bredr_on != "0x02" ||
	    !saw_encryption_enabled_reserved) {
		print "incomplete HCI Encryption Change handle extraction" > "/dev/stderr"
		exit 1
	}
	if (hci_page2_ocf != "0x0063" || hci_page2_apto_bit != 23 ||
	    hci_page2_encryption_v2_bit != 25) {
		print "incomplete HCI Event Mask Page 2 extraction" > "/dev/stderr"
		exit 1
	}
	le_feature_required = "ENCRYPTION CONN_PARAM 2M_PHY CONN_CTE_REQ CONNLESS_CTE_RX POWER_CONTROL PATH_LOSS SUBRATING"
	n_le_feature_required = split(le_feature_required, required_name, " ")
	for (i = 1; i <= n_le_feature_required; i++) {
		if (le_feature_bit[required_name[i]] == "") {
			print "incomplete LE feature extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	le_event_required = "CONNLESS_IQ CONN_IQ CTE_FAILED PATH_LOSS TX_POWER SUBRATE"
	n_le_event_required = split(le_event_required, required_name, " ")
	for (i = 1; i <= n_le_event_required; i++) {
		if (le_event_bit[required_name[i]] == "") {
			print "incomplete LE event-mask extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	ext_adv_required = "EVENT_TYPE ADDRESS_TYPE ADDRESS PRIMARY_PHY SECONDARY_PHY ADVERTISING_SID TX_POWER RSSI PERIODIC_INTERVAL DIRECT_ADDRESS_TYPE DIRECT_ADDRESS DATA_LENGTH"
	n_ext_adv_required = split(ext_adv_required, required_name, " ")
	for (i = 1; i <= n_ext_adv_required; i++) {
		if (ext_adv_size[required_name[i]] == "") {
			print "incomplete extended advertising report field extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	ext_adv_addr_required = "PUBLIC RANDOM PUBLIC_IDENTITY RANDOM_IDENTITY ANONYMOUS"
	n_ext_adv_addr_required = split(ext_adv_addr_required, required_name, " ")
	for (i = 1; i <= n_ext_adv_addr_required; i++) {
		if (ext_adv_addr_type[required_name[i]] == "") {
			print "incomplete extended advertising address-type extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (ext_adv_primary_phy_1m != "0x01") {
		print "incomplete extended advertising primary-PHY extraction" > "/dev/stderr"
		exit 1
	}
	if (ext_adv_data_length_min != 0 || ext_adv_data_length_max != 229) {
		print "incomplete extended advertising data-length extraction" > "/dev/stderr"
		exit 1
	}
	if (le_scan_parameters_ocf != "0x000b") {
		print "incomplete LE Set Scan Parameters OCF extraction" > "/dev/stderr"
		exit 1
	}
	le_scan_parameters_required = "SCAN_TYPE SCAN_INTERVAL SCAN_WINDOW OWN_ADDRESS_TYPE FILTER_POLICY"
	n_le_scan_parameters_required = split(le_scan_parameters_required, required_name, " ")
	for (i = 1; i <= n_le_scan_parameters_required; i++) {
		if (le_scan_parameters_size[required_name[i]] == "") {
			print "incomplete LE scan parameter field extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	le_scan_own_required = "PUBLIC RANDOM RPA_PUBLIC_FALLBACK RPA_RANDOM_FALLBACK"
	n_le_scan_own_required = split(le_scan_own_required, required_name, " ")
	for (i = 1; i <= n_le_scan_own_required; i++) {
		if (le_scan_own_address_type[required_name[i]] == "") {
			print "incomplete LE scan own-address extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (le_adv_parameters_ocf != "0x0006" ||
	    le_adv_interval_min != "0x000020" && le_adv_interval_min != "0x0020" ||
	    le_adv_interval_max != "0x4000") {
		print "incomplete LE advertising scalar extraction" > "/dev/stderr"
		exit 1
	}
	le_adv_required = "INTERVAL_MIN INTERVAL_MAX ADV_TYPE OWN_ADDRESS_TYPE PEER_ADDRESS_TYPE PEER_ADDRESS CHANNEL_MAP FILTER_POLICY"
	n_le_adv_required = split(le_adv_required, required_name, " ")
	for (i = 1; i <= n_le_adv_required; i++) {
		if (le_adv_parameters_size[required_name[i]] == "") {
			print "incomplete LE advertising field extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	le_adv_type_required = "UNDIRECTED DIRECTED_HIGH DIRECTED_LOW"
	n_le_adv_type_required = split(le_adv_type_required, required_name, " ")
	for (i = 1; i <= n_le_adv_type_required; i++) {
		if (le_adv_type[required_name[i]] == "") {
			print "incomplete LE advertising type extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (le_adv_peer_type["PUBLIC"] != "0x00" ||
	    le_adv_peer_type["RANDOM"] != "0x01" ||
	    le_adv_own_type_public != "0x00" ||
	    le_adv_filter_policy_all != "0x00") {
		print "incomplete LE advertising peer-type extraction" > "/dev/stderr"
		exit 1
	}
	le_ext_adv_required = "HANDLE EVENT_PROPERTIES INTERVAL_MIN INTERVAL_MAX CHANNEL_MAP OWN_ADDRESS_TYPE PEER_ADDRESS_TYPE PEER_ADDRESS FILTER_POLICY TX_POWER PRIMARY_PHY SECONDARY_MAX_SKIP SECONDARY_PHY SID SCAN_REQUEST_NOTIFY"
	n_le_ext_adv_required = split(le_ext_adv_required, required_name, " ")
	for (i = 1; i <= n_le_ext_adv_required; i++) {
		if (le_ext_adv_size[required_name[i]] == "") {
			print "incomplete LE extended advertising field extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	le_ext_adv_property_required = "CONNECTABLE DIRECTED HIGH_DUTY_DIRECTED LEGACY ANONYMOUS"
	n_le_ext_adv_property_required = split(le_ext_adv_property_required, required_name, " ")
	for (i = 1; i <= n_le_ext_adv_property_required; i++) {
		if (le_ext_adv_property_bit[required_name[i]] == "") {
			print "incomplete LE extended advertising property extraction: " required_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (le_ext_adv_interval_min != "0x000020" ||
	    le_ext_adv_interval_max != "0xffffff") {
		print "incomplete LE extended advertising interval extraction" > "/dev/stderr"
		exit 1
	}
	if (le_ext_adv_handle_min != "0x00" ||
	    le_ext_adv_handle_max != "0xef" ||
	    le_ext_adv_own_type_public != "0x00" ||
	    le_ext_adv_peer_type_public != "0x00" ||
	    le_ext_adv_peer_type_random != "0x01" ||
	    le_ext_adv_filter_policy_all != "0x00" ||
	    le_ext_adv_tx_power_no_preference != "0x7f" ||
	    le_ext_adv_primary_phy_1m != "0x01" ||
	    le_ext_adv_secondary_phy_1m != "0x01" ||
	    !(0 in le_ext_adv_channel_bit) ||
	    !(1 in le_ext_adv_channel_bit) ||
	    !(2 in le_ext_adv_channel_bit) ||
	    le_ext_adv_channel_bit[0] != 0 ||
	    le_ext_adv_channel_bit[1] != 1 ||
	    le_ext_adv_channel_bit[2] != 2) {
		print "incomplete LE extended advertising scalar extraction" > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= 11; i++) {
		if (hci_command[i] == "") {
			print "incomplete HCI command extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	if (gatt_hash_count != 16) {
		print "incomplete GATT Appendix B hash extraction: " gatt_hash_count > "/dev/stderr"
		exit 1
	}
	if (att_mtu_req_opcode == "" || att_mtu_rsp_opcode == "" ||
	    att_mtu_req_opcode_size != 1 || att_mtu_rsp_opcode_size != 1 ||
	    att_mtu_req_value_size != 2 || att_mtu_rsp_value_size != 2 ||
	    att_default_mtu != 23 || eatt_min_mtu != 64 ||
	    att_find_info_uuid16_format != "0x01" ||
	    att_find_info_uuid128_format != "0x02" ||
	    att_execute_cancel != "0x00" || att_execute_commit != "0x01" ||
	    bluetooth_base_uuid != "0000000000001000800000805f9b34fb") {
		print "incomplete ATT MTU extraction" > "/dev/stderr"
		exit 1
	}
	vector_required = "D1_KEY D1_1_OUT D1_2_MSG D1_2_OUT D1_3_MSG D1_3_OUT D1_4_MSG D1_4_OUT D2_U D2_V D2_X D2_OUT D3_DHKEY D3_N1 D3_N2 D3_A1 D3_A2 D3_LTK D3_MACKEY D4_N1 D4_N2 D4_MACKEY D4_R D4_IOCAP D4_A1 D4_A2 D4_OUT D5_U D5_V D5_X D5_Y D5_OUT D6_KEY D6_KEYID D6_OUT D7_IRK D7_PRAND D7_AES_OUT D7_AH D8_KEY D8_SALT D8_OUT D9_LTK D9_LINK_KEY D10_LTK D10_LINK_KEY D11_LINK_KEY D11_LTK D12_LINK_KEY D12_LTK"
	n_vector_required = split(vector_required, vector_name, " ")
	for (i = 1; i <= n_vector_required; i++) {
		if (vector[vector_name[i]] == "") {
			print "incomplete Core Appendix D vector " vector_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (vector_d2_z != "0x00") {
		print "incomplete Core Appendix D.2 Z vector" > "/dev/stderr"
		exit 1
	}
	legacy_required = "C1_KEY C1_R C1_PREQ C1_PRES C1_IAT C1_IA C1_RAT C1_RA C1_OUT S1_KEY S1_R1 S1_R2 S1_OUT"
	n_legacy_required = split(legacy_required, legacy_name, " ")
	for (i = 1; i <= n_legacy_required; i++) {
		if (legacy[legacy_name[i]] == "") {
			print "incomplete Core legacy vector " legacy_name[i] > "/dev/stderr"
			exit 1
		}
	}
	if (!saw_assoc_table || assoc_numeric_count != 4) {
		print "incomplete Core Table 2.8 association-model extraction" > "/dev/stderr"
		exit 1
	}
	if (random_address_mask != 192 || random_address_type[1] != 0 ||
	    random_address_type[2] != 64 || random_address_type[3] != 128 ||
	    random_address_type[4] != 192) {
		print "incomplete Core random-address subtype extraction" > "/dev/stderr"
		exit 1
	}
	if (f4_z_numeric_oob != "0x00" || f4_z_passkey_zero != "0x80" ||
	    f4_z_passkey_one != "0x81") {
		print "incomplete Core f4 Z-value extraction" > "/dev/stderr"
		exit 1
	}
	if (vector["SC_DEBUG_X"] == "" || vector["SC_DEBUG_Y"] == "") {
		print "incomplete Core Secure Connections debug-key extraction" > "/dev/stderr"
		exit 1
	}
	if (length(vector["LEGACY_PASSKEY_TK"]) != 32) {
		print "incomplete Core legacy passkey TK extraction" > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= 5; i++) {
		if (assoc_count[i] != 5) {
			print "incomplete Core Table 2.8 row " i > "/dev/stderr"
			exit 1
		}
	}
	if (assoc_sc[2, 2] != 2 || assoc_sc[2, 5] != 2 ||
	    assoc_sc[5, 2] != 2 || assoc_sc[5, 5] != 2) {
		print "unexpected Core Table 2.8 Numeric Comparison placement" > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= 8; i++) {
		if (gatt[i] == "") {
			print "incomplete GATT property extraction at index " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 1; i <= 14; i++) {
		if (smp_command_value[i] == "") {
			print "incomplete SMP command extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	if (!saw_key_dist_labels || !saw_key_dist_previous_label ||
	    !saw_key_dist_main_widths || !saw_key_dist_previous_width) {
		print "incomplete Core Figure 3.11 key-distribution extraction" > "/dev/stderr"
		exit 1
	}
	for (i = 1; i <= 16; i++) {
		if (smp_failure_value[i] == "") {
			print "incomplete SMP failure extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 0; i <= 4; i++) {
		if (smp_io_value[i] == "") {
			print "incomplete SMP IO capability extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	for (i = 0; i <= 4; i++) {
		if (smp_keypress_value[i] != sprintf("0x%02x", i)) {
			print "incomplete SMP Table 3.8 Keypress Notification extraction at " i > "/dev/stderr"
			exit 1
		}
	}
	if (smp_keypress_reserved_first != 5 || smp_keypress_reserved_last != 255) {
		print "incomplete SMP Table 3.8 reserved Keypress range" > "/dev/stderr"
		exit 1
	}
	if (!saw_smp_authreq_layout || !saw_smp_authreq_widths) {
		print "incomplete SMP AuthReq layout extraction" > "/dev/stderr"
		exit 1
	}
	if (smp_io_reserved_first != "0x05" || smp_io_reserved_last != "0xff") {
		print "incomplete SMP reserved IO-capability range extraction" > "/dev/stderr"
		exit 1
	}
	if (smp_identity_addr_public != "0x00" ||
	    smp_identity_addr_static_random != "0x01") {
		print "incomplete SMP identity address-type extraction" > "/dev/stderr"
		exit 1
	}
	if (smp_key_size_min != 7 || smp_key_size_max != 16) {
		print "incomplete SMP key size range extraction" > "/dev/stderr"
		exit 1
	}

	print "/* Generated from Bluetooth Core 6.3 text; do not edit. */"
	print "#ifndef TESTS_BLUETOOTH_SPEC_CORE63_GENERATED_H"
	print "#define TESTS_BLUETOOTH_SPEC_CORE63_GENERATED_H"
	print ""
	print "/* Vol 3, Part C, Section 11, Figure 11.1. */"
	print "#define BT_CORE63_AD_LENGTH_OFFSET 0"
	print "#define BT_CORE63_AD_LENGTH_SIZE " ad_structure_length_size
	print "#define BT_CORE63_AD_TYPE_OFFSET " ad_structure_length_size
	print "#define BT_CORE63_AD_TYPE_SIZE " ad_structure_type_size
	print "#define BT_CORE63_AD_PAYLOAD_OFFSET " (ad_structure_length_size + ad_structure_type_size)
	print ""
	print "/* Vol 3, Part F, Section 3.4.8, Table 3.42. */"
	print "#define BT_CORE63_ATT_ORACLES(X) \\"
	for (i = 1; i <= att_count; i++)
		printf "\tX(%s, %s)%s\n", att_symbol[i], att_value[i], (i == att_count ? "" : " \\")
	print ""
	print "/* Vol 3, Part F, Section 3.4.1, Table 3.4. */"
	print "#define BT_CORE63_ATT_ERROR_ORACLES(X) \\"
	for (i = 1; i <= error_count; i++)
		printf "\tX(%s, %s)%s\n", err_symbol[i], error_value[i], (i == error_count ? "" : " \\")
	print ""
	print "/* Vol 3, Part F, Sections 3.4.2.1-2, Tables 3.5-3.6; Vol 3, Part G, Section 5.2.1, Table 5.1. */"
	print "#define BT_CORE63_ATT_MTU_REQ_OPCODE " att_mtu_req_opcode
	print "#define BT_CORE63_ATT_MTU_RSP_OPCODE " att_mtu_rsp_opcode
	print "#define BT_CORE63_ATT_MTU_PDU_SIZE " (att_mtu_req_opcode_size + att_mtu_req_value_size)
	print "#define BT_CORE63_ATT_DEFAULT_MTU " att_default_mtu
	print "/* Vol 3, Part G, Section 5.3.1. */"
	print "#define BT_CORE63_EATT_MIN_MTU " eatt_min_mtu
	print "/* Vol 3, Part F, Section 3.4.3.2, Table 3.9. */"
	print "#define BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16 " att_find_info_uuid16_format
	print "#define BT_CORE63_ATT_FIND_INFO_FORMAT_UUID128 " att_find_info_uuid128_format
	print "/* Vol 3, Part F, Section 3.4.6.3, Table 3.35. */"
	print "#define BT_CORE63_ATT_EXECUTE_CANCEL " att_execute_cancel
	print "#define BT_CORE63_ATT_EXECUTE_COMMIT " att_execute_commit
	print "/* Vol 3, Part B, Section 2.5.1; first 12 LE octets. */"
	printf "#define BT_CORE63_BLUETOOTH_BASE_UUID_LE12 { "
	for (i = 16; i >= 5; i--) {
		printf "0x%s", substr(bluetooth_base_uuid, (i - 1) * 2 + 1, 2)
		printf "%s", (i == 5 ? " }\n" : ", ")
	}
	print ""
	print "/* Vol 3, Part G, Section 3.3.1.1, Table 3.5 (current assignments). */"
	print "#define BT_CORE63_GATT_PROPERTY_ORACLES(X) \\"
	printf "\tX(GATT_PROP_BROADCAST, %s) \\\n", gatt[1]
	printf "\tX(GATT_PROP_READ, %s) \\\n", gatt[2]
	printf "\tX(GATT_PROP_WRITE_NO_RSP, %s) \\\n", gatt[3]
	printf "\tX(GATT_PROP_WRITE, %s) \\\n", gatt[4]
	printf "\tX(GATT_PROP_NOTIFY, %s) \\\n", gatt[5]
	printf "\tX(GATT_PROP_INDICATE, %s) \\\n", gatt[6]
	printf "\tX(GATT_PROP_EXTENDED, %s)\n", gatt[8]
	print ""
	print "/* Vol 3, Part H, Section 3.3, Table 3.3 (current commands). */"
	print "#define BT_CORE63_SMP_COMMAND_ORACLES(X) \\"
	for (i = 1; i <= 14; i++) {
		if (i == 10)
			continue
		printf "\tX(%s, %s)%s\n", smp_command_symbol[i], \
		    smp_command_value[i], (i == 14 ? "" : " \\")
	}
	print ""
	print "/* Vol 3, Part H, Section 3.5.5, Table 3.7. */"
	print "#define BT_CORE63_SMP_FAILURE_ORACLES(X) \\"
	for (i = 1; i <= 16; i++)
		printf "\tX(%s, %s)%s\n", smp_failure_symbol[i], \
		    smp_failure_value[i], (i == 16 ? "" : " \\")
	print ""
	print "/* Vol 3, Part H, Section 3.5.1, Table 3.4 and Figure 3.3. */"
	print "#define BT_CORE63_SMP_SCALAR_ORACLES(X) \\"
	for (i = 0; i <= 4; i++)
		printf "\tX(%s, %s) \\\n", smp_io_symbol[i], smp_io_value[i]
	print "\tX(SMP_AUTH_BONDING, " sprintf("0x%02x", 2 ^ 0) ") \\"
	print "\tX(SMP_AUTH_MITM, " sprintf("0x%02x", 2 ^ 2) ") \\"
	print "\tX(SMP_AUTH_SC, " sprintf("0x%02x", 2 ^ 3) ") \\"
	print "\tX(SMP_AUTH_KEYPRESS, " sprintf("0x%02x", 2 ^ 4) ") \\"
	print "\tX(SMP_AUTH_CT2, " sprintf("0x%02x", 2 ^ 5) ")"
	print "#define BT_CORE63_SMP_PAIRING_REQUEST_OPCODE " smp_command_value[1]
	print "#define BT_CORE63_SMP_PAIRING_RESPONSE_OPCODE " smp_command_value[2]
	print "#define BT_CORE63_SMP_PAIRING_FAILED_OPCODE " smp_command_value[5]
	print "#define BT_CORE63_SMP_ENCRYPTION_INFORMATION_OPCODE " smp_command_value[6]
	print "#define BT_CORE63_SMP_CENTRAL_IDENTIFICATION_OPCODE " smp_command_value[7]
	print "#define BT_CORE63_SMP_IDENTITY_INFORMATION_OPCODE " smp_command_value[8]
	print "#define BT_CORE63_SMP_IDENTITY_ADDRESS_INFO_OPCODE " smp_command_value[9]
	print "#define BT_CORE63_SMP_INVALID_PARAMETERS_ERROR " smp_failure_value[10]
	print "#define BT_CORE63_SMP_ENCRYPTION_KEY_SIZE_ERROR " smp_failure_value[6]
	print "#define BT_CORE63_SMP_AUTH_BONDING " sprintf("0x%02x", 2 ^ 0)
	print "#define BT_CORE63_SMP_AUTH_SC " sprintf("0x%02x", 2 ^ 3)
	print "#define BT_CORE63_SMP_MIN_KEY_SIZE " smp_key_size_min
	print "#define BT_CORE63_SMP_MAX_KEY_SIZE " smp_key_size_max
	print "#define BT_CORE63_SMP_IO_RESERVED_FIRST " smp_io_reserved_first
	print "#define BT_CORE63_SMP_IO_RESERVED_LAST " smp_io_reserved_last
	print "#define BT_CORE63_SMP_ID_ADDR_PUBLIC " smp_identity_addr_public
	print "#define BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM " smp_identity_addr_static_random
	print ""
	print "/* Vol 3, Part H, Section 3.6.1, Figure 3.11. */"
	print "#define BT_CORE63_SMP_KEY_DIST_ORACLES(X) \\"
	print "\tX(SMP_KEY_DIST_ENC_KEY, " sprintf("0x%02x", 2 ^ 0) ") \\"
	print "\tX(SMP_KEY_DIST_ID_KEY, " sprintf("0x%02x", 2 ^ 1) ") \\"
	print "\tX(SMP_KEY_DIST_LINK_KEY, " sprintf("0x%02x", 2 ^ 3) ")"
	print "#define BT_CORE63_SMP_KEY_DIST_ENC_KEY " sprintf("0x%02x", 2 ^ 0)
	print "#define BT_CORE63_SMP_KEY_DIST_ID_KEY " sprintf("0x%02x", 2 ^ 1)
	print "#define BT_CORE63_SMP_KEY_DIST_LINK_KEY " sprintf("0x%02x", 2 ^ 3)
	print "#define BT_CORE63_SMP_KEY_DIST_DEFAULT_MASK " sprintf("0x%02x", (2 ^ 0) + (2 ^ 1) + (2 ^ 3))
	print "#define BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK " sprintf("0x%02x", 2 ^ 2)
	print ""
	print "/* Vol 3, Part H, Section 3.5.8, Table 3.8. */"
	print "#define BT_CORE63_SMP_KEYPRESS_ORACLES(X) \\"
	for (i = 0; i <= 4; i++)
		printf "\tX(%s, %s)%s\n", smp_keypress_symbol[i], smp_keypress_value[i], (i == 4 ? "" : " \\")
	print ""
	print "/* Vol 3, Part A, Section 2.1, Tables 2.1 and 2.3. */"
	print "#define BT_CORE63_L2CAP_CID_ORACLES(X) \\"
	print "\tX(NG_L2CAP_SIGNAL_CID, 0x0001) \\"
	print "\tX(NG_L2CAP_CLT_CID, 0x0002) \\"
	print "\tX(NG_L2CAP_ATT_CID, 0x0004) \\"
	print "\tX(NG_L2CAP_LESIGNAL_CID, 0x0005) \\"
	print "\tX(NG_L2CAP_SMP_CID, 0x0006) \\"
	print "\tX(NG_L2CAP_FIRST_CID, 0x0040) \\"
	print "\tX(NG_L2CAP_LELAST_CID, 0x007f)"
	print ""
	print "/* Vol 3, Part A, Section 4, Table 4.2. */"
	print "#define BT_CORE63_L2CAP_COMMAND_ORACLES(X) \\"
	for (i = 1; i <= 26; i++) {
		if (!(i in l2cap_command_symbol))
			continue
		printf "\tX(%s, %s)%s\n", l2cap_command_symbol[i], \
		    l2cap_command_value[i], (i == 26 ? "" : " \\")
	}
	print ""
	print "/* Vol 3, Part A, Section 4.25, Table 4.17. */"
	print "#define BT_CORE63_L2CAP_RESULT_ORACLES(X) \\"
	for (i = 0; i <= 15; i++) {
		if (!(i in l2cap_result_symbol))
			continue
		printf "\tX(%s, %s)%s\n", l2cap_result_symbol[i], \
		    l2cap_result_value[i], (i == 15 ? "" : " \\")
	}
	print ""
	print "/* Vol 3, Part A, Section 4.27, Table 4.18. */"
	print "#define BT_CORE63_L2CAP_RECONFIG_RESULT_ORACLES(X) \\"
	for (i = 0; i <= 4; i++)
		printf "\tX(%s, %s)%s\n", l2cap_reconfig_symbol[i], \
		    l2cap_reconfig_value[i], (i == 4 ? "" : " \\")
	print ""
	print "/* Vol 3, Part A, Figures 4.18-4.24; fixed fields only. */"
	print "#define BT_CORE63_L2CAP_LE_CREDIT_CON_REQ_SIZE 10"
	print "#define BT_CORE63_L2CAP_LE_CREDIT_CON_RSP_SIZE 10"
	print "#define BT_CORE63_L2CAP_FLOW_CREDIT_SIZE 4"
	print "#define BT_CORE63_L2CAP_CREDIT_CON_REQ_SIZE 8"
	print "#define BT_CORE63_L2CAP_CREDIT_CON_RSP_SIZE 8"
	print "#define BT_CORE63_L2CAP_RECONFIG_REQ_SIZE 4"
	print "#define BT_CORE63_L2CAP_RECONFIG_RSP_SIZE 2"
	print ""
	print "/* Vol 4, Part E, Sections 7.7.5, 7.7.8, 7.7.14, 7.7.15, 7.7.19, 7.7.65, 7.7.75. */"
	print "#define BT_CORE63_HCI_EVENT_ORACLES(X) \\"
	for (i = 1; i <= 8; i++)
		printf "\tX(%s, %s)%s\n", hci_event_symbol[i], hci_event[i], \
		    (i == 8 ? "" : " \\")
	print "#define BT_CORE63_HCI_ENCRYPTION_CHANGE_V1_EVENT " hci_event[2]
	print "#define BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_EVENT " hci_event[3]
	print "#define BT_CORE63_HCI_ENCRYPTION_CHANGE_V1_PARAM_SIZE " \
	    (hci_encryption_status_size + hci_encryption_handle_size + \
	    hci_encryption_enabled_size)
	print "#define BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_PARAM_SIZE " \
	    (hci_encryption_status_size + hci_encryption_handle_size + \
	    hci_encryption_enabled_size + hci_encryption_key_size_size)
	print "#define BT_CORE63_HCI_ENCRYPTION_STATUS_SUCCESS 0x00"
	print "#define BT_CORE63_HCI_ENCRYPTION_OFF " hci_encryption_off
	print "#define BT_CORE63_HCI_ENCRYPTION_LE_ON " hci_encryption_le_on
	print "#define BT_CORE63_HCI_ENCRYPTION_BREDR_AES_ON " hci_encryption_bredr_on
	print "#define BT_CORE63_HCI_ENCRYPTION_ENABLED_RESERVED_FIRST " \
	    sprintf("0x%02x", hex2dec(hci_encryption_bredr_on) + 1)
	print "#define BT_CORE63_HCI_EVENT_MASK_PAGE2_APTO_BIT " hci_page2_apto_bit
	print "#define BT_CORE63_HCI_SET_EVENT_MASK_PAGE2_OCF " hci_page2_ocf
	print "#define BT_CORE63_HCI_EVENT_MASK_PAGE2_ENCRYPTION_V2_BIT " \
	    hci_page2_encryption_v2_bit
	print "#define BT_CORE63_HCI_EVENT_MASK_PAGE2_DEFAULT \\"
	print "\t((UINT64_C(1) << BT_CORE63_HCI_EVENT_MASK_PAGE2_APTO_BIT) | \\"
	print "\t (UINT64_C(1) << BT_CORE63_HCI_EVENT_MASK_PAGE2_ENCRYPTION_V2_BIT))"
	print "#define BT_CORE63_LE_FEAT_ENCRYPTION (UINT64_C(1) << " le_feature_bit["ENCRYPTION"] ")"
	print "#define BT_CORE63_LE_FEAT_CONN_PARAM_REQ (UINT64_C(1) << " le_feature_bit["CONN_PARAM"] ")"
	print "#define BT_CORE63_LE_FEAT_2M_PHY (UINT64_C(1) << " le_feature_bit["2M_PHY"] ")"
	print "#define BT_CORE63_LE_FEAT_CONN_CTE_REQ (UINT64_C(1) << " le_feature_bit["CONN_CTE_REQ"] ")"
	print "#define BT_CORE63_LE_FEAT_CONNLESS_CTE_RX (UINT64_C(1) << " le_feature_bit["CONNLESS_CTE_RX"] ")"
	print "#define BT_CORE63_LE_FEAT_POWER_CONTROL (UINT64_C(1) << " le_feature_bit["POWER_CONTROL"] ")"
	print "#define BT_CORE63_LE_FEAT_PATH_LOSS_MONITORING (UINT64_C(1) << " le_feature_bit["PATH_LOSS"] ")"
	print "#define BT_CORE63_LE_FEAT_CONN_SUBRATING (UINT64_C(1) << " le_feature_bit["SUBRATING"] ")"
	print "#define BT_CORE63_LE_EVTMASK_CONNLESS_IQ_REPORT (UINT64_C(1) << " le_event_bit["CONNLESS_IQ"] ")"
	print "#define BT_CORE63_LE_EVTMASK_CONN_IQ_REPORT (UINT64_C(1) << " le_event_bit["CONN_IQ"] ")"
	print "#define BT_CORE63_LE_EVTMASK_CTE_REQ_FAILED (UINT64_C(1) << " le_event_bit["CTE_FAILED"] ")"
	print "#define BT_CORE63_LE_EVTMASK_PATH_LOSS_THRESH (UINT64_C(1) << " le_event_bit["PATH_LOSS"] ")"
	print "#define BT_CORE63_LE_EVTMASK_TX_POWER_REPORT (UINT64_C(1) << " le_event_bit["TX_POWER"] ")"
	print "#define BT_CORE63_LE_EVTMASK_SUBRATE_CHANGE (UINT64_C(1) << " le_event_bit["SUBRATE"] ")"
	ext_adv_offset["EVENT_TYPE"] = 0
	ext_adv_offset["ADDRESS_TYPE"] = ext_adv_offset["EVENT_TYPE"] + ext_adv_size["EVENT_TYPE"]
	ext_adv_offset["ADDRESS"] = ext_adv_offset["ADDRESS_TYPE"] + ext_adv_size["ADDRESS_TYPE"]
	ext_adv_offset["PRIMARY_PHY"] = ext_adv_offset["ADDRESS"] + ext_adv_size["ADDRESS"]
	ext_adv_offset["SECONDARY_PHY"] = ext_adv_offset["PRIMARY_PHY"] + ext_adv_size["PRIMARY_PHY"]
	ext_adv_offset["ADVERTISING_SID"] = ext_adv_offset["SECONDARY_PHY"] + ext_adv_size["SECONDARY_PHY"]
	ext_adv_offset["TX_POWER"] = ext_adv_offset["ADVERTISING_SID"] + ext_adv_size["ADVERTISING_SID"]
	ext_adv_offset["RSSI"] = ext_adv_offset["TX_POWER"] + ext_adv_size["TX_POWER"]
	ext_adv_offset["PERIODIC_INTERVAL"] = ext_adv_offset["RSSI"] + ext_adv_size["RSSI"]
	ext_adv_offset["DIRECT_ADDRESS_TYPE"] = ext_adv_offset["PERIODIC_INTERVAL"] + ext_adv_size["PERIODIC_INTERVAL"]
	ext_adv_offset["DIRECT_ADDRESS"] = ext_adv_offset["DIRECT_ADDRESS_TYPE"] + ext_adv_size["DIRECT_ADDRESS_TYPE"]
	ext_adv_offset["DATA_LENGTH"] = ext_adv_offset["DIRECT_ADDRESS"] + ext_adv_size["DIRECT_ADDRESS"]
	ext_adv_fixed_size = ext_adv_offset["DATA_LENGTH"] + ext_adv_size["DATA_LENGTH"]
	print "/* Vol 4, Part E, Section 7.7.65.13 parameter table. */"
	print "#define BT_CORE63_EXT_ADV_EVENT_TYPE_OFFSET " ext_adv_offset["EVENT_TYPE"]
	print "#define BT_CORE63_EXT_ADV_ADDRESS_TYPE_OFFSET " ext_adv_offset["ADDRESS_TYPE"]
	print "#define BT_CORE63_EXT_ADV_ADDRESS_OFFSET " ext_adv_offset["ADDRESS"]
	print "#define BT_CORE63_EXT_ADV_PRIMARY_PHY_OFFSET " ext_adv_offset["PRIMARY_PHY"]
	print "#define BT_CORE63_EXT_ADV_DATA_LENGTH_OFFSET " ext_adv_offset["DATA_LENGTH"]
	print "#define BT_CORE63_EXT_ADV_FIXED_SIZE " ext_adv_fixed_size
	print "#define BT_CORE63_EXT_ADV_ADDRESS_SIZE " ext_adv_size["ADDRESS"]
	print "#define BT_CORE63_EXT_ADV_ADDR_PUBLIC " ext_adv_addr_type["PUBLIC"]
	print "#define BT_CORE63_EXT_ADV_ADDR_RANDOM " ext_adv_addr_type["RANDOM"]
	print "#define BT_CORE63_EXT_ADV_ADDR_PUBLIC_IDENTITY " ext_adv_addr_type["PUBLIC_IDENTITY"]
	print "#define BT_CORE63_EXT_ADV_ADDR_RANDOM_IDENTITY " ext_adv_addr_type["RANDOM_IDENTITY"]
	print "#define BT_CORE63_EXT_ADV_ADDR_ANONYMOUS " ext_adv_addr_type["ANONYMOUS"]
	print "#define BT_CORE63_EXT_ADV_PRIMARY_PHY_1M " ext_adv_primary_phy_1m
	print "#define BT_CORE63_EXT_ADV_DATA_LENGTH_MIN " ext_adv_data_length_min
	print "#define BT_CORE63_EXT_ADV_DATA_LENGTH_MAX " ext_adv_data_length_max
	le_scan_parameters_offset["SCAN_TYPE"] = 0
	le_scan_parameters_offset["SCAN_INTERVAL"] = le_scan_parameters_offset["SCAN_TYPE"] + le_scan_parameters_size["SCAN_TYPE"]
	le_scan_parameters_offset["SCAN_WINDOW"] = le_scan_parameters_offset["SCAN_INTERVAL"] + le_scan_parameters_size["SCAN_INTERVAL"]
	le_scan_parameters_offset["OWN_ADDRESS_TYPE"] = le_scan_parameters_offset["SCAN_WINDOW"] + le_scan_parameters_size["SCAN_WINDOW"]
	le_scan_parameters_offset["FILTER_POLICY"] = le_scan_parameters_offset["OWN_ADDRESS_TYPE"] + le_scan_parameters_size["OWN_ADDRESS_TYPE"]
	le_scan_parameters_fixed_size = le_scan_parameters_offset["FILTER_POLICY"] + le_scan_parameters_size["FILTER_POLICY"]
	print "/* Vol 4, Part E, Section 7.8.10 command parameter table. */"
	print "#define BT_CORE63_LE_SET_SCAN_PARAMETERS_OCF " le_scan_parameters_ocf
	print "#define BT_CORE63_LE_SCAN_OWN_ADDRESS_TYPE_OFFSET " le_scan_parameters_offset["OWN_ADDRESS_TYPE"]
	print "#define BT_CORE63_LE_SCAN_PARAMETERS_SIZE " le_scan_parameters_fixed_size
	print "#define BT_CORE63_LE_OWN_ADDR_PUBLIC " le_scan_own_address_type["PUBLIC"]
	print "#define BT_CORE63_LE_OWN_ADDR_RANDOM " le_scan_own_address_type["RANDOM"]
	print "#define BT_CORE63_LE_OWN_ADDR_RPA_PUBLIC_FALLBACK " le_scan_own_address_type["RPA_PUBLIC_FALLBACK"]
	print "#define BT_CORE63_LE_OWN_ADDR_RPA_RANDOM_FALLBACK " le_scan_own_address_type["RPA_RANDOM_FALLBACK"]
	print "#define BT_CORE63_LE_OWN_ADDR_RESERVED_FIRST " sprintf("0x%02x", hex2dec(le_scan_own_address_type["RPA_RANDOM_FALLBACK"]) + 1)
	le_adv_offset["INTERVAL_MIN"] = 0
	le_adv_offset["INTERVAL_MAX"] = le_adv_offset["INTERVAL_MIN"] + le_adv_parameters_size["INTERVAL_MIN"]
	le_adv_offset["ADV_TYPE"] = le_adv_offset["INTERVAL_MAX"] + le_adv_parameters_size["INTERVAL_MAX"]
	le_adv_offset["OWN_ADDRESS_TYPE"] = le_adv_offset["ADV_TYPE"] + le_adv_parameters_size["ADV_TYPE"]
	le_adv_offset["PEER_ADDRESS_TYPE"] = le_adv_offset["OWN_ADDRESS_TYPE"] + le_adv_parameters_size["OWN_ADDRESS_TYPE"]
	le_adv_offset["PEER_ADDRESS"] = le_adv_offset["PEER_ADDRESS_TYPE"] + le_adv_parameters_size["PEER_ADDRESS_TYPE"]
	le_adv_offset["CHANNEL_MAP"] = le_adv_offset["PEER_ADDRESS"] + le_adv_parameters_size["PEER_ADDRESS"]
	le_adv_offset["FILTER_POLICY"] = le_adv_offset["CHANNEL_MAP"] + le_adv_parameters_size["CHANNEL_MAP"]
	le_adv_fixed_size = le_adv_offset["FILTER_POLICY"] + le_adv_parameters_size["FILTER_POLICY"]
	print "/* Vol 4, Part E, Section 7.8.5 command parameter table. */"
	print "#define BT_CORE63_LE_SET_ADV_PARAMETERS_OCF " le_adv_parameters_ocf
	print "#define BT_CORE63_LE_ADV_PARAMETERS_SIZE " le_adv_fixed_size
	print "#define BT_CORE63_LE_ADV_TYPE_OFFSET " le_adv_offset["ADV_TYPE"]
	print "#define BT_CORE63_LE_ADV_PEER_ADDRESS_TYPE_OFFSET " le_adv_offset["PEER_ADDRESS_TYPE"]
	print "#define BT_CORE63_LE_ADV_PEER_ADDRESS_OFFSET " le_adv_offset["PEER_ADDRESS"]
	print "#define BT_CORE63_LE_ADV_PEER_ADDRESS_SIZE " le_adv_parameters_size["PEER_ADDRESS"]
	print "#define BT_CORE63_LE_ADV_INTERVAL_MIN " le_adv_interval_min
	print "#define BT_CORE63_LE_ADV_TYPE_UNDIRECTED " le_adv_type["UNDIRECTED"]
	print "#define BT_CORE63_LE_ADV_TYPE_DIRECTED_HIGH " le_adv_type["DIRECTED_HIGH"]
	print "#define BT_CORE63_LE_ADV_TYPE_DIRECTED_LOW " le_adv_type["DIRECTED_LOW"]
	print "#define BT_CORE63_LE_ADV_PEER_ADDR_PUBLIC " le_adv_peer_type["PUBLIC"]
	print "#define BT_CORE63_LE_ADV_PEER_ADDR_RANDOM " le_adv_peer_type["RANDOM"]
	print "#define BT_CORE63_LE_ADV_OWN_ADDR_PUBLIC " le_adv_own_type_public
	print "#define BT_CORE63_LE_ADV_FILTER_POLICY_ALL " le_adv_filter_policy_all
	le_ext_adv_offset["HANDLE"] = 0
	le_ext_adv_offset["EVENT_PROPERTIES"] = le_ext_adv_offset["HANDLE"] + le_ext_adv_size["HANDLE"]
	le_ext_adv_offset["INTERVAL_MIN"] = le_ext_adv_offset["EVENT_PROPERTIES"] + le_ext_adv_size["EVENT_PROPERTIES"]
	le_ext_adv_offset["INTERVAL_MAX"] = le_ext_adv_offset["INTERVAL_MIN"] + le_ext_adv_size["INTERVAL_MIN"]
	le_ext_adv_offset["CHANNEL_MAP"] = le_ext_adv_offset["INTERVAL_MAX"] + le_ext_adv_size["INTERVAL_MAX"]
	le_ext_adv_offset["OWN_ADDRESS_TYPE"] = le_ext_adv_offset["CHANNEL_MAP"] + le_ext_adv_size["CHANNEL_MAP"]
	le_ext_adv_offset["PEER_ADDRESS_TYPE"] = le_ext_adv_offset["OWN_ADDRESS_TYPE"] + le_ext_adv_size["OWN_ADDRESS_TYPE"]
	le_ext_adv_offset["PEER_ADDRESS"] = le_ext_adv_offset["PEER_ADDRESS_TYPE"] + le_ext_adv_size["PEER_ADDRESS_TYPE"]
	le_ext_adv_offset["FILTER_POLICY"] = le_ext_adv_offset["PEER_ADDRESS"] + le_ext_adv_size["PEER_ADDRESS"]
	le_ext_adv_offset["TX_POWER"] = le_ext_adv_offset["FILTER_POLICY"] + le_ext_adv_size["FILTER_POLICY"]
	le_ext_adv_offset["PRIMARY_PHY"] = le_ext_adv_offset["TX_POWER"] + le_ext_adv_size["TX_POWER"]
	le_ext_adv_offset["SECONDARY_MAX_SKIP"] = le_ext_adv_offset["PRIMARY_PHY"] + le_ext_adv_size["PRIMARY_PHY"]
	le_ext_adv_offset["SECONDARY_PHY"] = le_ext_adv_offset["SECONDARY_MAX_SKIP"] + le_ext_adv_size["SECONDARY_MAX_SKIP"]
	le_ext_adv_offset["SID"] = le_ext_adv_offset["SECONDARY_PHY"] + le_ext_adv_size["SECONDARY_PHY"]
	le_ext_adv_offset["SCAN_REQUEST_NOTIFY"] = le_ext_adv_offset["SID"] + le_ext_adv_size["SID"]
	le_ext_adv_fixed_size = le_ext_adv_offset["SCAN_REQUEST_NOTIFY"] + le_ext_adv_size["SCAN_REQUEST_NOTIFY"]
	print "/* Vol 4, Part E, Section 7.8.53 command parameter table. */"
	print "#define BT_CORE63_LE_EXT_ADV_PARAMETERS_SIZE " le_ext_adv_fixed_size
	print "#define BT_CORE63_LE_EXT_ADV_EVENT_PROPERTIES_OFFSET " le_ext_adv_offset["EVENT_PROPERTIES"]
	print "#define BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_TYPE_OFFSET " le_ext_adv_offset["PEER_ADDRESS_TYPE"]
	print "#define BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_OFFSET " le_ext_adv_offset["PEER_ADDRESS"]
	print "#define BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_SIZE " le_ext_adv_size["PEER_ADDRESS"]
	print "#define BT_CORE63_LE_EXT_ADV_INTERVAL_MIN " le_ext_adv_interval_min
	print "#define BT_CORE63_LE_EXT_ADV_HANDLE_MIN " le_ext_adv_handle_min
	print "#define BT_CORE63_LE_EXT_ADV_OWN_ADDR_PUBLIC " le_ext_adv_own_type_public
	print "#define BT_CORE63_LE_EXT_ADV_PEER_ADDR_PUBLIC " le_ext_adv_peer_type_public
	print "#define BT_CORE63_LE_EXT_ADV_PEER_ADDR_RANDOM " le_ext_adv_peer_type_random
	print "#define BT_CORE63_LE_EXT_ADV_CHANNEL_MAP_ALL " sprintf("0x%02x", (2 ^ le_ext_adv_channel_bit[0]) + (2 ^ le_ext_adv_channel_bit[1]) + (2 ^ le_ext_adv_channel_bit[2]))
	print "#define BT_CORE63_LE_EXT_ADV_FILTER_POLICY_ALL " le_ext_adv_filter_policy_all
	print "#define BT_CORE63_LE_EXT_ADV_TX_POWER_NO_PREFERENCE " le_ext_adv_tx_power_no_preference
	print "#define BT_CORE63_LE_EXT_ADV_PRIMARY_PHY_1M " le_ext_adv_primary_phy_1m
	print "#define BT_CORE63_LE_EXT_ADV_SECONDARY_PHY_1M " le_ext_adv_secondary_phy_1m
	print "#define BT_CORE63_LE_EXT_ADV_PROP_CONNECTABLE (UINT16_C(1) << " le_ext_adv_property_bit["CONNECTABLE"] ")"
	print "#define BT_CORE63_LE_EXT_ADV_PROP_DIRECTED (UINT16_C(1) << " le_ext_adv_property_bit["DIRECTED"] ")"
	print "#define BT_CORE63_LE_EXT_ADV_PROP_HIGH_DUTY_DIRECTED (UINT16_C(1) << " le_ext_adv_property_bit["HIGH_DUTY_DIRECTED"] ")"
	print "#define BT_CORE63_LE_EXT_ADV_PROP_LEGACY (UINT16_C(1) << " le_ext_adv_property_bit["LEGACY"] ")"
	print "#define BT_CORE63_LE_EXT_ADV_PROP_ANONYMOUS (UINT16_C(1) << " le_ext_adv_property_bit["ANONYMOUS"] ")"
	print "#define BT_CORE63_HCI_ENCRYPTION_HANDLE_MIN " hci_encryption_handle_min
	print "#define BT_CORE63_HCI_ENCRYPTION_HANDLE_MAX " hci_encryption_handle_max
	print ""
	print "/* Vol 4, Part E, Section 7.7.65 LE Meta subevent sections. */"
	print "#define BT_CORE63_HCI_LE_SUBEVENT_ORACLES(X) \\"
	for (i = 1; i <= 10; i++)
		printf "\tX(%s, %s)%s\n", hci_subevent_symbol[i], hci_subevent[i], \
		    (i == 10 ? "" : " \\")
	print ""
	print "/* Vol 4, Part A, Section 2, Table 2.1. */"
	print "#define BT_CORE63_HCI_PACKET_ORACLES(X) \\"
	print "\tX(NG_HCI_EVENT_PKT, " hci_packet ")"
	print ""
	print "/* Vol 4, Part E, Sections 7.8.1, 7.8.53, 7.8.61, 7.8.64, 7.8.97, 7.8.99, 7.8.101, 7.8.103, 7.8.109, and 7.8.123-124. */"
	print "#define BT_CORE63_HCI_COMMAND_ORACLES(X) \\"
	for (i = 1; i <= 11; i++)
		printf "\tX(%s, %s)%s\n", hci_command_symbol[i], hci_command[i], \
		    (i == 11 ? "" : " \\")
	print ""
	print "/* Vol 3, Part G, Appendix B, Example Database Hash. */"
	print "#define BT_CORE63_GATT_DATABASE_HASH_KAT_BYTES \\"
	for (i = 1; i <= 16; i++)
		printf "\t%s%s%s\n", gatt_hash[i], (i == 16 ? "" : ","), \
		    (i == 16 ? "" : " \\")
	print ""
	print "/* Vol 3, Part H, Appendix D.1-D.12; specification byte order. */"
	for (i = 1; i <= n_vector_required; i++)
		print "#define BT_CORE63_SMP_" vector_name[i] "_HEX \"" vector[vector_name[i]] "\""
	print "#define BT_CORE63_SMP_D2_Z " vector_d2_z
	print "#define BT_CORE63_SMP_D5_OUT_VALUE 0x" vector["D5_OUT"]
	print ""
	print "/* Vol 3, Part H, Sections 2.2.3-2.2.4 worked examples; specification byte order. */"
	for (i = 1; i <= n_legacy_required; i++)
		print "#define BT_CORE63_SMP_" legacy_name[i] "_HEX \"" legacy[legacy_name[i]] "\""
	print ""
	print "/* Vol 3, Part H, Section 2.3.5.1, Table 2.8; rows are responder, columns initiator. */"
	print "#define BT_CORE63_SMP_ASSOC_LEGACY_MATRIX \\"
	for (i = 1; i <= 5; i++)
		printf "\t{ %d, %d, %d, %d, %d }%s%s\n", assoc_legacy[i,1], assoc_legacy[i,2], assoc_legacy[i,3], assoc_legacy[i,4], assoc_legacy[i,5], (i == 5 ? "" : ","), (i == 5 ? "" : " \\")
	print "#define BT_CORE63_SMP_ASSOC_SC_MATRIX \\"
	for (i = 1; i <= 5; i++)
		printf "\t{ %d, %d, %d, %d, %d }%s%s\n", assoc_sc[i,1], assoc_sc[i,2], assoc_sc[i,3], assoc_sc[i,4], assoc_sc[i,5], (i == 5 ? "" : ","), (i == 5 ? "" : " \\")
	print ""
	print "/* Vol 6, Part B, Section 1.3.2, Table 1.2; Address[47:46]. */"
	print "#define BT_CORE63_RANDOM_ADDRESS_TYPE_MASK " sprintf("0x%02x", random_address_mask)
	print "#define BT_CORE63_RANDOM_ADDRESS_NONRESOLVABLE " sprintf("0x%02x", random_address_type[1])
	print "#define BT_CORE63_RANDOM_ADDRESS_RESOLVABLE " sprintf("0x%02x", random_address_type[2])
	print "#define BT_CORE63_RANDOM_ADDRESS_RESERVED " sprintf("0x%02x", random_address_type[3])
	print "#define BT_CORE63_RANDOM_ADDRESS_STATIC " sprintf("0x%02x", random_address_type[4])
	print ""
	print "/* Vol 3, Part H, Section 2.2.6 and Table 2.1; f4 Z values. */"
	print "#define BT_CORE63_SMP_F4_Z_NUMERIC_OOB " f4_z_numeric_oob
	print "#define BT_CORE63_SMP_F4_Z_PASSKEY_ZERO " f4_z_passkey_zero
	print "#define BT_CORE63_SMP_F4_Z_PASSKEY_ONE " f4_z_passkey_one
	print ""
	print "/* Vol 3, Part H, Section 2.3.5.6.1; Secure Connections debug public key. */"
	print "#define BT_CORE63_SMP_SC_DEBUG_X_HEX \"" vector["SC_DEBUG_X"] "\""
	print "#define BT_CORE63_SMP_SC_DEBUG_Y_HEX \"" vector["SC_DEBUG_Y"] "\""
	print ""
	print "/* Vol 3, Part H, Section 2.3.5.3; passkey 019655 worked example. */"
	print "#define BT_CORE63_SMP_LEGACY_PASSKEY_TK_HEX \"" vector["LEGACY_PASSKEY_TK"] "\""
	print ""
	print "/* Vol 1 Part E Section 2.4.2; Vol 3 Part A Table 2.1; Part F Table 3.42; Part G Table 3.5; Part H Table 3.3/Figure 3.11. */"
	print "#define BT_CORE63_PREVIOUSLY_USED_ORACLES(X) \\"
	print "\tX(ATT_OP_LEGACY_SIGNED_WRITE_CMD, 0xd2) \\"
	printf "\tX(GATT_PROP_LEGACY_AUTH_SIGNED_WRITE, %s) \\\n", gatt[7]
	printf "\tX(SMP_LEGACY_SIGNING_INFORMATION, %s) \\\n", smp_command_value[10]
	print "\tX(SMP_KEY_DIST_LEGACY_SIGN_KEY, 0x04) \\"
	print "\tX(NG_L2CAP_LEGACY_A2MP_CID, 0x0003)"
	print "#define BT_CORE63_LEGACY_SMP_SIGNING_OPCODE 0x0a"
	print "#define BT_CORE63_LEGACY_SMP_SIGN_KEY_MASK 0x04"
	print "#define BT_CORE63_LEGACY_L2CAP_A2MP_CID 0x0003"
	print ""
	print "#endif /* TESTS_BLUETOOTH_SPEC_CORE63_GENERATED_H */"
}
