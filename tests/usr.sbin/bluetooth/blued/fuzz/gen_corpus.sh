#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Generate seed corpora for the blued fuzz harnesses.  Seeds are valid
# (or near-valid) PDUs so the fuzzer starts from meaningful coverage
# instead of rediscovering the wire format byte by byte.
#
# Usage: sh gen_corpus.sh <corpus-dir>

set -eu

DIR="${1:-corpus}"

# Write raw bytes given as a hex string ("02 1700" etc.) to a file.
emit() {
	_dir="$1"; _name="$2"; _hex=$(printf '%s' "$3" | tr -d ' ')
	mkdir -p "$DIR/$_dir"
	python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))' \
	    "$_hex" > "$DIR/$_dir/$_name"
}

# Write a literal text file (for configuration parser seeds).
emit_text() {
	_dir="$1"; _name="$2"; _text="$3"
	mkdir -p "$DIR/$_dir"
	printf '%s\n' "$_text" > "$DIR/$_dir/$_name"
}

# ---- ATT server PDUs (opcode + params), Core Spec Vol 3 Part F ----
emit att_server mtu_req            "02 1700"                 # Exchange MTU, MTU=23
emit att_server find_info          "04 0100 ffff"           # Find Information 0x0001-0xFFFF
emit att_server find_by_type       "06 0100 ffff 0028 0018" # Find By Type Value, primary svc 0x1800
emit att_server read_by_group      "10 0100 ffff 0028"      # Read By Group Type, primary service
emit att_server read_by_type       "08 0100 ffff 0328"      # Read By Type, characteristic decl
emit att_server read_req           "0a 0300"                # Read handle 3
emit att_server read_blob          "0c 0600 0000"           # Read Blob handle 6 offset 0
emit att_server read_multiple      "0e 0300 0600"           # Read Multiple
emit att_server write_req          "12 0600 aabbccdd"       # Write handle 6
emit att_server write_cmd          "52 0600 01"             # Write Command
emit att_server prepare_write      "16 0600 0000 aabb"      # Prepare Write
emit att_server exec_write         "18 01"                  # Execute Write (commit)

# ---- Advertising data (AD structures), Core Spec Vol 3 Part C S11 ----
emit adv_data flags                "02 01 06"                       # Flags: LE General Disc
emit adv_data name                 "05 09 66 75 7a 7a"              # Complete Local Name "fuzz"
emit adv_data uuid16               "03 03 0f 18"                    # Complete 16-bit UUID 0x180F
emit adv_data combined             "02 01 06 05 09 66 75 7a 7a"     # Flags + Name

# ---- LE Extended Advertising Reports (24B header + AD), hci_scan.c ----
# Header: event_type(2) addr_type(1) addr(6) pphy(1) sphy(1) sid(1)
#         txpwr(1) rssi(1) per_int(2) dir_addr_type(1) dir_addr(6) data_len(1)
# followed by data_len bytes of AD structures.
emit adv_report flags_name \
    "0000 00 112233445566 01 01 00 f4 c0 0000 00 000000000000 09 020106 05094e414d45"
emit adv_report empty \
    "0000 00 aabbccddeeff 01 01 00 f4 c0 0000 00 000000000000 00"
emit adv_report uuid16 \
    "0000 01 010203040506 01 01 00 f4 c0 0000 00 000000000000 05 03 03 0f18"
# Raw AD-only seeds (drive hci_parse_ad_fields directly)
emit adv_report ad_name  "05 09 66 75 7a 7a"
emit adv_report ad_mfr   "05 ff ffff 0102"

# ---- ATT responses driving GATT discovery, gatt.c ----
# Read By Group Type Response: [0x11][entry_len=6][s,e,uuid]...
emit gatt_client group_rsp   "11 06 0100 0300 0018 0400 0700 0f18"
# Read By Type Response (characteristics): [0x09][entry_len=7][handle,props,vhandle,uuid]
emit gatt_client type_rsp    "09 07 0200 02 0300 0a2a 0500 04 0600 192a"
# Find Information Response (descriptors): [0x05][format=1][handle,uuid]...
emit gatt_client find_info   "05 01 0700 0229 0800 0429"
# Error Response: [0x01][req_op][handle][err]
emit gatt_client err_rsp     "01 10 0100 0a"

# ---- SMP responder PDUs (opcode + params), Core Spec Vol 3 Part H ----
# The harness splits input into length-prefixed SEQPACKET datagrams: each
# record is one byte of length N followed by N bytes of SMP PDU.
emit smp_responder pairing_req  "07 01 03 00 01 10 000f"   # Pairing Request
emit smp_responder pairing_cfrm "11 03 000102030405060708090a0b0c0d0e0f"  # Confirm
emit smp_responder pairing_rand "11 04 000102030405060708090a0b0c0d0e0f"  # Random
emit smp_responder id_info      "11 08 000102030405060708090a0b0c0d0e0f"  # Identity Info

# ---- L2CAP signalling C-frames, sys/.../ng_l2cap_evnt.c ----
# The fuzz_l2cap_sig harness frames each input as:
#     code, ident, ctrl, <command payload...>
# where ctrl bit0 selects BR/EDR(0) vs LE(1) signalling CID, bits1-2 pick a
# length-corruption mode (0 = well-formed), and bit3 connects the l2c hook.
# The harness prepends the L2CAP + command headers itself, so seeds carry
# only the three selector bytes plus the raw command parameters.
emit l2cap_sig cmd_rej        "01 01 00 0000"                      # Command Reject (BR/EDR)
emit l2cap_sig con_req        "02 01 00 0100 4000"                 # Connection Request psm=SDP scid=0x40
emit l2cap_sig cfg_req        "04 01 00 4000 0000 0102 a002"       # Config Request dcid=0x40 + MTU=672 opt
emit l2cap_sig discon_req     "06 01 00 4000 4100"                 # Disconnection Request dcid=0x40 scid=0x41
emit l2cap_sig echo_req       "08 01 00 deadbeef"                  # Echo Request + data
emit l2cap_sig info_mtu       "0a 01 00 0100"                      # Info Request: connectionless MTU
emit l2cap_sig info_extfeat   "0a 01 00 0200"                      # Info Request: extended features
emit l2cap_sig info_fixedchan "0a 01 00 0300"                      # Info Request: fixed channels
emit l2cap_sig param_update   "12 01 01 1800 2800 0000 0001"       # Conn Param Update Req (LE)
emit l2cap_sig le_credit_req  "14 01 01 2700 4000 4000 4000 0100"  # LE Credit Based Con Req (EATT)
emit l2cap_sig flow_credit    "16 01 01 4000 0a00"                 # Flow Control Credit cid=0x40 credits=10
emit l2cap_sig ecred_req      "17 01 01 2700 4000 4000 0100 4000 4100" # ECRED Con Req, 2 SCIDs
emit l2cap_sig ecred_reconfig "19 01 01 8002 8002 4000"            # ECRED Reconfigure Req mtu=mps=640
emit l2cap_sig ecred_recfg_rs "1a 01 01 0000"                      # ECRED Reconfigure Rsp success

# ---- Bluetooth Mesh secured Network PDUs, lib/libmesh/mesh_net.c ----
# Each seed is a complete obfuscated+encrypted Network PDU keyed with the
# fixed MshPRT_v1.1 Section 8.2.2 material the harness hardcodes (NID 0x68,
# IV Index 0x12345678), so mesh_net_decrypt() runs the real deobfuscate +
# AES-CCM + NetMIC path over them.  Sample data from MshPRT_v1.1 Section 8.3.
# Message #1 (Section 8.3.1): control PDU (CTL=1, 64-bit NetMIC), 28 octets.
emit mesh_net msg1_8_3_1 \
    "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"
# Message #6 segment #0 (Section 8.3.6): access PDU (CTL=0, 32-bit NetMIC), 29 octets.
emit mesh_net msg6_8_3_6 \
    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e"

# ---- Bluetooth Mesh Access PDUs, lib/libmesh/mesh_access.c + models ----
# Each seed is a cleartext Access PDU (opcode + parameters) as the upper
# transport hands up.  Config AppKey Add is the MshPRT Section 8.3.6 access
# payload; Health Current Status is the Section 8.3.18 access payload; the
# rest exercise the opcode-length forms and the Config/Health model parsers.
emit mesh_access appkey_add_8_3_6 \
    "0056341263964771734fbd76e3b40519d1d94a48"
emit mesh_access health_current_8_3_18 "0400000000"
emit mesh_access comp_data_status \
    "0200f10502000300640003000001020100000200f1053412000001000010"
emit mesh_access model_app_bind_sig "803d020006000010"
emit mesh_access model_app_bind_vnd "803d02000600f1053412"
emit mesh_access model_pub_set      "03020000c006000700000010"
emit mesh_access appkey_list        "80020056042361458907"
emit mesh_access fault_status       "0503f1050251"
emit mesh_access vendor_opcode      "ca123400aabbcc"
emit mesh_access reserved_7f        "7f"

# ---- Bluetooth Mesh multi-node simulator, lib/libmesh/mesh_sim.c ----
# The mesh_sim harness treats its input as an attacker-injected secured
# Network PDU on the shared medium (same Section 8.2.2 material the sim
# derives).  Reuse the Section 8.3 sample Network PDUs so the injected byte
# stream drives the whole node receive pipeline, plus a short blob that also
# exercises the Generic OnOff/Level parsers.
emit mesh_sim msg1_8_3_1 \
    "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"
emit mesh_sim msg6_8_3_6 \
    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e"
emit mesh_sim onoff_set "02010141"
emit mesh_sim level_set "0634121001"

# ---- blued v4 control-socket frames, ctl.c ----
# Each daemon seed starts with HELLO (4-byte zero capability mask), followed
# by one correlated CTL operation.  Headers are len:u32, type:u16, arg:u16 LE.
emit ctl_ipc status \
    "04000000 0100 0400 00000000 14000000 0c00 0100 01000000 0000 0000 0b00 0000 00000000 00000000"
emit ctl_ipc set_mtu \
    "04000000 0100 0400 00000000 14000000 0c00 0100 02000000 0000 0000 0300 0000 f7000000 00000000"
emit ctl_ipc adapter_caps \
    "04000000 0100 0400 00000000 14000000 0c00 0100 03000000 0000 0000 0c00 0000 02000000 00000000"
emit ctl_ipc bad_domain \
    "04000000 0100 0400 00000000 08000000 0c00 ffff 04000000 0000 0000"

# ---- libble v4 daemon frames, lib/libble/ble.c ----
emit ble_ipc hello "04000000 0100 0400 03000000"
emit ble_ipc ctl_reply \
    "10000000 0d00 0100 01000000 0000 0000 0300 0000 f7000000"
emit ble_ipc diagnostic_error "03000000 0400 0300 626164"
emit ble_ipc malformed_length "ffffffff 0e00 0300"

# ---- L2CAP credit DATA-path K-frames, sys/.../ng_l2cap_ulpi.c ----
# The fuzz_l2cap_data harness frames each input as:
#     cfg, <len, len-bytes>, <len, len-bytes>, ...
# cfg tunes the open channel (bit1..2 local MPS, bit3..6 local credits,
# bit7 small/large MTU); each following length-prefixed record is fed as an
# incoming K-frame.  A first K-frame carries a 2-byte little-endian SDU-Length
# prefix; continuation K-frames do not (Core Spec Vol 3 Part A Section 3.4.3).
emit l2cap_data one_kframe    "40 0c 0a00 00112233445566778899"          # 1 K-frame, SDU=10
emit l2cap_data two_kframe    "46 0c 1400 00112233445566778899 0a aabbccddeeff00112233" # SDU=20, 2 frames
emit l2cap_data zero_credit   "00 06 0400 aabbccdd"                      # credits=0 -> disconnect
emit l2cap_data sdu_over_mtu  "c0 04 e803 0000"                         # SDU-len 1000 > MTU 32
emit l2cap_data payload_over_mps \
    "40 28 140055555555555555555555555555555555555555555555555555555555555555555555555555" # 40>MPS 23
emit l2cap_data empty_frame   "40 02 0000"                              # SDU-len 0

# ---- blued config files (UCL), usr.sbin/bluetooth/blued/config.c ----
emit_text config general \
    'general { pidfile = "/tmp/x.pid"; loglevel = 3; daemonize = true; adapters = ["ubt0"]; }'
emit_text config features \
    'features { eatt = true; privacy = true; reconnect = true; reconnect_max_delay = 30; }'
emit_text config security \
    'security { io_capability = "keyboarddisplay"; bondable = true; sc = "on"; min_key_size = 16; rpa_timeout = 900; }'
emit_text config device \
    'devices = [ { addr = "11:22:33:44:55:66"; addr_type = "public"; reconnect = true; } ]'
emit_text config service \
    'service { uuid = "0x180F"; characteristic { uuid = "0x2A19"; properties = "read,notify"; permissions = "read"; value = "64"; } }'
emit_text config combined \
    'general { loglevel = 2; } security { bondable = true; } peripheral_name = "fuzz";'

# ---- Legacy LE Advertising Reports (subevent 0x02), hci_scan.c ----
# fuzz_scan_parse frames input as: num_reports(1) then, per report,
#   event_type(1) addr_type(1) addr(6) data_len(1) data[data_len] rssi(1)
# driving hci_parse_ad_fields() + the static scan_result_merge() dedup path.
emit scan_parse one_report \
    "01 00 00 112233445566 09 020106 05094e414d45 c0"
emit scan_parse two_same_addr \
    "02 00 00 112233445566 03 020106 c0 04 00 112233445566 07 06094e414d4531 b8"
emit scan_parse uuid16_mfr \
    "01 00 01 aabbccddeeff 0a 03030f18 05ff01020304 c4"
emit scan_parse empty_data \
    "01 00 00 010203040506 00 d0"

# ---- LE Meta events (HCI event 0x3E), blued_le_meta.h ----
# Raw HCI event framing: type(04) evt(3e) plen sub params...
# Covers the BT 5.2 Power Control (0x20/0x21) and ISO (0x19-0x1e) subevents.
emit hci_event pathloss  "04 3e 04 20 4000 0a 01"           # LE Path Loss Threshold
emit hci_event txpower   "04 3e 08 21 00 4000 00 01 f4 03 02"  # LE TX Power Reporting
emit hci_event cis_est \
    "04 3e 1c 19 00 4000 000000 000000 000000 000000 01 01 05 01 01 01 01 fb00 fb00 0800"  # CIS Established
emit hci_event cis_req   "04 3e 06 1a 4000 4100 01 01"      # CIS Request
emit hci_event big_compl \
    "04 3e 16 1b 00 01 000000 000000 01 05 01 01 01 fb00 0800 02 4000 4100"  # Create BIG Complete, num_bis=2
emit hci_event big_lost  "04 3e 02 1e 01 13"                # BIG Sync Lost

# ---- SMP LE Secure Connections PDUs, smp_sc.c ----
# fuzz_smp_sc splits input into length-prefixed SEQPACKET datagrams (one byte
# of length N then N bytes of SMP PDU), focused on the SC exchange:
#   Pairing Public Key 0x0c (64B x||y), Confirm 0x03, Random 0x04, DHKey 0x0d.
emit smp_sc pubkey \
    "41 0c 1111111111111111111111111111111111111111111111111111111111111111 1111111111111111111111111111111111111111111111111111111111111111"
emit smp_sc confirm  "11 03 000102030405060708090a0b0c0d0e0f"  # Pairing Confirm
emit smp_sc random   "11 04 000102030405060708090a0b0c0d0e0f"  # Pairing Random
emit smp_sc dhkey    "11 0d 000102030405060708090a0b0c0d0e0f"  # DHKey Check

# ---- HOGP output-report routing, blued_central.c ----
# fuzz_hogp_report_map layout: N(1) then N*[value_handle(2 LE) id(1) type(1)]
# (the paired device's Report Reference classifications) then the raw report
# bytes the kernel vhid device delivers.  type 0x02 = Output report.
emit hogp_report_map out_id2    "01 3000 02 02 02abcd"        # 1 output report id=2, buf w/ id
emit hogp_report_map no_ids     "01 5000 00 02 112233"        # output id=0, no id byte stripped
emit hogp_report_map unmatched  "01 3000 02 02 09ff"          # report id 0x09 not present
emit hogp_report_map no_reports "00 deadbeef"                 # zero reports, stray bytes

echo "seed corpus written to $DIR"
