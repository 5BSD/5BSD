#!/bin/sh
#
# Expand every Kyua test case into a normative or implementation-contract
# citation.  A suite-level reference is intentionally inherited by each case;
# narrower per-case overrides can be added below as gaps are found.
#
# Usage: spec_traceability_audit.sh [-q] /absolute/path/to/Kyuafile

set -eu

quiet=false
if [ "${1-}" = "-q" ]; then
	quiet=true
	shift
fi
if [ "$#" -ne 1 ]; then
	echo "usage: $0 [-q] Kyuafile" >&2
	exit 64
fi

kyuafile=$1
if [ ! -f "$kyuafile" ]; then
	echo "traceability: Kyuafile not found: $kyuafile" >&2
	exit 66
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
requirements="$script_dir/spec_requirements.tsv"
oracles="$script_dir/spec_oracles.h $script_dir/spec_core63_generated.h $script_dir/spec_assigned_generated.h"
if [ ! -f "$requirements" ]; then
	echo "traceability: requirements catalog not found: $requirements" >&2
	exit 66
fi
for oracle_file in $oracles; do
	if [ ! -f "$oracle_file" ]; then
		echo "traceability: independent oracle catalog not found: $oracle_file" >&2
		exit 66
	fi
done

# A normative oracle must not import implementation definitions.  Its second
# X-macro argument must remain a literal transcribed from the specification.
if grep -n '^[[:space:]]*#include' $oracles |
    grep -v 'spec_oracles.h:.*"spec_.*_generated.h"'; then
	echo 'traceability: spec_oracles.h must not include production headers' >&2
	exit 1
fi
if grep -h '^[[:space:]]*X(' $oracles |
    grep -Ev '^[[:space:]]*X\([A-Za-z0-9_]+, 0x[0-9A-Fa-f]+\)( \\)?$'; then
	echo 'traceability: every specification oracle must use an independent hexadecimal literal' >&2
	exit 1
fi
core_source="$script_dir/../../../../bluetooth-specs/Core_Specification_6_3.txt"
assigned_source="$script_dir/../../../../bluetooth-specs/Assigned_Numbers.html"
# Official SIG source documents are local review inputs and are not
# redistributed with the source tree.  Recheck generated headers whenever
# both inputs are available; a partial local reference set is an error.
if [ -f "$core_source" ] && [ -f "$assigned_source" ]; then
	"$script_dir/check_generated_oracles.sh" "$core_source" \
	    "$assigned_source"
elif [ -f "$core_source" ] || [ -f "$assigned_source" ]; then
	echo 'traceability: incomplete local Bluetooth specification inputs' >&2
	exit 66
elif ! $quiet; then
	echo 'traceability: local SIG sources absent; generated-header freshness skipped'
fi
for group in ATT_ORACLES ATT_ERROR_ORACLES GATT_PROPERTY_ORACLES \
    PREVIOUSLY_USED_ORACLES SMP_COMMAND_ORACLES SMP_FAILURE_ORACLES \
    SMP_KEY_DIST_ORACLES \
    SMP_SCALAR_ORACLES L2CAP_CID_ORACLES L2CAP_COMMAND_ORACLES \
    L2CAP_RESULT_ORACLES L2CAP_RECONFIG_RESULT_ORACLES \
    HCI_PACKET_ORACLES HCI_EVENT_ORACLES HCI_LE_SUBEVENT_ORACLES \
    HCI_COMMAND_ORACLES; do
	if ! grep -q "BT_CORE63_${group}(CHECK_SPEC_ORACLE)" \
	    "$script_dir/spec_wire_contract_test.c"; then
		echo "traceability: independent oracle group $group is not executed" >&2
		exit 1
	fi
done
if ! grep -q 'BT_ASSIGNED_EATT_PSM_ORACLES(CHECK_SPEC_ORACLE)' \
    "$script_dir/spec_wire_contract_test.c"; then
	echo 'traceability: Assigned Numbers EATT PSM oracle is not executed' >&2
	exit 1
fi
if ! grep -q 'BT_CORE63_GATT_DATABASE_HASH_KAT_BYTES' \
    "$script_dir/gatt_test.c"; then
	echo 'traceability: generated GATT Appendix B hash oracle is not executed' >&2
	exit 1
fi
if ! grep -q 'BT_CORE63_GATT_DATABASE_HASH_KAT_BYTES' \
    "$script_dir/att_server_edge_test.c"; then
	echo 'traceability: generated GATT Appendix B server hash oracle is not executed' >&2
	exit 1
fi
for mtu_oracle in BT_CORE63_ATT_MTU_REQ_OPCODE BT_CORE63_ATT_MTU_RSP_OPCODE \
    BT_CORE63_ATT_MTU_PDU_SIZE BT_CORE63_ATT_DEFAULT_MTU; do
	if ! grep -q "$mtu_oracle" "$script_dir/att_test.c"; then
		echo "traceability: generated ATT MTU oracle $mtu_oracle is not executed" >&2
		exit 1
	fi
done
for appendix in D1 D2 D3 D4 D5 D6 D7 D8 D9 D10 D11 D12; do
	if ! grep -q "BT_CORE63_SMP_${appendix}_" "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SMP Appendix $appendix vector is not executed" >&2
		exit 1
	fi
done
for legacy_vector in C1 S1; do
	if ! grep -q "BT_CORE63_SMP_${legacy_vector}_" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SMP $legacy_vector worked example is not executed" >&2
		exit 1
	fi
done
for association_matrix in LEGACY SC; do
	if ! grep -q "BT_CORE63_SMP_ASSOC_${association_matrix}_MATRIX" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SMP $association_matrix association matrix is not executed" >&2
		exit 1
	fi
done
for address_oracle in TYPE_MASK NONRESOLVABLE RESOLVABLE RESERVED STATIC; do
	if ! grep -q "BT_CORE63_RANDOM_ADDRESS_${address_oracle}" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated random-address oracle $address_oracle is not executed" >&2
		exit 1
	fi
done
for production_address_oracle in TYPE_MASK RESOLVABLE; do
	if ! grep -q "BT_CORE63_RANDOM_ADDRESS_${production_address_oracle}" \
	    "$script_dir/spec_wire_contract_test.c"; then
		echo "traceability: production random-address constant $production_address_oracle is not checked" >&2
		exit 1
	fi
done
for f4_z_oracle in NUMERIC_OOB PASSKEY_ZERO PASSKEY_ONE; do
	if ! grep -q "BT_CORE63_SMP_F4_Z_${f4_z_oracle}" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated f4 Z oracle $f4_z_oracle is not executed" >&2
		exit 1
	fi
done
for debug_coordinate in X Y; do
	if ! grep -q "BT_CORE63_SMP_SC_DEBUG_${debug_coordinate}_HEX" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SC debug-key coordinate $debug_coordinate is not executed" >&2
		exit 1
	fi
done
if ! grep -q 'BT_CORE63_SMP_LEGACY_PASSKEY_TK_HEX' \
    "$script_dir/smp_crypto_test.c"; then
	echo 'traceability: generated legacy passkey TK is not executed' >&2
	exit 1
fi
for keysize_oracle in MIN_KEY_SIZE MAX_KEY_SIZE ENCRYPTION_KEY_SIZE_ERROR; do
	if ! grep -q "BT_CORE63_SMP_${keysize_oracle}" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SMP key-size oracle $keysize_oracle is not executed" >&2
		exit 1
	fi
done
for io_reserved_oracle in FIRST LAST; do
	if ! grep -q "BT_CORE63_SMP_IO_RESERVED_${io_reserved_oracle}" \
	    "$script_dir/smp_crypto_test.c"; then
		echo "traceability: generated SMP reserved IO boundary $io_reserved_oracle is not executed" >&2
		exit 1
	fi
done
for identity_addr_oracle in PUBLIC STATIC_RANDOM; do
	if ! grep -q "BT_CORE63_SMP_ID_ADDR_${identity_addr_oracle}" \
	    "$script_dir/smp_keys_edge_test.c"; then
		echo "traceability: generated SMP identity address type $identity_addr_oracle is not executed" >&2
		exit 1
	fi
done

if ! $quiet; then
	printf '%s\t%s\t%s\n' "test_case" "authority" "exact_reference"
fi

kyua list -k "$kyuafile" | while IFS= read -r test_case; do
	program=${test_case%%:*}
	authority=normative
	case "$program" in
	adv_*|privacy_scan_test)
		ref='Bluetooth Core 6.3 Vol 3 Part C §11; CSS v12 Part A §§1.1-1.3'
		;;
	att_*)
		ref='Bluetooth Core 6.3 Vol 3 Part F §§3.2-3.4'
		;;
	gatt_*|peripheral_test|profile_data_test)
		ref='Bluetooth Core 6.3 Vol 3 Part G §§2-7; Vol 3 Part F §§3.2-3.4'
		;;
	hogp_*)
		ref='HID over GATT Profile 1.1.1 §§4-6; Bluetooth Core 6.3 Vol 3 Part G §§4-7'
		;;
	hci_periodic_df_test)
		ref='Bluetooth Core 6.3 Vol 4 Part E §§7.7.65.15-7.7.65.22, 7.8.67-7.8.89'
		;;
	hci_privacy_kernel_test|privacy_test)
		ref='Bluetooth Core 6.3 Vol 6 Part B §1.3.2; Vol 4 Part E §§7.8.39-7.8.48'
		;;
	hci_*|power_control_*)
		ref='Bluetooth Core 6.3 Vol 4 Part E §§5.4, 7.1, 7.3, 7.7, 7.8'
		;;
	iso_*)
		ref='Bluetooth Core 6.3 Vol 4 Part E §§5.4.5, 7.7.65.25-7.7.65.30, 7.8.97-7.8.111'
		;;
	l2cap_*)
		ref='Bluetooth Core 6.3 Vol 3 Part A §§2, 4'
		;;
	smp_crypto_test)
		ref='Bluetooth Core 6.3 Vol 3 Part H §2.2 and Appendix D'
		;;
	smp_*|bond_migrate_test)
		ref='Bluetooth Core 6.3 Vol 3 Part H §§2.3-3.6; Vol 3 Part C §10.2'
		;;
	mesh_crypto_*)
		ref='Mesh Protocol 1.1 §§3.8, 3.9 and §8.2 security-function sample data'
		;;
	mesh_access_test)
		ref='Mesh Protocol 1.1 §§3.4, 3.7 and §8.3 access-message sample data'
		;;
	mesh_beacon_*)
		ref='Mesh Protocol 1.1 §§3.9.3, 3.10 and §8.3 beacon sample data'
		;;
	mesh_friend_test|mesh_lpn_test)
		ref='Mesh Protocol 1.1 §3.6.6 and §8.3 friendship sample data'
		;;
	mesh_iv_test)
		ref='Mesh Protocol 1.1 §3.10.5'
		;;
	mesh_key_refresh_test)
		ref='Mesh Protocol 1.1 §3.10.4'
		;;
	mesh_net_test|mesh_network_test|mesh_netxport_fault_test|mesh_transport_test)
		ref='Mesh Protocol 1.1 §§3.4-3.6, 3.8 and §8.3 network/transport sample data'
		;;
	mesh_provision_test|mesh_provisioner_test|mesh_provision_fault_test)
		ref='Mesh Protocol 1.1 §5 and §8.7 provisioning sample data'
		;;
	mesh_proxy_test|mesh_proxy_fault_test|mesh_remote_prov_test)
		ref='Mesh Protocol 1.1 §6; Mesh Remote Provisioning 1.1 §4'
		;;
	mesh_relay_test)
		ref='Mesh Protocol 1.1 §§3.4.6, 3.6.4 and 4.2.20'
		;;
	mesh_rpl_test)
		ref='Mesh Protocol 1.1 §§3.4.6.3 and 3.6.4.3'
		;;
	mesh_cfg_model_test|mesh_cfg_v11_test|mesh_cfgclient_test|mesh_cfgsrv_test|mesh_manager_test)
		ref='Mesh Model 1.1.1 §§4.3-4.4'
		;;
	mesh_health_model_test)
		ref='Mesh Model 1.1.1 §7'
		;;
	mesh_heartbeat_test)
		ref='Mesh Model 1.1.1 §4.4.1; Mesh Protocol 1.1 §3.6.7'
		;;
	mesh_generic_test)
		ref='Mesh Model 1.1.1 §§3.2-3.3'
		;;
	mesh_lighting_test|mesh_lighting_lc_quality_test)
		ref='Mesh Model 1.1.1 §6'
		;;
	mesh_sensor_test)
		ref='Mesh Model 1.1.1 §4.1'
		;;
	mesh_time_scene_test)
		ref='Mesh Model 1.1.1 §§5.1-5.3'
		;;
	mesh_df_test)
		ref='Mesh Protocol 1.1 §3.6.7; Mesh Model 1.1.1 §4.3.4'
		;;
	btpeer*|emu_peer_equiv_test|dataflow_test)
		ref='Bluetooth Core 6.3 Vol 3 Parts A/F/H §§4/3.4/3.5; Vol 4 Part E §§5.4, 7.7-7.8'
		;;
	spec_wire_contract_test)
		ref='Bluetooth Core 6.3 Vol 3 Parts A/F/H §§2,4/3.3-3.4/3.3-3.6; Vol 4 Part E §§5.4,7.7-7.8'
		;;
	*)
		authority=implementation
		ref="Implementation contract: tests/usr.sbin/bluetooth/blued/${program}.c and linked production interfaces"
		;;
	esac

	case "$authority:$ref" in
	normative:*§*|normative:*Appendix*|normative:*Table*) ;;
	implementation:'Implementation contract:'*) ;;
	*)
		echo "traceability: invalid reference for $test_case: $ref" >&2
		exit 1
		;;
	esac

	if ! $quiet; then
		printf '%s\t%s\t%s\n' "$test_case" "$authority" "$ref"
	fi
	done

# The pipeline above runs in a subshell on POSIX sh.  Recount independently so
# the summary and the zero-case guard are portable.
case_list=$(mktemp -t bluetooth-trace.XXXXXX)
trap 'rm -f "$case_list"' EXIT HUP INT TERM
kyua list -k "$kyuafile" >"$case_list"
count=$(wc -l <"$case_list" | tr -d ' ')
if [ "$count" -eq 0 ]; then
	echo 'traceability: no Kyua cases found' >&2
	exit 1
fi

requirement_count=0
tab=$(printf '\t')
while IFS="$tab" read -r requirement_id exact_reference selectors oracle; do
	case "$requirement_id" in
	''|'#'*) continue ;;
	esac
	case "$exact_reference" in
	*§*|*Appendix*|*Table*) ;;
	*)
		echo "traceability: requirement $requirement_id lacks an exact reference" >&2
		exit 1
		;;
	esac
	matched=false
	old_ifs=$IFS
	IFS='|'
	for selector in $selectors; do
		IFS=$old_ifs
		while IFS= read -r test_case; do
			case "$test_case" in
			$selector) matched=true; break ;;
			esac
		done <"$case_list"
		$matched && break
		IFS='|'
	done
	IFS=$old_ifs
	if ! $matched; then
		echo "traceability: requirement $requirement_id has no test matching $selectors" >&2
		exit 1
	fi
	requirement_count=$((requirement_count + 1))
done <"$requirements"

if $quiet; then
	echo "traceability: $count/$count test cases classified; $requirement_count/$requirement_count implemented requirements covered; independent wire oracles verified"
fi
