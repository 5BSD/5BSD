PACKAGE=	bluetooth-tests

# Build the complete software test matrix with LLVM source and branch
# instrumentation.  tests/usr.sbin/bluetooth/blued/coverage.sh owns the
# corresponding build/run/report workflow; keeping the flags here ensures
# every production translation unit linked by an ATF program is measured.
.if defined(BLUETOOTH_COVERAGE)
CFLAGS+=	-O0 -fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=	-fprofile-instr-generate
.endif

TESTSDIR=	${TESTSBASE}/usr.sbin/bluetooth/blued
BINDIR=		${TESTSDIR}

ATF_TESTS_C+=	smp_crypto_test
ATF_TESTS_C+=	att_test
ATF_TESTS_C+=	conn_test
ATF_TESTS_C+=	ctl_test
ATF_TESTS_C+=	peripheral_test
ATF_TESTS_C+=	config_test
ATF_TESTS_C+=	persist_test
ATF_TESTS_C+=	devmgr_test
ATF_TESTS_C+=	hci_hw_test
ATF_TESTS_C+=	smp_pairing_test
ATF_TESTS_C+=	adv_data_test
ATF_TESTS_C+=	adv_builder_test
ATF_TESTS_C+=	privacy_scan_test
ATF_TESTS_C+=	gatt_test
ATF_TESTS_C+=	hci_log_test
ATF_TESTS_C+=	hci_offline_test
ATF_TESTS_C+=	hci_conform_test
ATF_TESTS_C+=	hci_findings_test
ATF_TESTS_C+=	spec_wire_contract_test
ATF_TESTS_C+=	ctl_adv_conn_test
ATF_TESTS_C+=	ctl_adapter_scan_test
ATF_TESTS_C+=	hci_periodic_df_test
ATF_TESTS_C+=	hogp_test
ATF_TESTS_C+=	libble_test
ATF_TESTS_C+=	smp_negative_test
ATF_TESTS_C+=	att_negative_test
ATF_TESTS_C+=	gatt_client_test
ATF_TESTS_C+=	hci_event_test
ATF_TESTS_C+=	privacy_test
ATF_TESTS_C+=	libble_negative_test
ATF_TESTS_C+=	config_negative_test
ATF_TESTS_C+=	hogp_report_map_test
ATF_TESTS_C+=	hogp_boot_test
ATF_TESTS_C+=	findings_regression_test
ATF_TESTS_C+=	adv_regression_test
ATF_TESTS_C+=	profile_data_test
ATF_TESTS_C+=	hci_emulator_test
ATF_TESTS_C+=	hci_encode_edge_test
ATF_TESTS_C+=	hci_scan_parse_edge_test
ATF_TESTS_C+=	smp_keys_edge_test
ATF_TESTS_C+=	smp_secret_test
ATF_TESTS_C+=	bond_migrate_test
ATF_TESTS_C+=	smp_sc_edge_test
ATF_TESTS_C+=	smp_legacy_edge_test
ATF_TESTS_C+=	att_client_test
ATF_TESTS_C+=	att_server_edge_test
ATF_TESTS_C+=	att_server_cov_test
ATF_TESTS_C+=	att_client_cov_test
ATF_TESTS_C+=	mesh_crypto_fault_test
ATF_TESTS_C+=	mesh_beacon_fault_test
ATF_TESTS_C+=	mesh_provision_fault_test
ATF_TESTS_C+=	mesh_netxport_fault_test
ATF_TESTS_C+=	mesh_proxy_fault_test
ATF_TESTS_C+=	conn_fault_test
ATF_TESTS_C+=	config_fault_test
ATF_TESTS_C+=	hci_emulator_fault_test
ATF_TESTS_C+=	gatt_discovery_edge_test
ATF_TESTS_C+=	config_edge_test
ATF_TESTS_C+=	libble_edge_test
ATF_TESTS_C+=	ctl_conn_edge_test
ATF_TESTS_C+=	hci_log_deep_test
ATF_TESTS_C+=	hci_drive_deep_test
ATF_TESTS_C+=	l2cap_sig_test
ATF_TESTS_C+=	hci_le_role_test
ATF_TESTS_C+=	hci_privacy_kernel_test
ATF_TESTS_C+=	util_decode_test
ATF_TESTS_C+=	smp_deep_legacy_test
ATF_TESTS_C+=	smp_deep_sc_test
ATF_TESTS_C+=	smp_deep_scneg_test
ATF_TESTS_C+=	smp_deep_misc_test
ATF_TESTS_C+=	smp_timeout_test
ATF_TESTS_C+=	smp_sc_oob_test
ATF_TESTS_C+=	gatt_client_deepcov_test
ATF_TESTS_C+=	config_coverage_test
ATF_TESTS_C+=	libble_branch_test
ATF_TESTS_C+=	libble_internal_test
ATF_TESTS_C+=	att_server_deep_test
ATF_TESTS_C+=	att_client_deep_test
ATF_TESTS_C+=	att_fault_test
ATF_TESTS_C+=	hci_devreq_mock_test
ATF_TESTS_C+=	hci_error_arms_test
ATF_TESTS_C+=	hci_emulator_link_test
ATF_TESTS_C+=	conn_deep_test
ATF_TESTS_C+=	smp_fault_test
ATF_TESTS_C+=	libble_fault_test
ATF_TESTS_C+=	l2cap_sig_rsp_test
ATF_TESTS_C+=	power_control_test
ATF_TESTS_C+=	power_control_deep_test
ATF_TESTS_C+=	iso_transport_test
ATF_TESTS_C+=	iso_deep_test
ATF_TESTS_C+=	iso_control_test
ATF_TESTS_C+=	iso_lifecycle_test
ATF_TESTS_C+=	hci_emulator_enc_test
ATF_TESTS_C+=	hci_emulator_deep_test
ATF_TESTS_C+=	probe_tap_test
ATF_TESTS_C+=	mesh_crypto_test
ATF_TESTS_C+=	mesh_net_test
ATF_TESTS_C+=	mesh_transport_test
ATF_TESTS_C+=	btpeer_test
ATF_TESTS_C+=	btpeer_srv_pdu_test
ATF_TESTS_C+=	mesh_access_test
ATF_TESTS_C+=	mesh_cfg_model_test
ATF_TESTS_C+=	mesh_health_model_test
ATF_TESTS_C+=	mesh_provision_test
ATF_TESTS_C+=	mesh_beacon_test
ATF_TESTS_C+=	mesh_iv_test
ATF_TESTS_C+=	mesh_rpl_test
ATF_TESTS_C+=	mesh_key_refresh_test
ATF_TESTS_C+=	mesh_proxy_test
ATF_TESTS_C+=	mesh_friend_test
ATF_TESTS_C+=	mesh_relay_test
ATF_TESTS_C+=	mesh_generic_test
ATF_TESTS_C+=	mesh_sensor_test
ATF_TESTS_C+=	mesh_time_scene_test
ATF_TESTS_C+=	mesh_lighting_test
ATF_TESTS_C+=	mesh_lighting_lc_quality_test
ATF_TESTS_C+=	mesh_sim_test
ATF_TESTS_C+=	mesh_sim_fault_test
ATF_TESTS_C+=	meshd_test
ATF_TESTS_C+=	meshd_fault_test
ATF_TESTS_C+=	meshd_security_test
ATF_TESTS_C+=	mesh_cfgsrv_test
ATF_TESTS_C+=	mesh_cfg_v11_test
ATF_TESTS_C+=	mesh_findings_meshd_test
ATF_TESTS_C+=	mesh_df_test
ATF_TESTS_C+=	mesh_remote_prov_test
ATF_TESTS_C+=	smp_scenario_test
ATF_TESTS_C+=	gatt_scenario_test
ATF_TESTS_C+=	hogp_scenario_test
ATF_TESTS_C+=	emu_peer_equiv_test
ATF_TESTS_C+=	dataflow_test
# App-platform completeness: dynamic reads + per-access authorization for
# app-backed characteristics (deferred ATT read/authorize round-trips).
ATF_TESTS_C+=	platform_test

SRCS.smp_crypto_test=	smp_crypto_test.c
SRCS.att_test=		att_test.c
SRCS.gatt_test=		gatt_test.c
SRCS.conn_test=		conn_test.c
SRCS.ctl_test=		ctl_test.c
SRCS.peripheral_test=	peripheral_test.c
SRCS.config_test=	config_test.c
SRCS.hci_hw_test=	hci_hw_test.c
SRCS.smp_pairing_test=	smp_pairing_test.c
SRCS.hci_log_test=	hci_log_test.c
SRCS.adv_data_test=	adv_data_test.c

CFLAGS+=	-I${SRCTOP}/usr.sbin/bluetooth/blued
CFLAGS+=	-I${SRCTOP}/lib/libble
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
# libmesh (mesh_*.h) + meshd (meshd*.h) headers — distinct prefixes, no collision
# with the blued/libble headers; global so shared engine sources compile.
CFLAGS+=	-I${SRCTOP}/lib/libmesh
CFLAGS+=	-I${SRCTOP}/usr.sbin/bluetooth/meshd
# ble_open() now completes the HELLO handshake; the edge test drives the
# daemon's side of it from a helper thread.
LIBADD.libble_edge_test+=	pthread
LIBADD.att_test+=	pthread
# Bluetooth Mesh crypto toolbox KATs (Mesh Protocol 1.1 sec 8 sample data).
SRCS.mesh_crypto_test=	mesh_crypto_test.c mesh_crypto.c
CFLAGS.mesh_crypto_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_net_test=	mesh_net_test.c mesh_net.c mesh_crypto.c
CFLAGS.mesh_net_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_transport_test=	mesh_transport_test.c mesh_transport.c mesh_net.c mesh_crypto.c
CFLAGS.mesh_transport_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_access_test=	mesh_access_test.c mesh_access.c mesh_crypto.c
CFLAGS.mesh_access_test+=	-I${SRCTOP}/lib/libmesh
# Directed Forwarding engine: forwarding table, path discovery PDUs, the
# forwarding decision, and the DF Configuration model codecs (MshPRT 3.6.6).
SRCS.mesh_df_test=	mesh_df_test.c mesh_df.c mesh_net.c mesh_access.c \
			mesh_crypto.c
CFLAGS.mesh_df_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_cfg_model_test=	mesh_cfg_model_test.c mesh_cfg_model.c mesh_access.c \
			mesh_crypto.c
CFLAGS.mesh_cfg_model_test+=	-I${SRCTOP}/lib/libmesh
# Heartbeat: transport control message + Config Heartbeat Pub/Sub codecs.
ATF_TESTS_C+=	mesh_heartbeat_test
SRCS.mesh_heartbeat_test=	mesh_heartbeat_test.c mesh_heartbeat.c \
			mesh_cfg_model.c mesh_access.c mesh_crypto.c
CFLAGS.mesh_heartbeat_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_health_model_test=	mesh_health_model_test.c mesh_health_model.c \
			mesh_access.c mesh_crypto.c
CFLAGS.mesh_health_model_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_provision_test=	mesh_provision_test.c mesh_provision.c mesh_crypto.c
CFLAGS.mesh_provision_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_beacon_test=	mesh_beacon_test.c mesh_beacon.c mesh_crypto.c
CFLAGS.mesh_beacon_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_iv_test=	mesh_iv_test.c mesh_iv.c
CFLAGS.mesh_iv_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_rpl_test=	mesh_rpl_test.c mesh_rpl.c mesh_net.c mesh_crypto.c
CFLAGS.mesh_rpl_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_key_refresh_test=	mesh_key_refresh_test.c mesh_key_refresh.c
CFLAGS.mesh_key_refresh_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_proxy_test=	mesh_proxy_test.c mesh_proxy.c mesh_crypto.c
CFLAGS.mesh_proxy_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_friend_test=	mesh_friend_test.c mesh_friend.c mesh_crypto.c
CFLAGS.mesh_friend_test+=	-I${SRCTOP}/lib/libmesh
# Driven Friend + Low Power node state machines (MshPRT_v1.1 Section 3.6.5).
ATF_TESTS_C+=	mesh_lpn_test
SRCS.mesh_lpn_test=	mesh_lpn_test.c mesh_lpn.c mesh_friend.c mesh_crypto.c
CFLAGS.mesh_lpn_test+=	-I${SRCTOP}/lib/libmesh
# Driven Provisioner + Device provisioning roles (MshPRT_v1.1 Section 5).
ATF_TESTS_C+=	mesh_provisioner_test
SRCS.mesh_provisioner_test=	mesh_provisioner_test.c mesh_provisioner.c \
			mesh_provision.c mesh_crypto.c
CFLAGS.mesh_provisioner_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_remote_prov_test=	mesh_remote_prov_test.c mesh_remote_prov.c \
			mesh_provisioner.c mesh_provision.c mesh_access.c \
			mesh_crypto.c
CFLAGS.mesh_remote_prov_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_relay_test=	mesh_relay_test.c mesh_relay.c mesh_net.c mesh_crypto.c
CFLAGS.mesh_relay_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_generic_test=	mesh_generic_test.c mesh_generic.c mesh_access.c \
			mesh_crypto.c
CFLAGS.mesh_generic_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_sensor_test=	mesh_sensor_test.c mesh_sensor.c mesh_access.c mesh_crypto.c
CFLAGS.mesh_sensor_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_time_scene_test=	mesh_time_scene_test.c mesh_time_scene.c \
	mesh_access.c mesh_crypto.c
CFLAGS.mesh_time_scene_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_lighting_test=	mesh_lighting_test.c mesh_lighting.c \
		mesh_lighting_lc.c mesh_generic.c mesh_access.c mesh_crypto.c
CFLAGS.mesh_lighting_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_lighting_lc_quality_test=	mesh_lighting_lc_quality_test.c \
		mesh_lighting.c mesh_lighting_lc.c mesh_generic.c mesh_access.c \
		mesh_crypto.c
CFLAGS.mesh_lighting_lc_quality_test+=	-I${SRCTOP}/lib/libmesh
# mesh_sim links Directed Forwarding, Heartbeat and driven provisioning in
# addition to the generic/relay/friend/proxy modules it already composes.
MESH_SIM_SRCS=	mesh_sim.c mesh_generic.c mesh_sensor.c mesh_lighting.c \
				mesh_lighting_lc.c mesh_time_scene.c mesh_access.c mesh_net.c \
			mesh_transport.c mesh_crypto.c mesh_rpl.c mesh_relay.c \
			mesh_iv.c mesh_key_refresh.c mesh_beacon.c mesh_friend.c \
			mesh_proxy.c mesh_df.c mesh_heartbeat.c mesh_cfg_model.c \
			mesh_provision.c mesh_provisioner.c
SRCS.mesh_sim_test=	mesh_sim_test.c ${MESH_SIM_SRCS}
CFLAGS.mesh_sim_test+=	-I${SRCTOP}/lib/libmesh
# mesh_network_test: multi-node NETWORK scenarios (relay/replay/friend/proxy/
# IV/key-refresh/subnets/group) over the in-process mesh_sim medium.
ATF_TESTS_C+=	mesh_network_test
SRCS.mesh_network_test=	mesh_network_test.c ${MESH_SIM_SRCS}
CFLAGS.mesh_network_test+=	-I${SRCTOP}/lib/libmesh
SRCS.mesh_sim_fault_test=	mesh_sim_fault_test.c ${MESH_SIM_SRCS}
CFLAGS.mesh_sim_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_sim_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_sim_fault_test+=	-Wl,--wrap=mesh_net_encrypt \
	-Wl,--wrap=mesh_upper_encrypt -Wl,--wrap=mesh_upper_decrypt \
	-Wl,--wrap=mesh_lower_build -Wl,--wrap=mesh_lower_parse \
	-Wl,--wrap=mesh_sar_segment -Wl,--wrap=mesh_reasm_input \
	-Wl,--wrap=mesh_reasm_get -Wl,--wrap=mesh_access_pdu_parse \
	-Wl,--wrap=mesh_k2 -Wl,--wrap=mesh_k4 \
	-Wl,--wrap=mesh_secure_beacon_build -Wl,--wrap=mesh_friend_poll_build \
	-Wl,--wrap=mesh_friend_poll_parse -Wl,--wrap=mesh_kr_beacon \
	-Wl,--wrap=mesh_friend_credentials \
	-Wl,--wrap=mesh_df_discovery_start -Wl,--wrap=mesh_df_path_request_build \
	-Wl,--wrap=mesh_hb_msg_build
# Virtual remote peer (btpeer): drives our real ATT/GATT/SMP over the emulator link.
SRCS.btpeer_test=	btpeer_test.c btpeer.c hci_emulator.c \
			att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.btpeer_test+=	pthread
# Byte-level spec-conformance tests of the peer's OWN emitted ATT/SMP PDUs,
# captured raw on the far side of the emulator link (btpeer.c is the oracle
# target; the Core Spec is the oracle).
SRCS.btpeer_srv_pdu_test=	btpeer_srv_pdu_test.c btpeer.c hci_emulator.c \
			smp_crypto.c
# Integration scenario matrix (tester-equivalents): peer<->real stack over the emulator.
SRCS.smp_scenario_test=	smp_scenario_test.c btpeer.c hci_emulator.c \
			att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.smp_scenario_test+=	pthread
# Provides non-static HCI stub symbols (hci_send_raw_cmd etc.) that replace the
# real ones for the emulator encryption path, like smp_deep_legacy_test.
CFLAGS.smp_scenario_test.c+=	-Wno-missing-prototypes
# Emulator<->peer 3-way equivalence (peer==emulator==spec) differential test.
SRCS.emu_peer_equiv_test=	emu_peer_equiv_test.c profile_fixtures.c btpeer.c \
			hci_emulator.c att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.emu_peer_equiv_test+=	pthread
CFLAGS.emu_peer_equiv_test.c+=	-Wno-missing-prototypes
# HCI encoder error/fault arms: --wrap the devreq + syscall seams to drive the
# controller-error and failure paths (branch 52%->99%).
SRCS.hci_error_arms_test=	hci_error_arms_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.hci_error_arms_test+=	-Wl,--wrap=bt_devreq -Wl,--wrap=bt_devrecv \
			-Wl,--wrap=bt_devfilter -Wl,--wrap=bt_devopen \
			-Wl,--wrap=ioctl -Wl,--wrap=socket -Wl,--wrap=bind \
			-Wl,--wrap=connect -Wl,--wrap=setsockopt -Wl,--wrap=close \
			-Wl,--wrap=write -Wl,--wrap=writev
SRCS.gatt_scenario_test=	gatt_scenario_test.c btpeer.c hci_emulator.c \
			att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.gatt_scenario_test+=	pthread
SRCS.hogp_scenario_test=	hogp_scenario_test.c btpeer.c hci_emulator.c \
			att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.hogp_scenario_test+=	pthread
# Full-stack data-flow scenarios: peer<->controller<->OUR stack with real data
# volume/variety (HOGP stream, GATT throughput, ISO CIS/BIG, pairing lifecycle,
# soak), asserting end-to-end integrity.  Reuses the scenario harness link set.
SRCS.dataflow_test=	dataflow_test.c btpeer.c hci_emulator.c \
			att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c \
			smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
LIBADD.dataflow_test+=	pthread
CFLAGS.dataflow_test.c+=	-Wno-missing-prototypes
# Mutable argv[] built from string literals for the CLI-parser harness.
CFLAGS.config_edge_test.c+=	-Wno-cast-qual
CFLAGS.config_coverage_test.c+=	-Wno-cast-qual
LIBADD.config_coverage_test+=	ucl
LIBADD.smp_fault_test+=	pthread

# Fault-injection seams: __wrap_<sym> intercepts the allocator/OpenSSL/socket
# calls so the failure-handling arms become reachable.
CFLAGS.smp_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.smp_fault_test+=	-Wl,--wrap=malloc -Wl,--wrap=RAND_bytes \
	-Wl,--wrap=PKCS5_PBKDF2_HMAC -Wl,--wrap=EVP_CIPHER_CTX_new \
	-Wl,--wrap=EVP_CIPHER_CTX_ctrl -Wl,--wrap=EVP_EncryptInit_ex \
	-Wl,--wrap=EVP_EncryptUpdate -Wl,--wrap=EVP_EncryptFinal_ex \
	-Wl,--wrap=EVP_DecryptInit_ex -Wl,--wrap=EVP_DecryptUpdate \
	-Wl,--wrap=EVP_DecryptFinal_ex -Wl,--wrap=EVP_MAC_fetch \
	-Wl,--wrap=EVP_MAC_CTX_new -Wl,--wrap=EVP_MAC_init \
	-Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final \
	-Wl,--wrap=EC_GROUP_new_by_curve_name -Wl,--wrap=EC_POINT_new \
	-Wl,--wrap=BN_bin2bn -Wl,--wrap=EC_POINT_set_affine_coordinates \
	-Wl,--wrap=EC_POINT_is_on_curve -Wl,--wrap=EVP_PKEY_CTX_new_id \
	-Wl,--wrap=EVP_PKEY_keygen \
	-Wl,--wrap=EVP_PKEY_get_octet_string_param \
	-Wl,--wrap=EVP_PKEY_fromdata -Wl,--wrap=EVP_PKEY_derive \
	-Wl,--wrap=flock -Wl,--wrap=fsync
CFLAGS.libble_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.libble_fault_test+=	-Wl,--wrap=socket -Wl,--wrap=calloc \
	-Wl,--wrap=malloc
# The handshake responder that lets a successful ble_open() complete runs on a
# helper thread.
LIBADD.libble_fault_test+=	pthread

# hci_le_role_test #include's the kernel TU ng_hci_evnt.c like l2cap_sig_test.
CFLAGS.hci_le_role_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/hci
CFLAGS.hci_le_role_test.c+=	-Wno-pointer-sign -Wno-unused-parameter \
			-Wno-unused-function -Wno-unused-variable \
			-Wno-missing-prototypes -Wno-sign-compare -Wno-cast-align

# hci_privacy_kernel_test #include's the kernel TU ng_hci_ulpi.c (LE Create
# Connection build path) with the same mbuf/callout shims.
CFLAGS.hci_privacy_kernel_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/hci
CFLAGS.hci_privacy_kernel_test.c+=	-Wno-pointer-sign -Wno-unused-parameter \
			-Wno-unused-function -Wno-unused-variable \
			-Wno-missing-prototypes -Wno-sign-compare -Wno-cast-align

# att_fault_test: --wrap socket/malloc/EVP seams to drive att_open/EATT + rsp-alloc
# + hash-crypto failure arms (att.c 0% open paths -> covered).
SRCS.att_fault_test=	att_fault_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
CFLAGS.att_fault_test.c+=	-Wno-missing-prototypes -Wno-missing-variable-declarations
LDFLAGS.att_fault_test+=	-Wl,--wrap=socket -Wl,--wrap=bind \
			-Wl,--wrap=connect -Wl,--wrap=accept4 \
			-Wl,--wrap=setsockopt -Wl,--wrap=getsockopt \
			-Wl,--wrap=malloc -Wl,--wrap=free \
			-Wl,--wrap=EVP_MAC_fetch \
			-Wl,--wrap=EVP_MAC_CTX_new -Wl,--wrap=EVP_MAC_init \
			-Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final

# l2cap_sig_rsp_test #include's the kernel TU like l2cap_sig_test.
CFLAGS.l2cap_sig_rsp_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/l2cap
CFLAGS.l2cap_sig_rsp_test.c+=	-Wno-unused-variable -Wno-unused-parameter \
			-Wno-unused-function -Wno-missing-prototypes \
			-Wno-sign-compare -Wno-cast-align
CFLAGS.adv_data_test+=	-I${SRCTOP}/usr.sbin/bluetooth/hccontrol
SRCS.util_decode_test=	util_decode_test.c util.c
CFLAGS.util_decode_test+=	-I${SRCTOP}/usr.sbin/bluetooth/hccontrol
CFLAGS.util.c+=	-Wno-sign-compare -Wno-ignored-qualifiers -Wno-missing-prototypes \
			-Wno-cast-qual
CFLAGS.adv_regression_test+=	-I${SRCTOP}/usr.sbin/bluetooth/hccontrol
CFLAGS.adv_data.c+=	-Wno-ignored-qualifiers -Wno-sign-compare

.PATH:		${SRCTOP}/usr.sbin/bluetooth/blued
.PATH:		${SRCTOP}/usr.sbin/bluetooth/hccontrol
.PATH:		${SRCTOP}/lib/libble
.PATH:		${SRCTOP}/lib/libmesh
.PATH:		${SRCTOP}/usr.sbin/bluetooth/meshd

# Mesh tests embed libblemesh sources for private-state and fault-injection
# coverage.  Explicit prerequisites prevent shared mesh_*.pieo objects from
# surviving source/header changes when bsd.tests.mk omits secondary-source
# dependency files.
MESH_EMBED_SRCS=	mesh_crypto.c mesh_net.c mesh_transport.c mesh_access.c \
	mesh_cfg_model.c mesh_cfg_v11.c mesh_df.c mesh_heartbeat.c \
	mesh_health_model.c mesh_generic.c mesh_sensor.c mesh_lighting.c \
	mesh_lighting_lc.c mesh_time_scene.c mesh_provision.c mesh_beacon.c \
	mesh_iv.c mesh_rpl.c mesh_key_refresh.c mesh_proxy.c mesh_friend.c \
	mesh_lpn.c mesh_provisioner.c mesh_remote_prov.c mesh_manager.c \
	mesh_relay.c mesh_sim.c
MESH_EMBED_HEADERS=	mesh_access.h mesh_beacon.h mesh_cfg_model.h \
	mesh_cfg_v11.h mesh_crypto.h mesh_df.h mesh_heartbeat.h mesh_friend.h \
	mesh_generic.h mesh_sensor.h mesh_lighting.h mesh_time_scene.h \
	mesh_health_model.h mesh_iv.h mesh_key_refresh.h mesh_lpn.h \
	mesh_manager.h mesh_net.h mesh_probes.h mesh_provision.h \
	mesh_provisioner.h mesh_remote_prov.h mesh_proxy.h mesh_relay.h \
	mesh_rpl.h mesh_sim.h mesh_transport.h
.for _mesh_src in ${MESH_EMBED_SRCS}
${_mesh_src:R}.o ${_mesh_src:R}.pieo: ${_mesh_src} ${MESH_EMBED_HEADERS}
.endfor

MESHD_EMBED_SRCS=	meshd_node.c meshd_models.c meshd_config.c meshd_ctl.c \
	meshd_pbgatt.c meshd_proxy_gatt.c meshd_persist.c meshd_cfgclient.c \
	meshd_bearer_blued.c
MESHD_EMBED_HEADERS=	meshd.h meshd_models.h meshd_persist.h \
	meshd_bearer_blued.h meshd_probes.h
.for _meshd_src in ${MESHD_EMBED_SRCS}
${_meshd_src:R}.o ${_meshd_src:R}.pieo: ${_meshd_src} ${MESHD_EMBED_HEADERS} \
	${MESH_EMBED_HEADERS}
.endfor

# meshd daemon (libblemesh consumer) — node + config + ctl over the mesh engine.
MESHD_ENGINE_NO_NODE=	meshd_models.c meshd_config.c meshd_ctl.c \
		meshd_pbgatt.c meshd_proxy_gatt.c \
		meshd_persist.c meshd_cfgclient.c \
			mesh_sim.c mesh_generic.c mesh_sensor.c mesh_lighting.c \
			mesh_lighting_lc.c mesh_time_scene.c \
		mesh_access.c mesh_cfg_model.c mesh_cfg_v11.c mesh_health_model.c \
		mesh_heartbeat.c mesh_df.c mesh_remote_prov.c \
		mesh_provision.c mesh_provisioner.c mesh_manager.c mesh_lpn.c \
		mesh_net.c mesh_transport.c mesh_crypto.c mesh_rpl.c mesh_relay.c \
		mesh_iv.c mesh_key_refresh.c mesh_beacon.c mesh_friend.c mesh_proxy.c
MESHD_ENGINE=	meshd_node.c ${MESHD_ENGINE_NO_NODE}
SRCS.meshd_test=	meshd_test.c blued_probe_tap.c ptap_meshd_node.c \
		${MESHD_ENGINE_NO_NODE}
CFLAGS.meshd_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd \
		-I${SRCTOP}/usr.sbin/bluetooth/blued -DMESHD_WITH_PROBE_TAP
SRCS.meshd_security_test=	meshd_security_test.c meshd_bearer_blued.c \
		${MESHD_ENGINE}
CFLAGS.meshd_security_test+=	-I${SRCTOP}/lib/libmesh \
		-I${SRCTOP}/usr.sbin/bluetooth/meshd
CFLAGS.meshd_security_test.c+=	-Wno-missing-prototypes
CFLAGS.ptap_meshd_node.c+=	-DMESHD_WITH_PROBE_TAP
# Mesh network manager / provisioner application (create-network, address
# allocation, node roster + DevKey store, Config Client) end to end.
ATF_TESTS_C+=	mesh_manager_test
SRCS.mesh_manager_test=	mesh_manager_test.c ${MESHD_ENGINE}
CFLAGS.mesh_manager_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# meshd Config Client operability layer: the "cfg" control verbs seal a
# Configuration message to a roster node's DevKey, transmit it, and correlate
# the Config Status; plus manager-DB persistence and the OTA provisioning verbs.
ATF_TESTS_C+=	mesh_cfgclient_test
SRCS.mesh_cfgclient_test=	mesh_cfgclient_test.c ptap_meshd_cfgclient.c \
		${MESHD_ENGINE:Nmeshd_cfgclient.c}
CFLAGS.mesh_cfgclient_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# meshd Directed Forwarding wiring (finding 129): DF Configuration Server model
# registration, "df" Config-Client verbs, and the Path Origin discovery FSM.
ATF_TESTS_C+=	meshd_df_test
SRCS.meshd_df_test=	meshd_df_test.c ${MESHD_ENGINE}
CFLAGS.meshd_df_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# meshd Remote Provisioning wiring (finding 128): RPR Server model registration,
# "remote-prov" Client verbs, and the scan/link client FSM transitions.
ATF_TESTS_C+=	meshd_rpr_test
SRCS.meshd_rpr_test=	meshd_rpr_test.c ${MESHD_ENGINE}
CFLAGS.meshd_rpr_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# meshd Friendship wiring (MshPRT_v1.1 Section 3.6.5/3.6.6): the Friend and Low
# Power node roles driven over the bearer (Request/Offer/Poll/Update handshake +
# queued-message delivery on Poll) plus the "friend"/"low-power" control verbs.
ATF_TESTS_C+=	meshd_friendship_test
SRCS.meshd_friendship_test=	meshd_friendship_test.c ${MESHD_ENGINE}
CFLAGS.meshd_friendship_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# meshd persistent node-state store: SEQ block reservation (no regress across
# restart), RPL survives restart, keys/IV/config round-trip, clock tick.
ATF_TESTS_C+=	meshd_persist_test
ATF_TESTS_C+=	meshd_persist_fault_test
SRCS.meshd_persist_test=	meshd_persist_test.c ptap_meshd_persist.c \
	${MESHD_ENGINE:Nmeshd_persist.c}
CFLAGS.meshd_persist_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
SRCS.meshd_persist_fault_test=	meshd_persist_fault_test.c ${MESHD_ENGINE}
CFLAGS.meshd_persist_fault_test+=	-I${SRCTOP}/lib/libmesh \
	-I${SRCTOP}/usr.sbin/bluetooth/meshd
LDFLAGS.meshd_persist_fault_test+=	-Wl,--wrap=write -Wl,--wrap=fsync \
	-Wl,--wrap=rename
SRCS.meshd_fault_test=	meshd_fault_test.c ${MESHD_ENGINE}
CFLAGS.meshd_fault_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# Regression tests for the meshd/meshctl correctness + completeness findings
# (bluetooth-bugs.md 52-55, 69, 71, 73, 106, 107, 126, 127, 130, 131).
SRCS.mesh_findings_meshd_test=	mesh_findings_meshd_test.c ${MESHD_ENGINE}
CFLAGS.mesh_findings_meshd_test+=	-I${SRCTOP}/lib/libmesh \
		-I${SRCTOP}/usr.sbin/bluetooth/meshd
# Force the (otherwise unreachable) PB-ADV link-open failure path for finding
# 123's regression test; the wrapper passes through unless a flag is set.
LDFLAGS.mesh_findings_meshd_test+=	-Wl,--wrap=mesh_prov_link_open
# Configuration Server dispatch runtime + node config database end-to-end.
SRCS.mesh_cfgsrv_test=	mesh_cfgsrv_test.c ${MESHD_ENGINE}
CFLAGS.mesh_cfgsrv_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# Mesh 1.1 Configuration model codecs + their Config Server dispatch integration.
SRCS.mesh_cfg_v11_test=	mesh_cfg_v11_test.c ${MESHD_ENGINE}
CFLAGS.mesh_cfg_v11_test+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/usr.sbin/bluetooth/meshd
# Real-IPC LOOPBACK: links BOTH bearer halves into one binary -- the real
# blued mesh-bearer verb handling (ctl.c + its dep set) and the real meshd
# bearer client (meshd_bearer_blued.c) -- and makes them talk over a real
# socketpair.  The meshd RX seams are link-wrapped so each AD type's landing is
# observed on the far side of the wire; the blued HCI seam is captured in-test.
ATF_TESTS_C+=	mesh_broker_loop_test
SRCS.mesh_broker_loop_test=	mesh_broker_loop_test.c \
	ctl.c ctl_conn.c ctl_gatt.c conn.c att.c att_server.c \
	att_server_dispatch.c att_server_notify.c att_server_hash.c gatt.c \
	config.c adv_builder.c ctl_privacy_oob_stub.c \
	meshd_bearer_blued.c ${MESHD_ENGINE}
CFLAGS.mesh_broker_loop_test+=	-I${SRCTOP}/lib/libmesh \
	-I${SRCTOP}/usr.sbin/bluetooth/meshd
LDFLAGS.mesh_broker_loop_test+=	-Wl,--wrap=meshd_bearer_rx \
	-Wl,--wrap=meshd_beacon_rx -Wl,--wrap=meshd_provisioner_recv
LIBADD.mesh_broker_loop_test+=	pthread ucl
CFLAGS.meshd_test.c+=	-Wno-cast-qual
CFLAGS.meshd_fault_test.c+=	-Wno-missing-prototypes -Wno-cast-qual
LDFLAGS.meshd_fault_test+=	-Wl,--wrap=mesh_sim_init -Wl,--wrap=mesh_sim_add_node \
	-Wl,--wrap=mesh_sim_add_model -Wl,--wrap=mesh_sim_reinject \
	-Wl,--wrap=mesh_sim_send_access -Wl,--wrap=mesh_gen_onoff_set_encode \
	-Wl,--wrap=mesh_gen_level_set_encode -Wl,--wrap=mesh_prov_data_unpack \
	-Wl,--wrap=mesh_cfg_comp_page0_encode -Wl,--wrap=mesh_cfg_comp_status_build \
	-Wl,--wrap=mesh_cfg_u8_state_build -Wl,--wrap=mesh_cfg_u8_state_parse \
	-Wl,--wrap=mesh_cfg_comp_get_parse -Wl,--wrap=mesh_cfg_node_reset_status_build \
	-Wl,--wrap=mesh_hlt_attention_build -Wl,--wrap=mesh_hlt_attention_parse \
	-Wl,--wrap=mesh_hlt_fault_get_parse -Wl,--wrap=mesh_hlt_fault_status_build
SRCS.smp_crypto_test+=	smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_pairing_test+=	smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
SRCS.att_test+=		att.c att_server.c att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.peripheral_test+=	att.c att_server.c att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.conn_test+=	conn.c
LIBADD.conn_test+=	pthread
SRCS.ctl_test+=		ptap_ctl.c ctl_conn.c ctl_gatt.c conn.c att.c \
			att_server.c att_server_dispatch.c att_server_notify.c \
			att_server_hash.c gatt.c config.c adv_builder.c
SRCS.iso_lifecycle_test=	iso_lifecycle_test.c iso.c ctl_iso.c
LDFLAGS.iso_lifecycle_test+=	-Wl,--wrap=calloc
LIBADD.iso_lifecycle_test+=	pthread
SRCS.config_test+=	config.c
SRCS.persist_test=	persist_test.c blued_persist.c
SRCS.devmgr_test=	devmgr_test.c blued_devmgr.c blued_persist.c
SRCS.hci_hw_test+=	hci_util.c hci_adv.c hci_scan.c hci_conn.c \
			hci_privacy.c hci_misc.c hci_log.c
SRCS.hci_log_test+=	hci_log.c
SRCS.gatt_test+=	att.c att_server.c att_server_dispatch.c att_server_notify.c att_server_hash.c gatt.c
SRCS.adv_data_test+=	adv_data.c
SRCS.hci_offline_test=	hci_offline_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.hci_conform_test=	hci_conform_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.hci_conform_test+=	-Wl,--wrap=bt_devreq
LIBADD.hci_conform_test+=	pthread

SRCS.hci_findings_test=	hci_findings_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.hci_findings_test+=	-Wl,--wrap=bt_devreq
LIBADD.hci_findings_test+=	pthread

# Advertising / connection parameter HCI emission via the bt_devreq wrap seam:
# hci_adv_configure() (SET_ADV_PARAMS) + LE Connection Update / Set PHY / Set
# Data Length encoders (CONNPARAMS_UPDATE / SET_PHY / SET_DATA_LEN).
SRCS.ctl_adv_conn_test=	ctl_adv_conn_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.ctl_adv_conn_test+=	-Wl,--wrap=bt_devreq
LIBADD.ctl_adv_conn_test+=	pthread

# Structured advertising-data builder: pure [len][type][data] AD-structure
# byte assertions (no HCI seam needed).
SRCS.adv_builder_test=	adv_builder_test.c adv_builder.c

# Runtime-privacy HCI emission (LE Set Address Resolution Enable / Set RPA
# Timeout / scan own-address threading) via the bt_devreq wrap seam.
SRCS.privacy_scan_test=	privacy_scan_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.privacy_scan_test+=	-Wl,--wrap=bt_devreq
LIBADD.privacy_scan_test+=	pthread

# Adapter runtime-setting + scan-filter HCI emission via the bt_devreq wrap
# seam: LE Set [Ext] Scan Parameters / Scan Enable, discoverable Flags AD, and
# the post-scan result-filter predicate.
SRCS.ctl_adapter_scan_test=	ctl_adapter_scan_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.ctl_adapter_scan_test+=	-Wl,--wrap=bt_devreq
LIBADD.ctl_adapter_scan_test+=	pthread

# Periodic Advertising / PAST / Direction Finding: command byte layout via
# the bt_devreq wrap seam + LE Meta event decode via blued_parse_le_meta_event.
SRCS.hci_periodic_df_test=	hci_periodic_df_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.hci_periodic_df_test+=	-Wl,--wrap=bt_devreq
LIBADD.hci_periodic_df_test+=	pthread
SRCS.hogp_test=		hogp_test.c hogp_report.c
LIBADD.hogp_test=
SRCS.libble_test=	libble_test.c ble.c
LIBADD.libble_test+=	pthread

SRCS.smp_negative_test=	smp_negative_test.c smp.c smp_crypto.c smp_keys.c \
			smp_legacy.c smp_sc.c
LDFLAGS.smp_negative_test+=	-Wl,--wrap=socket
SRCS.smp_timeout_test=	smp_timeout_test.c smp.c smp_crypto.c smp_keys.c \
			smp_legacy.c smp_sc.c
LIBADD.smp_timeout_test+=	pthread
SRCS.smp_sc_oob_test=	smp_sc_oob_test.c smp.c smp_crypto.c smp_keys.c \
			smp_legacy.c smp_sc.c
LIBADD.smp_sc_oob_test+=	pthread
SRCS.att_negative_test=	att_negative_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.gatt_client_test=	gatt_client_test.c att.c gatt.c
SRCS.hci_event_test=	hci_event_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.privacy_test=	privacy_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c \
			smp_crypto.c smp_keys.c
ATF_TESTS_C+=	multiadapter_test
SRCS.multiadapter_test=	multiadapter_test.c ctl.c ctl_conn.c ctl_gatt.c \
			conn.c att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c config.c \
			adv_builder.c ctl_privacy_oob_stub.c
LIBADD.multiadapter_test+=	pthread ucl
SRCS.libble_negative_test=	libble_negative_test.c ble.c
SRCS.config_negative_test=	config_negative_test.c config.c
SRCS.hogp_report_map_test=	hogp_report_map_test.c
LIBADD.hogp_report_map_test=
SRCS.hogp_boot_test=	hogp_boot_test.c hogp_boot.c
LIBADD.hogp_boot_test=
SRCS.findings_regression_test=	findings_regression_test.c ble.c
SRCS.adv_regression_test=	adv_regression_test.c adv_data.c
SRCS.profile_data_test=	profile_data_test.c profile_fixtures.c att.c \
			att_server.c att_server_dispatch.c att_server_notify.c \
			att_server_hash.c gatt.c
SRCS.hci_emulator_test=	hci_emulator_test.c hci_emulator.c
SRCS.hci_emulator_link_test=	hci_emulator_link_test.c hci_emulator.c
SRCS.hci_emulator_enc_test=	hci_emulator_enc_test.c hci_emulator.c
SRCS.hci_emulator_deep_test=	hci_emulator_deep_test.c hci_emulator.c
SRCS.conn_deep_test=	conn_deep_test.c conn.c
SRCS.smp_fault_test=	smp_fault_test.c smp.c smp_crypto.c smp_keys.c \
			smp_legacy.c smp_sc.c
SRCS.libble_fault_test=	libble_fault_test.c ble.c
SRCS.l2cap_sig_rsp_test=	l2cap_sig_rsp_test.c
SRCS.power_control_test=	power_control_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.power_control_test+=	-Wl,--wrap=bt_devreq
SRCS.power_control_deep_test=	power_control_deep_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.power_control_deep_test+=	-Wl,--wrap=bt_devreq
# ISO transport (CIS/BIG/ISO-data-path) command-encoder conformance.  Same
# link set + bt_devreq wrap seam as hci_devreq_mock_test; the wrap also
# captures the built command bytes so the on-wire layout is checked byte for
# byte against Core Spec Vol 4 Part E §7.8.96-116.
SRCS.iso_transport_test=	iso_transport_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.iso_transport_test+=	-Wl,--wrap=bt_devreq
SRCS.iso_deep_test=	iso_deep_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.iso_deep_test+=	-Wl,--wrap=bt_devreq
# ISO control-plane callers (CIG provisioning, Setup ISO Data Path,
# established-stream orchestration).  Same link set + bt_devreq wrap seam;
# the wrap captures a SEQUENCE of commands so multi-command callers are
# checked command by command against Core Spec Vol 4 Part E §7.8.97/§7.8.109.
SRCS.iso_control_test=	iso_control_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
LDFLAGS.iso_control_test+=	-Wl,--wrap=bt_devreq
# Probe-tap observability test.  The BLUED_PROBE_* sites this test asserts on
# live in att_server.c, gatt.c and smp.c; those must be compiled with
# -DWITH_PROBE_TAP so the macros record into the in-process ring buffer
# (blued_probe_tap.c).  The production objects are shared (one .o each) across
# every test in this directory, so instead of tap-poisoning the shared
# att_server.pieo/gatt.pieo/smp.pieo (which would break the other tests, none
# of which link blued_probe_tap.c) this test links uniquely-named ptap_*.c
# wrappers that #include those sources and carry the define per-source.  The
# remaining, un-asserted dependencies (att.c, att_server_dispatch.c, the other
# smp_*.c, ...) are linked as their normal no-tap shared objects: they simply
# do not reference the tap and their probes stay silent.
SRCS.probe_tap_test=	probe_tap_test.c blued_probe_tap.c \
			ptap_att_server.c ptap_gatt.c ptap_smp.c \
			ptap_att_server_notify.c \
			att.c att_server_dispatch.c \
			att_server_hash.c smp_crypto.c smp_keys.c \
			smp_legacy.c smp_sc.c
CFLAGS.ptap_att_server.c+=	-DWITH_PROBE_TAP
CFLAGS.ptap_gatt.c+=		-DWITH_PROBE_TAP
CFLAGS.ptap_smp.c+=		-DWITH_PROBE_TAP
CFLAGS.ptap_att_server_notify.c+=	-DWITH_PROBE_TAP
LIBADD.probe_tap_test+=	pthread
SRCS.hci_encode_edge_test=	hci_encode_edge_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.hci_scan_parse_edge_test=	hci_scan_parse_edge_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.smp_keys_edge_test=	smp_keys_edge_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_secret_test=	smp_secret_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
LDFLAGS.smp_secret_test+=	-Wl,--wrap=open -Wl,--wrap=openat \
				-Wl,--wrap=write
SRCS.bond_migrate_test=	bond_migrate_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_sc_edge_test=	smp_sc_edge_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_legacy_edge_test=	smp_legacy_edge_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.att_client_test=	att_client_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.att_server_edge_test=	att_server_edge_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.platform_test=	platform_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.att_server_cov_test=	att_server_cov_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
CFLAGS.att_server_cov_test.c+=	-Wno-missing-prototypes \
			-Wno-missing-variable-declarations
SRCS.att_client_cov_test=	att_client_cov_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
CFLAGS.att_client_cov_test.c+=	-Wno-missing-prototypes \
			-Wno-missing-variable-declarations
SRCS.mesh_crypto_fault_test=	mesh_crypto_fault_test.c mesh_crypto.c
CFLAGS.mesh_crypto_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_crypto_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_crypto_fault_test+=	-Wl,--wrap=EVP_CIPHER_CTX_new -Wl,--wrap=EVP_CIPHER_CTX_ctrl \
	-Wl,--wrap=EVP_EncryptInit_ex -Wl,--wrap=EVP_EncryptUpdate -Wl,--wrap=EVP_EncryptFinal_ex \
	-Wl,--wrap=EVP_DecryptInit_ex -Wl,--wrap=EVP_DecryptUpdate -Wl,--wrap=EVP_MAC_fetch \
	-Wl,--wrap=EVP_MAC_CTX_new -Wl,--wrap=EVP_MAC_init -Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final
SRCS.mesh_beacon_fault_test=	mesh_beacon_fault_test.c mesh_beacon.c mesh_crypto.c
CFLAGS.mesh_beacon_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_beacon_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_beacon_fault_test+=	-Wl,--wrap=EVP_MAC_init
SRCS.mesh_provision_fault_test=	mesh_provision_fault_test.c mesh_provision.c mesh_crypto.c
CFLAGS.mesh_provision_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_provision_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_provision_fault_test+=	-Wl,--wrap=EVP_PKEY_CTX_new_id -Wl,--wrap=EVP_PKEY_keygen_init \
	-Wl,--wrap=EVP_PKEY_CTX_set_ec_paramgen_curve_nid -Wl,--wrap=EVP_PKEY_keygen \
	-Wl,--wrap=EVP_PKEY_get_octet_string_param -Wl,--wrap=EC_GROUP_new_by_curve_name -Wl,--wrap=BN_bin2bn \
	-Wl,--wrap=EC_POINT_new -Wl,--wrap=BN_new -Wl,--wrap=EC_POINT_mul \
	-Wl,--wrap=EC_POINT_get_affine_coordinates -Wl,--wrap=BN_bn2binpad -Wl,--wrap=OSSL_PARAM_BLD_new \
	-Wl,--wrap=OSSL_PARAM_BLD_push_utf8_string -Wl,--wrap=OSSL_PARAM_BLD_push_BN \
	-Wl,--wrap=OSSL_PARAM_BLD_push_octet_string -Wl,--wrap=OSSL_PARAM_BLD_to_param \
	-Wl,--wrap=EVP_PKEY_CTX_new_from_name -Wl,--wrap=EVP_PKEY_fromdata_init -Wl,--wrap=EVP_PKEY_fromdata \
	-Wl,--wrap=EVP_PKEY_CTX_new -Wl,--wrap=EVP_PKEY_derive_init -Wl,--wrap=EVP_PKEY_derive_set_peer \
	-Wl,--wrap=EVP_PKEY_derive -Wl,--wrap=EVP_MAC_init -Wl,--wrap=EC_POINT_is_on_curve \
	-Wl,--wrap=EC_POINT_is_at_infinity
SRCS.mesh_netxport_fault_test=	mesh_netxport_fault_test.c mesh_net.c mesh_transport.c mesh_crypto.c
CFLAGS.mesh_netxport_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_netxport_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_netxport_fault_test+=	-Wl,--wrap=mesh_aes128_e -Wl,--wrap=mesh_aes_ccm_encrypt
SRCS.mesh_proxy_fault_test=	mesh_proxy_fault_test.c mesh_proxy.c mesh_crypto.c
CFLAGS.mesh_proxy_fault_test+=	-I${SRCTOP}/lib/libmesh
CFLAGS.mesh_proxy_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.mesh_proxy_fault_test+=	-Wl,--wrap=mesh_aes128_e -Wl,--wrap=mesh_aes_ccm_encrypt
SRCS.conn_fault_test=		conn_fault_test.c conn.c
CFLAGS.conn_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.conn_fault_test+=	-Wl,--wrap=calloc
SRCS.config_fault_test=		config_fault_test.c config.c
CFLAGS.config_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.config_fault_test+=	-Wl,--wrap=lseek -Wl,--wrap=malloc
LIBADD.config_fault_test+=	ucl
SRCS.hci_emulator_fault_test=		hci_emulator_fault_test.c hci_emulator.c
CFLAGS.hci_emulator_fault_test.c+=	-Wno-missing-prototypes
LDFLAGS.hci_emulator_fault_test+=	-Wl,--wrap=malloc -Wl,--wrap=calloc
SRCS.gatt_discovery_edge_test=	gatt_discovery_edge_test.c att.c gatt.c
SRCS.config_edge_test=	config_edge_test.c config.c
SRCS.libble_edge_test=	libble_edge_test.c ble.c
SRCS.ctl_conn_edge_test=	ctl_conn_edge_test.c ctl.c ctl_conn.c ctl_gatt.c \
			conn.c att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c config.c \
			adv_builder.c ctl_privacy_oob_stub.c
SRCS.hci_log_deep_test=	hci_log_deep_test.c hci_util.c hci_adv.c hci_scan.c \
			hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.hci_drive_deep_test=	hci_drive_deep_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
SRCS.l2cap_sig_test=	l2cap_sig_test.c
SRCS.smp_deep_legacy_test=	smp_deep_legacy_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_deep_sc_test=	smp_deep_sc_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_deep_scneg_test=	smp_deep_scneg_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.smp_deep_misc_test=	smp_deep_misc_test.c smp.c smp_crypto.c \
			smp_keys.c smp_legacy.c smp_sc.c
SRCS.gatt_client_deepcov_test=	gatt_client_deepcov_test.c att.c gatt.c
SRCS.config_coverage_test=	config_coverage_test.c config.c
SRCS.libble_branch_test=	libble_branch_test.c ble.c
SRCS.att_server_deep_test=	att_server_deep_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.att_client_deep_test=	att_client_deep_test.c att.c att_server.c \
			att_server_dispatch.c att_server_notify.c att_server_hash.c
SRCS.hci_devreq_mock_test=	hci_devreq_mock_test.c hci_util.c hci_adv.c \
			hci_scan.c hci_conn.c hci_privacy.c hci_misc.c hci_log.c
# Redirect the encoders' bt_devreq() to the test's __wrap_bt_devreq so a
# controllable controller response drives the rp.status success/failure arms.
LDFLAGS.hci_devreq_mock_test+=	-Wl,--wrap=bt_devreq

LIBADD+=	bluetooth crypto
LIBADD.ctl_test+=	pthread ucl
LIBADD.config_test+=	ucl
LIBADD.smp_negative_test+=	pthread
LIBADD.smp_keys_edge_test+=	pthread
LIBADD.smp_secret_test+=	pthread
LIBADD.bond_migrate_test+=	pthread
LIBADD.smp_sc_edge_test+=	pthread
LIBADD.smp_legacy_edge_test+=	pthread
LIBADD.config_edge_test+=	ucl
LIBADD.ctl_conn_edge_test+=	pthread ucl
LIBADD.smp_deep_legacy_test+=	pthread
LIBADD.smp_deep_sc_test+=	pthread
LIBADD.smp_deep_scneg_test+=	pthread
LIBADD.smp_deep_misc_test+=	pthread

# l2cap_sig_test #include's the kernel TU ng_l2cap_evnt.c to reach its static
# signalling decoders.  The include path is program-wide; the warning
# suppressions must be per-source (.c) so they land after the WARNS flags.
# The kernel TU's debug macros are no-ops in userspace and it is compiled
# outside the kernel build's own -Wno set, so relax the warnings it trips.
CFLAGS.l2cap_sig_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/l2cap
CFLAGS.l2cap_sig_test.c+=	-Wno-unused-variable -Wno-unused-parameter \
			-Wno-unused-function -Wno-missing-prototypes \
			-Wno-sign-compare -Wno-cast-align
LIBADD.config_negative_test+=	ucl

# libFuzzer harness sources for the PDU parsers (ATT/GATT, advertising data,
# libble IPC, SMP responder, control socket, kernel L2CAP
# signalling).  These need -fsanitize=fuzzer and are a developer tool, so they
# are NOT built by the world build; ship their sources and build glue as data
# files under fuzz/ so an installed bluetooth-tests package carries them.  Use
# a dedicated FUZZ filegroup (not the bsd.test.mk-owned ${PACKAGE}FILES group,
# whose DIR is pinned to ${TESTSDIR}) so they install into the fuzz/
# subdirectory and are tagged into the package.  Build/run instructions and
# the sandbox truss caveat live in the fuzz/Makefile header.
FILESGROUPS+=	FUZZ
FUZZDIR=	${TESTSDIR}/fuzz
FUZZPACKAGE=	${PACKAGE}
FUZZ+=		fuzz/Makefile
FUZZ+=		fuzz/gen_corpus.sh
FUZZ+=		fuzz/standalone.c
FUZZ+=		fuzz/fuzz_att_server.c
FUZZ+=		fuzz/fuzz_adv_data.c
FUZZ+=		fuzz/fuzz_ble_ipc.c
FUZZ+=		fuzz/fuzz_adv_report.c
FUZZ+=		fuzz/fuzz_gatt_client.c
FUZZ+=		fuzz/fuzz_smp_responder.c
FUZZ+=		fuzz/fuzz_ctl_ipc.c
FUZZ+=		fuzz/fuzz_l2cap_sig.c
FUZZ+=		fuzz/fuzz_mesh_net.c
FUZZ+=		fuzz/fuzz_mesh_access.c
FUZZ+=		fuzz/fuzz_l2cap_data.c
FUZZ+=		fuzz/fuzz_config.c
FUZZ+=		fuzz/fuzz_scan_parse.c
FUZZ+=		fuzz/fuzz_hci_event.c
FUZZ+=		fuzz/fuzz_smp_sc.c
FUZZ+=		fuzz/fuzz_hogp_report_map.c
FUZZ+=		fuzz/fuzz_mesh_provision.c
FUZZ+=		fuzz/fuzz_mesh_beacon.c
FUZZ+=		fuzz/fuzz_mesh_proxy.c
FUZZ+=		fuzz/fuzz_mesh_friend.c
FUZZ+=		fuzz/fuzz_mesh_transport.c
FUZZ+=		fuzz/fuzz_att_client.c
FUZZ+=		fuzz/fuzz_mesh_sim.c

# Ensure every fuzz harness advertised by fuzz/Makefile is present in the
# installed bluetooth-tests package.
ATF_TESTS_SH+=	fuzz_manifest_test

# The daemon is also a native capability bundle; keep its package layout and
# storage/activation contract in the ordinary Bluetooth regression suite.
ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

ATF_TESTS_C+=	l2cap_data_test
SRCS.l2cap_data_test=	l2cap_data_test.c
CFLAGS.l2cap_data_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/l2cap
CFLAGS.l2cap_data_test.c+=	-Wno-unused-variable -Wno-unused-parameter \
			-Wno-unused-function -Wno-missing-prototypes \
			-Wno-sign-compare -Wno-cast-align

# l2cap_data_deep_test reuses l2cap_data_test's shim to #include the kernel
# credit data-path TUs (ng_l2cap_misc.c + ng_l2cap_cmds.c + ng_l2cap_ulpi.c +
# ng_l2cap_evnt.c); same include path and warning relaxations.
ATF_TESTS_C+=	l2cap_data_deep_test
SRCS.l2cap_data_deep_test=	l2cap_data_deep_test.c
CFLAGS.l2cap_data_deep_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/l2cap
CFLAGS.l2cap_data_deep_test.c+=	-Wno-unused-variable -Wno-unused-parameter \
			-Wno-unused-function -Wno-missing-prototypes \
			-Wno-sign-compare -Wno-cast-align

# Control-socket framed IPC protocol (ipc_proto.h): wire framing round-trip
# plus the libble handshake / error-taxonomy / event-routing (C8) client path.
ATF_TESTS_C+=	ipc_frame_test
SRCS.ipc_frame_test=	ipc_frame_test.c
ATF_TESTS_C+=	ipc_client_test
SRCS.ipc_client_test=	ipc_client_test.c ble.c
LDFLAGS.ipc_client_test+=	-Wl,--wrap=sendmsg

# Deferred IPC feature phases (findings C1/C2/C5/C9/C10): connection-lifecycle
# push events, CONNINFO MTU surfacing, pairing correlation, advertising
# commands.  Daemon-side test links the control server object set.
ATF_TESTS_C+=	ipc_events_test
SRCS.ipc_events_test=	ipc_events_test.c ctl.c ctl_conn.c ctl_gatt.c \
			conn.c att.c att_server.c att_server_dispatch.c \
			att_server_notify.c att_server_hash.c gatt.c config.c \
			adv_builder.c ctl_privacy_oob_stub.c
LIBADD.ipc_events_test+=	pthread ucl

# Client-side (libble) surface the bluedctl CLI is built on: CONNECTED/
# DISCONNECTED event dispatch + MTU, advertising / conninfo command wrappers.
ATF_TESTS_C+=	cli_ipc_test
SRCS.cli_ipc_test=	cli_ipc_test.c ble.c

# K1 stack-OOB regression: #include's the bluedctl PROG translation unit (with
# main() renamed) to drive its static join_args() directly.
# The renamed main becomes an ordinary global -> silence -Wmissing-prototypes.
ATF_TESTS_C+=	cli_test
SRCS.cli_test=	cli_test.c ble.c
CFLAGS.cli_test+=	-I${SRCTOP}/usr.sbin/bluetooth/bluedctl
CFLAGS.cli_test.c+=	-Wno-missing-prototypes


# === iso_socket_test: AF_BLUETOOTH ISO/CIS kernel socket unit tests ======
# TU-include harness (mirrors l2cap_data_test.c): #includes the kernel
# ng_btsocket_iso.c with userspace mbuf-cluster / mtx / callout / sockbuf /
# netgraph shims to exercise ng_btsocket_iso_send2 / _data_input / _connect /
# _ctloutput directly.  Covers the ISO socket security findings (heap/cluster
# overflow in send2 segmentation, reassembly bounds, TS_Flag handling,
# reconnect-while-OPEN, pkt_size clamp) against Core Spec Vol 4 Part E 5.4.5.
ATF_TESTS_C+=	iso_socket_test
SRCS.iso_socket_test=	iso_socket_test.c
CFLAGS.iso_socket_test+=	-I${SRCTOP}/sys/netgraph/bluetooth/socket
CFLAGS.iso_socket_test.c+=	-Wno-unused-variable -Wno-unused-parameter \
			-Wno-unused-function -Wno-missing-prototypes \
			-Wno-sign-compare -Wno-cast-align -Wno-shadow \
			-Wno-missing-variable-declarations -Wno-cast-qual \
			-Wno-pointer-arith
# =========================================================================

meshd_node.pieo meshd_pbgatt.pieo meshd_cfgclient.pieo: ${SRCTOP}/usr.sbin/bluetooth/meshd/meshd.h
conn.pieo ctl.pieo ctl_conn.pieo ctl_gatt.pieo blued_event.pieo: ${SRCTOP}/usr.sbin/bluetooth/blued/blued.h ${SRCTOP}/usr.sbin/bluetooth/blued/blued_internal.h
ble.pieo ctl.pieo ctl_conn.pieo ctl_gatt.pieo: ${SRCTOP}/lib/libble/ipc_proto.h

# Machine-enforced, case-by-case Bluetooth specification traceability gate.
# It classifies every generated Kyua case and verifies that every implemented
# normative requirement in spec_requirements.tsv is exercised by a test.
spec-traceability: Kyuafile
	${.CURDIR}/spec_traceability_audit.sh -q ${.OBJDIR}/Kyuafile
	${.CURDIR}/spec_case_manifest_audit.sh -q ${.OBJDIR}/Kyuafile

# Completion gate: unlike spec-traceability, this rejects every provisional,
# missing-oracle, or environment-blocked per-case record.
spec-traceability-strict: Kyuafile
	${.CURDIR}/spec_traceability_audit.sh -q ${.OBJDIR}/Kyuafile
	${.CURDIR}/spec_case_manifest_audit.sh -q --strict ${.OBJDIR}/Kyuafile

.include <bsd.test.mk>
