PACKAGE=	bluetooth-tests

# SPDX-License-Identifier: BSD-2-Clause
#
# libFuzzer harnesses over the blued / libble / kernel-L2CAP PDU parsers that
# consume untrusted input.  Each feeds arbitrary bytes to one decode entry
# point and relies on AddressSanitizer / UndefinedBehaviorSanitizer to catch
# out-of-bounds access and UB.  Harnesses:
#
#   fuzz_att_server   att_server_handle()          ATT requests (peripheral)
#   fuzz_adv_data     print_adv_data()             advertising / scan-rsp AD
#   fuzz_ble_ipc      ble_process()                libble control-socket frames
#   fuzz_adv_report   hci_parse_ext_adv_report()   LE adv reports (scan path)
#   fuzz_gatt_client  gatt_discover_*()            ATT responses (GATT client)
#   fuzz_smp_responder smp_respond()               SMP pairing PDUs
#   fuzz_ctl_ipc      blued_ctl_dispatch()         blued control-socket frames
#   fuzz_l2cap_sig    ng_l2cap_receive()           kernel L2CAP signalling
#   fuzz_l2cap_data   ng_l2cap_l2ca_receive()      kernel L2CAP K-frame data
#   fuzz_config       blued_config_load_fd()       blued config-file parser
#   fuzz_scan_parse   legacy LE adv report + merge (hci_scan.c)
#   fuzz_hci_event    blued_parse_le_meta_event()  LE Meta events (controller)
#   fuzz_smp_sc       smp_respond_sc()/smp_pair_sc  SMP Secure Connections PDUs
#   fuzz_hogp_report_map hogp_handle_vhid_output()  HOGP output-report routing
#
# These are intentionally NOT wired into bsd.test.mk: libFuzzer targets are
# developer/CI fuzzing tools, not ATF regression tests.  Build/run explicitly:
#
#     make                 # build all libFuzzer + std_* replay drivers
#     make corpus          # (re)generate the seed corpus via gen_corpus.sh
#     make check           # replay the seed corpus under ASan/UBSan (CI-safe)
#     make run-att         # coverage-guided fuzz of one harness (run-<name>)
#     make smoke           # brief coverage-guided run of every harness
#     make clean
#
# Requires clang with -fsanitize=fuzzer (base-system cc on 5BSD).
#
# SANDBOX CAVEAT: in some restricted sandboxes an ASan binary built here hangs
# at startup when run directly, but runs correctly under truss(1) (ptrace
# changes how the large MAP_FIXED ASan shadow mappings are handled).  If a
# driver hangs with no output, run it under truss -- this is an environment
# artifact, not a defect:
#
#     truss -o /dev/null ./std_adv_data corpus/adv_data

H=		${.CURDIR}
SRCTOP?=	${.CURDIR}/../../../../..
BLUED=		${SRCTOP}/usr.sbin/bluetooth/blued
HCCONTROL=	${SRCTOP}/usr.sbin/bluetooth/hccontrol
LIBBLE=		${SRCTOP}/lib/libble
LIBMESH=	${SRCTOP}/lib/libmesh

CC?=		cc
SAN=		-fsanitize=fuzzer,address,undefined
# Standalone replay driver: sanitizers without the libFuzzer runtime.
STDSAN=		-fsanitize=address,undefined
INCS=		-I${H}/.. -I${BLUED} -I${SRCTOP}/sys -I${HCCONTROL} -I${LIBBLE} \
		-I${LIBMESH} -I${SRCTOP}/contrib/libucl/include
FUZZFLAGS=	-g -O1 ${SAN} ${INCS}
STDFLAGS=	-g -O1 ${STDSAN} ${INCS}
LIBS=		-lbluetooth -lcrypto

# Number of seconds each `run-*' target fuzzes for in CI smoke mode.
RUNTIME?=	30
RUNOPTS=	-max_total_time=${RUNTIME} -print_final_stats=1

ATT_SRCS=	${BLUED}/att.c ${BLUED}/att_server.c \
		${BLUED}/att_server_dispatch.c ${BLUED}/att_server_notify.c \
		${BLUED}/att_server_hash.c
ADV_SRCS=	${HCCONTROL}/adv_data.c
BLE_SRCS=	${LIBBLE}/ble.c
HCI_SRCS=	${BLUED}/hci_util.c ${BLUED}/hci_adv.c ${BLUED}/hci_scan.c \
		${BLUED}/hci_conn.c ${BLUED}/hci_privacy.c ${BLUED}/hci_misc.c \
		${BLUED}/hci_log.c
GATT_SRCS=	${BLUED}/att.c ${BLUED}/gatt.c
SMP_SRCS=	${BLUED}/smp.c ${BLUED}/smp_crypto.c ${BLUED}/smp_keys.c \
		${BLUED}/smp_legacy.c ${BLUED}/smp_sc.c
CTL_SRCS=	${BLUED}/ctl.c ${BLUED}/ctl_conn.c ${BLUED}/ctl_gatt.c \
		${BLUED}/conn.c ${BLUED}/att.c ${BLUED}/att_server.c \
		${BLUED}/att_server_dispatch.c ${BLUED}/att_server_notify.c \
		${BLUED}/att_server_hash.c ${BLUED}/gatt.c ${BLUED}/config.c \
		${BLUED}/adv_builder.c
CTL_STUB_SRCS=	${H}/../ctl_privacy_oob_stub.c
MESH_SRCS=	${LIBMESH}/mesh_net.c ${LIBMESH}/mesh_crypto.c
# Access layer + Configuration / Health model message parsers.  The access
# layer pulls in mesh_crypto (s1 / AES-CMAC), so mesh_crypto.c is linked and
# -lcrypto is required for this harness.
MESH_ACCESS_SRCS=	${LIBMESH}/mesh_access.c ${LIBMESH}/mesh_cfg_model.c \
		${LIBMESH}/mesh_health_model.c ${LIBMESH}/mesh_crypto.c
# Multi-node mesh simulator + Generic models: the whole node receive pipeline
# (network/transport/access) plus the Generic OnOff/Level codecs.
MESH_SIM_SRCS=	${LIBMESH}/mesh_sim.c ${LIBMESH}/mesh_generic.c \
		${LIBMESH}/mesh_access.c ${LIBMESH}/mesh_net.c \
		${LIBMESH}/mesh_transport.c ${LIBMESH}/mesh_crypto.c \
		${LIBMESH}/mesh_rpl.c ${LIBMESH}/mesh_relay.c ${LIBMESH}/mesh_iv.c \
		${LIBMESH}/mesh_key_refresh.c ${LIBMESH}/mesh_beacon.c \
		${LIBMESH}/mesh_friend.c ${LIBMESH}/mesh_proxy.c \
		${LIBMESH}/mesh_df.c ${LIBMESH}/mesh_heartbeat.c \
		${LIBMESH}/mesh_cfg_model.c ${LIBMESH}/mesh_provision.c \
		${LIBMESH}/mesh_provisioner.c

# LE Meta event decoder fuzzer.  blued_parse_le_meta_event() is a pure,
# side-effect-free static-inline decoder in blued_le_meta.h; the harness
# just includes the header (which pulls <netgraph/bluetooth/include/ng_hci.h>
# via -I${SRCTOP}/sys), so there is nothing to compile or link separately.
HCIEV_SRCS=	# none: blued_le_meta.h is header-only (inline decoder)

# HOGP output-report routing fuzzer.  Drives the real hogp_handle_vhid_output()
# in blued_central.c, so that TU is linked together with the ATT/GATT stack it
# calls (att.c, gatt.c) plus the logging (hci_log.c) and connection (conn.c)
# TUs those pull in.  The daemon globals and the SMP/HCI helpers referenced
# only by other (uncalled) blued_central.c functions are satisfied by link-only
# stubs inside the harness.
HOGP_SRCS=	${BLUED}/blued_central.c ${BLUED}/att.c ${BLUED}/gatt.c \
		${BLUED}/hci_log.c ${BLUED}/conn.c

# L2CAP signalling decoder fuzzer.  The kernel TU is #include'd by the
# harness (it reaches the static process_*() handlers), so there is no
# separate source file to compile -- only the include paths matter:
#   -I${SRCTOP}/sys                 real UAPI (netgraph/bluetooth/include)
#   -I<l2cap dir>                   so #include "ng_l2cap_evnt.c" resolves
# The harness predefines the kernel-only header guards, so no fake-header
# tree and no libbluetooth/libcrypto are required.
L2CAP_DIR=	${SRCTOP}/sys/netgraph/bluetooth/l2cap
L2CAP_SIG_SRCS=	# none: ng_l2cap_evnt.c is #include'd, not compiled separately
L2CAP_SIG_INCS=	-I${SRCTOP}/sys -I${L2CAP_DIR}
L2CAP_SIG_FUZZFLAGS=	-g -O1 ${SAN} ${L2CAP_SIG_INCS}
L2CAP_SIG_STDFLAGS=	-g -O1 ${STDSAN} ${L2CAP_SIG_INCS}

# L2CAP credit *data-path* fuzzer.  Like fuzz_l2cap_sig it #includes the kernel
# TUs (ng_l2cap_misc.c + ng_l2cap_cmds.c + ng_l2cap_ulpi.c + ng_l2cap_evnt.c)
# to reach ng_l2cap_l2ca_receive() and the static reassembly/credit code, so
# there is nothing to compile separately -- only the include paths matter.  The
# kernel TUs trip a few warnings outside the kernel's own -Wno set; relax them.
L2CAP_DATA_INCS=	-I${SRCTOP}/sys -I${L2CAP_DIR}
L2CAP_RELAX=	-Wno-unused-variable -Wno-unused-parameter \
		-Wno-unused-function -Wno-missing-prototypes \
		-Wno-sign-compare -Wno-cast-align
L2CAP_DATA_FUZZFLAGS=	-g -O1 ${SAN} ${L2CAP_DATA_INCS} ${L2CAP_RELAX}
L2CAP_DATA_STDFLAGS=	-g -O1 ${STDSAN} ${L2CAP_DATA_INCS} ${L2CAP_RELAX}

# Config-file parser fuzzer: config.c pulls in libucl, linked from UCL_A below.
CONFIG_SRCS=	${BLUED}/config.c

# Legacy adv-report / scan-response fuzzer.  fuzz_scan_parse.c #includes
# hci_scan.c (to reach the static scan_result_merge()), so hci_scan.c is
# EXCLUDED here and the remaining HCI object set is linked.
SCAN_SRCS=	${BLUED}/hci_util.c ${BLUED}/hci_adv.c ${BLUED}/hci_conn.c \
		${BLUED}/hci_privacy.c ${BLUED}/hci_misc.c ${BLUED}/hci_log.c

# libucl is a PRIVATELIB, so it is not on the default linker path.  The world
# build stages libprivateucl.a under /usr/obj; the ctl fuzzer (config.c pulls
# in UCL) links it directly.  Override UCL_A on the command line if the world
# object tree lives elsewhere.
UCL_A!=		find /usr/obj -name libprivateucl.a -path '*tmp/usr/lib/*' 2>/dev/null | head -1

# Standalone mesh model / provisioning / transport parsers.  Each drives one
# lib/libmesh receive surface on top of mesh_crypto (s1 / AES-CMAC), so each
# links mesh_crypto.c and needs -lcrypto.
MESH_BEACON_SRCS=	${LIBMESH}/mesh_beacon.c ${LIBMESH}/mesh_crypto.c
MESH_FRIEND_SRCS=	${LIBMESH}/mesh_friend.c ${LIBMESH}/mesh_crypto.c
MESH_PROV_SRCS=		${LIBMESH}/mesh_provision.c ${LIBMESH}/mesh_crypto.c
MESH_PROXY_SRCS=	${LIBMESH}/mesh_proxy.c ${LIBMESH}/mesh_crypto.c
MESH_XPORT_SRCS=	${LIBMESH}/mesh_transport.c ${LIBMESH}/mesh_net.c \
			${LIBMESH}/mesh_crypto.c
# ATT client response decoder: drives att.c's client-side decode over the ATT
# server object graph it shares (att_server*.c + gatt.c).
ATT_CLIENT_SRCS=	${BLUED}/att.c ${BLUED}/att_server.c \
			${BLUED}/att_server_dispatch.c ${BLUED}/att_server_notify.c \
			${BLUED}/att_server_hash.c ${BLUED}/gatt.c

HARNESSES=	fuzz_att_server fuzz_adv_data fuzz_ble_ipc fuzz_adv_report \
		fuzz_gatt_client fuzz_smp_responder fuzz_ctl_ipc \
		fuzz_l2cap_sig fuzz_mesh_net fuzz_mesh_access fuzz_l2cap_data \
		fuzz_config fuzz_scan_parse fuzz_hci_event fuzz_smp_sc \
		fuzz_hogp_report_map fuzz_mesh_sim fuzz_att_client \
		fuzz_mesh_beacon fuzz_mesh_friend fuzz_mesh_provision \
		fuzz_mesh_proxy fuzz_mesh_transport
STANDALONE=	std_att_server std_adv_data std_ble_ipc std_adv_report \
		std_gatt_client std_smp_responder std_ctl_ipc \
		std_l2cap_sig std_mesh_net std_mesh_access std_l2cap_data \
		std_config std_scan_parse std_hci_event std_smp_sc \
		std_hogp_report_map std_mesh_sim

all: ${HARNESSES} ${STANDALONE}

fuzz_att_server: ${H}/fuzz_att_server.c ${ATT_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_att_server.c ${ATT_SRCS} ${LIBS}

fuzz_adv_data: ${H}/fuzz_adv_data.c ${ADV_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_adv_data.c ${ADV_SRCS} ${LIBS}

fuzz_ble_ipc: ${H}/fuzz_ble_ipc.c ${BLE_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_ble_ipc.c ${BLE_SRCS} ${LIBS}

fuzz_adv_report: ${H}/fuzz_adv_report.c ${HCI_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_adv_report.c ${HCI_SRCS} ${LIBS}

fuzz_gatt_client: ${H}/fuzz_gatt_client.c ${GATT_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_gatt_client.c ${GATT_SRCS} ${LIBS}

fuzz_smp_responder: ${H}/fuzz_smp_responder.c ${SMP_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_smp_responder.c ${SMP_SRCS} ${LIBS} -lpthread

fuzz_ctl_ipc: ${H}/fuzz_ctl_ipc.c ${CTL_SRCS} ${CTL_STUB_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_ctl_ipc.c ${CTL_SRCS} ${CTL_STUB_SRCS} ${LIBS} ${UCL_A} -lpthread

fuzz_l2cap_sig: ${H}/fuzz_l2cap_sig.c ${L2CAP_DIR}/ng_l2cap_evnt.c
	${CC} ${L2CAP_SIG_FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_l2cap_sig.c

fuzz_mesh_net: ${H}/fuzz_mesh_net.c ${MESH_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_net.c ${MESH_SRCS} -lcrypto

fuzz_mesh_access: ${H}/fuzz_mesh_access.c ${MESH_ACCESS_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_access.c ${MESH_ACCESS_SRCS} -lcrypto

fuzz_mesh_sim: ${H}/fuzz_mesh_sim.c ${MESH_SIM_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_sim.c ${MESH_SIM_SRCS} -lcrypto

fuzz_l2cap_data: ${H}/fuzz_l2cap_data.c ${L2CAP_DIR}/ng_l2cap_ulpi.c
	${CC} ${L2CAP_DATA_FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_l2cap_data.c

fuzz_config: ${H}/fuzz_config.c ${CONFIG_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_config.c ${CONFIG_SRCS} ${LIBS} ${UCL_A}

fuzz_scan_parse: ${H}/fuzz_scan_parse.c ${SCAN_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_scan_parse.c ${SCAN_SRCS} ${LIBS}

fuzz_hci_event: ${H}/fuzz_hci_event.c
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_hci_event.c ${HCIEV_SRCS}

fuzz_smp_sc: ${H}/fuzz_smp_sc.c ${SMP_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_smp_sc.c ${SMP_SRCS} ${LIBS} -lpthread

fuzz_hogp_report_map: ${H}/fuzz_hogp_report_map.c ${HOGP_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_hogp_report_map.c ${HOGP_SRCS} ${LIBS} -lpthread

fuzz_att_client: ${H}/fuzz_att_client.c ${ATT_CLIENT_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_att_client.c ${ATT_CLIENT_SRCS} ${LIBS}

fuzz_mesh_beacon: ${H}/fuzz_mesh_beacon.c ${MESH_BEACON_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_beacon.c ${MESH_BEACON_SRCS} -lcrypto

fuzz_mesh_friend: ${H}/fuzz_mesh_friend.c ${MESH_FRIEND_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_friend.c ${MESH_FRIEND_SRCS} -lcrypto

fuzz_mesh_provision: ${H}/fuzz_mesh_provision.c ${MESH_PROV_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_provision.c ${MESH_PROV_SRCS} -lcrypto

fuzz_mesh_proxy: ${H}/fuzz_mesh_proxy.c ${MESH_PROXY_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_proxy.c ${MESH_PROXY_SRCS} -lcrypto

fuzz_mesh_transport: ${H}/fuzz_mesh_transport.c ${MESH_XPORT_SRCS}
	${CC} ${FUZZFLAGS} -o ${H}/${.TARGET:T} ${H}/fuzz_mesh_transport.c ${MESH_XPORT_SRCS} -lcrypto

# Standalone (libFuzzer-runtime-free) replay builds.
std_att_server: ${H}/fuzz_att_server.c ${H}/standalone.c ${ATT_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_att_server.c ${ATT_SRCS} ${LIBS}

std_adv_data: ${H}/fuzz_adv_data.c ${H}/standalone.c ${ADV_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_adv_data.c ${ADV_SRCS} ${LIBS}

std_ble_ipc: ${H}/fuzz_ble_ipc.c ${H}/standalone.c ${BLE_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_ble_ipc.c ${BLE_SRCS} ${LIBS}

std_adv_report: ${H}/fuzz_adv_report.c ${H}/standalone.c ${HCI_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_adv_report.c ${HCI_SRCS} ${LIBS}

std_gatt_client: ${H}/fuzz_gatt_client.c ${H}/standalone.c ${GATT_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_gatt_client.c ${GATT_SRCS} ${LIBS}

std_smp_responder: ${H}/fuzz_smp_responder.c ${H}/standalone.c ${SMP_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_smp_responder.c ${SMP_SRCS} ${LIBS} -lpthread

std_ctl_ipc: ${H}/fuzz_ctl_ipc.c ${H}/standalone.c ${CTL_SRCS} ${CTL_STUB_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_ctl_ipc.c ${CTL_SRCS} ${CTL_STUB_SRCS} ${LIBS} ${UCL_A} -lpthread

std_l2cap_sig: ${H}/fuzz_l2cap_sig.c ${H}/standalone.c ${L2CAP_DIR}/ng_l2cap_evnt.c
	${CC} ${L2CAP_SIG_STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_l2cap_sig.c

std_mesh_net: ${H}/fuzz_mesh_net.c ${H}/standalone.c ${MESH_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_mesh_net.c ${MESH_SRCS} -lcrypto

std_mesh_access: ${H}/fuzz_mesh_access.c ${H}/standalone.c ${MESH_ACCESS_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_mesh_access.c ${MESH_ACCESS_SRCS} -lcrypto

std_mesh_sim: ${H}/fuzz_mesh_sim.c ${H}/standalone.c ${MESH_SIM_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_mesh_sim.c ${MESH_SIM_SRCS} -lcrypto

std_l2cap_data: ${H}/fuzz_l2cap_data.c ${H}/standalone.c ${L2CAP_DIR}/ng_l2cap_ulpi.c
	${CC} ${L2CAP_DATA_STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_l2cap_data.c

std_config: ${H}/fuzz_config.c ${H}/standalone.c ${CONFIG_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_config.c ${CONFIG_SRCS} ${LIBS} ${UCL_A}

std_scan_parse: ${H}/fuzz_scan_parse.c ${H}/standalone.c ${SCAN_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_scan_parse.c ${SCAN_SRCS} ${LIBS}

std_hci_event: ${H}/fuzz_hci_event.c ${H}/standalone.c
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_hci_event.c ${HCIEV_SRCS}

std_smp_sc: ${H}/fuzz_smp_sc.c ${H}/standalone.c ${SMP_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_smp_sc.c ${SMP_SRCS} ${LIBS} -lpthread

std_hogp_report_map: ${H}/fuzz_hogp_report_map.c ${H}/standalone.c ${HOGP_SRCS}
	${CC} ${STDFLAGS} -o ${H}/${.TARGET:T} ${H}/standalone.c ${H}/fuzz_hogp_report_map.c ${HOGP_SRCS} ${LIBS} -lpthread

# Replay the seed corpus through the standalone drivers under ASan/UBSan.
# This is the CI-safe smoke test (no libFuzzer runtime required).
check: ${STANDALONE} corpus
	cd ${H} && ./std_att_server  corpus/att_server
	cd ${H} && ./std_adv_data    corpus/adv_data
	cd ${H} && ./std_ble_ipc     corpus/ble_ipc
	cd ${H} && ./std_adv_report  corpus/adv_report
	cd ${H} && ./std_gatt_client corpus/gatt_client
	cd ${H} && ./std_smp_responder corpus/smp_responder
	cd ${H} && ./std_ctl_ipc     corpus/ctl_ipc
	cd ${H} && ./std_l2cap_sig corpus/l2cap_sig
	cd ${H} && ./std_mesh_net corpus/mesh_net
	cd ${H} && ./std_mesh_access corpus/mesh_access
	cd ${H} && ./std_mesh_sim corpus/mesh_sim
	cd ${H} && ./std_l2cap_data corpus/l2cap_data
	cd ${H} && ./std_config corpus/config
	cd ${H} && ./std_scan_parse corpus/scan_parse
	cd ${H} && ./std_hci_event corpus/hci_event
	cd ${H} && ./std_smp_sc corpus/smp_sc
	cd ${H} && ./std_hogp_report_map corpus/hogp_report_map

corpus:
	sh ${H}/gen_corpus.sh ${H}/corpus

run-att: fuzz_att_server corpus
	cd ${H} && ./fuzz_att_server ${RUNOPTS} corpus/att_server
run-adv: fuzz_adv_data corpus
	cd ${H} && ./fuzz_adv_data ${RUNOPTS} corpus/adv_data
run-ble: fuzz_ble_ipc corpus
	cd ${H} && ./fuzz_ble_ipc ${RUNOPTS} corpus/ble_ipc
run-report: fuzz_adv_report corpus
	cd ${H} && ./fuzz_adv_report ${RUNOPTS} corpus/adv_report
run-gatt: fuzz_gatt_client corpus
	cd ${H} && ./fuzz_gatt_client ${RUNOPTS} corpus/gatt_client
run-smp: fuzz_smp_responder corpus
	cd ${H} && ./fuzz_smp_responder ${RUNOPTS} corpus/smp_responder
run-ctl: fuzz_ctl_ipc corpus
	cd ${H} && ./fuzz_ctl_ipc ${RUNOPTS} corpus/ctl_ipc
run-l2cap: fuzz_l2cap_sig corpus
	cd ${H} && ./fuzz_l2cap_sig ${RUNOPTS} corpus/l2cap_sig
run-mesh-net: fuzz_mesh_net corpus
	cd ${H} && ./fuzz_mesh_net ${RUNOPTS} corpus/mesh_net
run-mesh-access: fuzz_mesh_access corpus
	cd ${H} && ./fuzz_mesh_access ${RUNOPTS} corpus/mesh_access
run-mesh-sim: fuzz_mesh_sim corpus
	cd ${H} && ./fuzz_mesh_sim ${RUNOPTS} corpus/mesh_sim
run-l2cap-data: fuzz_l2cap_data corpus
	cd ${H} && ./fuzz_l2cap_data ${RUNOPTS} corpus/l2cap_data
run-config: fuzz_config corpus
	cd ${H} && ./fuzz_config ${RUNOPTS} corpus/config
run-scan: fuzz_scan_parse corpus
	cd ${H} && ./fuzz_scan_parse ${RUNOPTS} corpus/scan_parse
run-hci-event: fuzz_hci_event corpus
	cd ${H} && ./fuzz_hci_event ${RUNOPTS} corpus/hci_event
run-smp-sc: fuzz_smp_sc corpus
	cd ${H} && ./fuzz_smp_sc ${RUNOPTS} corpus/smp_sc
run-hogp: fuzz_hogp_report_map corpus
	cd ${H} && ./fuzz_hogp_report_map ${RUNOPTS} corpus/hogp_report_map

# CI smoke: build everything, fuzz each briefly against the seed corpus.
smoke: run-att run-adv run-ble run-report run-gatt run-smp run-ctl run-l2cap \
	run-mesh-net run-mesh-access run-mesh-sim run-l2cap-data run-config \
	run-scan run-hci-event run-smp-sc run-hogp

clean:
	cd ${H} && rm -f ${HARNESSES} ${STANDALONE} *.o
	cd ${H} && rm -rf crash-* leak-* oom-* timeout-*

.PHONY: all corpus run-att run-adv run-ble run-report run-gatt run-smp run-ctl \
	run-l2cap run-mesh-net run-mesh-access run-mesh-sim run-l2cap-data \
	run-config run-scan run-hci-event run-smp-sc run-hogp smoke check clean
