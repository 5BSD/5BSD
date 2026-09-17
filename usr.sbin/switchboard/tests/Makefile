.include <src.opts.mk>

PACKAGE=	switchboard-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/switchboard

.PATH: ${SRCTOP}/usr.sbin/capsule/tests
.PATH: ${SRCTOP}/lib/libservice/tests
.PATH: ${SRCTOP}/usr.sbin/switchboard

ATF_TESTS_SH+=	switchboard_naming_test
ATF_TESTS_SH+=	switchboard_svc_test
ATF_TESTS_SH+=	switchboard_integration_test
ATF_TESTS_SH+=	switchboard_dynamic_claims_test
ATF_TESTS_SH+=	bundle_integration_test
ATF_TESTS_SH+=	helper_integration_test
ATF_TESTS_SH+=	service_reachability_test
ATF_TESTS_SH+=	shipped_manifest_policy_test
ATF_TESTS_SH_SED_bundle_integration_test+= \
	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_helper_integration_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_shipped_manifest_policy_test+= \
	-e 's,@SRCTOP@,${SRCTOP},g'
# IPC anointment observability contract: probes, the shipped DTrace script
# and the bsdinstruments profile clauses (source-tree greps; dtrace -e parse).
ATF_TESTS_SH+=	anoint_observability_test
ATF_TESTS_SH_SED_anoint_observability_test+= \
	-e 's,@SRCTOP@,${SRCTOP},g' \
	-e 's,@OBJTOP@,${OBJTOP},g' \
	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

${PACKAGE}FILES+=	test_helpers.sh
${PACKAGE}FILES+=	capd_test_harness.sh
${PACKAGE}FILES+=	CapabilityKyuafile
${PACKAGE}FILES+=	run_capsule_switchboard_capability_tests.sh
${PACKAGE}FILESMODE_run_capsule_switchboard_capability_tests.sh=	0555

# ATF shell programs execute from the object directory before installation.
# Keep their shared harnesses beside them so raw object-tree test runs are as
# reliable as installed /usr/tests runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/test_helpers.sh: ${.CURDIR}/test_helpers.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/capd_test_harness.sh: \
    ${SRCTOP}/usr.sbin/capsule/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/test_helpers.sh ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	test_helpers.sh capd_test_harness.sh
.endif

PROGS+=		capd_test_guardian
PROGS+=		capd_service_fixture
PROGS+=		capd_protocol_fixture
PROGS+=		service_probe
ATF_TESTS_C+=	activation_test
ATF_TESTS_C+=	domain_test
ATF_TESTS_C+=	anoint_test
ATF_TESTS_C+=	on_demand_test
ATF_TESTS_C+=	fd_budget_test
ATF_TESTS_C+=	launch_limits_test
ATF_TESTS_C+=	manifest_compare_test
ATF_TESTS_C+=	management_enforce_test
ATF_TESTS_C+=	bundle_selection_test
ATF_TESTS_C+=	rc_ingest_test
# registry_watch_test drives the install-root watch through a real kqueue with
# the supervisor stubbed (container model: pkg install/remove loads/unloads).
ATF_TESTS_C+=	registry_watch_test
SRCS.registry_watch_test=	registry_watch_test.c registry_watch.c
ATF_TESTS_C+=	rc_adopt_test
ATF_TESTS_C+=	activation_calendar_test
ATF_TESTS_C+=	ambient_hygiene_test
ATF_TESTS_C+=	sctl_gate_test
ATF_TESTS_C+=	register_lookup_gate_test
BINDIR=		${TESTSDIR}

# rc_ingest.c is compiled into BOTH rc_ingest_test and rc_adopt_test.  A source
# shared by more than one test program is built once with the common CFLAGS —
# the per-program CFLAGS.<prog> do not reach a shared object — so the include
# paths rc_ingest.c needs (switchboard_manifest.h in libcapbundle, which pulls in
# capsulert.h from libcapsulert) must be global.
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
# management.c is now shared by management_enforce_test and sctl_gate_test; a
# source in more than one test program builds once with the common CFLAGS (the
# per-program CFLAGS.<prog> do not reach a shared object), so the include paths
# management.c needs (switchboard.h + management.h in the switchboard dir, and the
# kernel headers switchboard.h pulls in) must be global.
CFLAGS+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS+=	-I${SRCTOP}/sys

# rc_ingest_test compiles the parser directly (pure logic, no daemon deps).
# rc_ingest.c comes from the switchboard source dir via .PATH above; referencing
# it by basename keeps its object in the objdir (an absolute ${SRCTOP} path in
# SRCS would place the object inside $SRCTOP, which objdir builds forbid).
SRCS.rc_ingest_test=	rc_ingest_test.c rc_ingest.c
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/lib/libcapbundle

# rc_adopt_test compiles the adoption selection + unit-building logic directly
# (pure logic, no daemon event loop).  --gc-sections drops rc_adopt_register(),
# the only function that touches sd.services/svc_by_label, so the unit needs no
# daemon objects to link.  rc_adopt.c and rc_ingest.c come from the switchboard
# source dir via the .PATH above; referencing them by basename keeps their
# objects in the objdir.
SRCS.rc_adopt_test=	rc_adopt_test.c rc_adopt.c rc_ingest.c
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/sys
CFLAGS.rc_adopt_test+=	-ffunction-sections -fdata-sections
LDFLAGS.rc_adopt_test+=	-Wl,--gc-sections

# activation_calendar_test compiles the pure calendar math directly (no daemon
# event loop or kqueue).  activation_calendar.c comes from the switchboard source
# dir via the .PATH above; referencing it by basename keeps its object in the
# objdir.
SRCS.activation_calendar_test=	activation_calendar_test.c activation_calendar.c
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/lib/libcapsulert

# ambient_hygiene_test exercises the pure launch-hygiene predicate in
# ambient_hygiene.h (SEC-1 regression) — header-only, no daemon objects.
SRCS.ambient_hygiene_test=	ambient_hygiene_test.c
CFLAGS.ambient_hygiene_test+=	-I${SRCTOP}/usr.sbin/switchboard

# sctl_gate_test exercises the pure control-plane authorization predicates
# (sctl_gate.h) plus the management-class gate (management.c, shared with
# management_enforce_test — its include paths are global, above).  No daemon
# event loop.  management.c comes from the switchboard source dir via .PATH.
SRCS.sctl_gate_test=	sctl_gate_test.c management.c
CFLAGS.sctl_gate_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.sctl_gate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.sctl_gate_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.sctl_gate_test+=	-I${SRCTOP}/sys

# opcode-band invariants from switchboard_svc_proto.h.  No daemon objects.

# register_lookup_gate_test is header-only: the pure adoption/scope predicate in
# register_lookup_gate.h (which pulls switchboard.h for enum svc_domain_kind and
# the wire struct from switchboard_svc_proto.h).  No daemon objects, no live plane.
SRCS.register_lookup_gate_test=	register_lookup_gate_test.c
CFLAGS.register_lookup_gate_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.register_lookup_gate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.register_lookup_gate_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.register_lookup_gate_test+=	-I${SRCTOP}/sys


CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
LIBADD.capd_protocol_fixture+=	service channel capability

LIBADD.capd_service_fixture+=	capability channel service pthread
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys

# service_probe: the ambient-reachability helper for service_reachability_test.
LIBADD.service_probe+=		service channel pthread
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libservice
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libchannel
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libcapsulert
CFLAGS.service_probe+=		-I${SRCTOP}/sys


# activation_test.c #includes ../activation.c inline; that now calls into the
# calendar math, so activation_calendar.c is linked alongside (by basename via
# .PATH).  --gc-sections drops the unreferenced daemon-state functions.
SRCS.activation_test=	activation_test.c activation_calendar.c
CFLAGS.activation_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libcapability
CFLAGS.activation_test+=	-I${SRCTOP}/sys
CFLAGS.activation_test+=	-ffunction-sections -fdata-sections
LDFLAGS.activation_test+=	-Wl,--gc-sections
LIBADD.activation_test+=	capbundle
NO_SHARED.activation_test=	yes
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libcapsulert
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libservice
CFLAGS.domain_test+=		-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.domain_test+=		-I${SRCTOP}/sys
CFLAGS.domain_test+=		-ffunction-sections -fdata-sections
LDFLAGS.domain_test+=		-Wl,--gc-sections
# domain.c/naming.c reach libchannel; the minted-channel case drives the
# switchboard side from a helper thread and plays the client with libservice.
LIBADD.domain_test+=		channel service pthread
# anoint_test.c #includes ../anoint.c, ../domain.c and ../naming.c inline (the
# same trick as domain_test) to drive the IPC-anointment match, the session-set
# plumbing and the grant identity without a live switchboard.  USE_BSM_AUDIT is
# defined so the refusal path calls switchboard_audit(), which the test stubs
# to capture the record; no libbsm is linked.
CFLAGS.anoint_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.anoint_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.anoint_test+=		-I${SRCTOP}/lib/libcapsulert
CFLAGS.anoint_test+=		-I${SRCTOP}/lib/libservice
CFLAGS.anoint_test+=		-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.anoint_test+=		-I${SRCTOP}/sys
CFLAGS.anoint_test+=		-DUSE_BSM_AUDIT
CFLAGS.anoint_test+=		-ffunction-sections -fdata-sections
LDFLAGS.anoint_test+=		-Wl,--gc-sections
LIBADD.anoint_test+=		channel service pthread
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libcapsulert
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libservice
CFLAGS.on_demand_test+=		-I${SRCTOP}/sys
CFLAGS.on_demand_test+=		-ffunction-sections -fdata-sections
LDFLAGS.on_demand_test+=	-Wl,--gc-sections
# The idle-shutdown cases pull supervisor.c + svc_proto.c into the unit, which
# reach libchannel and (in the mac_capability-gated case) a provider thread.
LIBADD.on_demand_test+=		channel pthread
CFLAGS.fd_budget_test+=	-I${SRCTOP}/sys
CFLAGS.launch_limits_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.launch_limits_test+=	-I${SRCTOP}/sys
SRCS.manifest_compare_test=	manifest_compare_test.c manifest_compare.c
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/sys
# management_enforce_test compiles management.c directly (pure class logic, no
# daemon event loop).  management.c comes from the switchboard source dir via the
# .PATH above; referencing it by basename keeps its object in the objdir.
SRCS.management_enforce_test=	management_enforce_test.c management.c
CFLAGS.management_enforce_test+=	-I${SRCTOP}/usr.sbin/switchboard
CFLAGS.management_enforce_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.management_enforce_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.management_enforce_test+=	-I${SRCTOP}/sys
SRCS.bundle_selection_test=	bundle_selection_test.c bundle_selection.c
CFLAGS.bundle_selection_test+=	-I${SRCTOP}/usr.sbin/switchboard

LIBADD.capd_service_fixture+= capsulert


.include <bsd.test.mk>
