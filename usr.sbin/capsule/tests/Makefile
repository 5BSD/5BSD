PACKAGE=	capsule-tests

.PATH:	${SRCTOP}/usr.sbin/capsule/tests

ATF_TESTS_SH+=	capsule_config_cli_test
ATF_TESTS_SH+=	capsule_daemon_test
ATF_TESTS_SH+=	capsule_init_test
ATF_TESTS_SH+=	capsule_daemon_lifecycle_test
ATF_TESTS_SH+=	capsule_bootstrap_test
ATF_TESTS_SH+=	capd_test_guardian_test
ATF_TESTS_SH+=	capsule_boot_test

# A test-local Capsule claims /dev/mac_capability through
# mac_capability_isolation, which hides the node from every other process,
# and only one stack can hold the claim.  Programs that start such a stack or
# open the device directly must not run concurrently with each other or with
# other device users.
TEST_METADATA.capsule_init_test+=	is_exclusive="true"
TEST_METADATA.capsule_daemon_lifecycle_test+=	is_exclusive="true"
TEST_METADATA.capsule_bootstrap_test+=	is_exclusive="true"

PROGS+=		capd_test_guardian
PROGS+=		capd_bootstrap_fixture
BINDIR=		${TESTSDIR}

CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/sys
CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/lib/libcapsulert

${PACKAGE}FILES+=	capd_test_harness.sh loader-defaults.conf \
                run_capsule_vm_boot_test.sh \
			run_capsule_vm_image_test.sh
${PACKAGE}FILESMODE_run_capsule_vm_boot_test.sh=	0555
${PACKAGE}FILESMODE_run_capsule_vm_image_test.sh=	0555

# Keep the shared harness beside generated ATF programs for object-tree runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: ${.CURDIR}/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/loader-defaults.conf: ${SRCTOP}/stand/defaults/loader.conf
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/run_capsule_vm_boot_test.sh: ${.CURDIR}/run_capsule_vm_boot_test.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/run_capsule_vm_image_test.sh: ${.CURDIR}/run_capsule_vm_image_test.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh ${.OBJDIR}/loader-defaults.conf \
	${.OBJDIR}/run_capsule_vm_boot_test.sh \
	${.OBJDIR}/run_capsule_vm_image_test.sh
CLEANFILES+=	capd_test_harness.sh loader-defaults.conf \
		run_capsule_vm_boot_test.sh run_capsule_vm_image_test.sh
.endif

ATF_TESTS_C+=	req_validate_test
CFLAGS.req_validate_test+=	-I${SRCTOP}/sys
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.req_validate_test+=	-I${SRCTOP}/usr.sbin/capsule

# Capsule PID-1 unit tests exercise the pure decision/hygiene helpers factored
# out of capsule.c (capsule_ambient.h, capsule_lifecycle.h, capsule_plane.h) —
# header-only, no PID-1 state machine or daemon objects linked.
ATF_TESTS_C+=	capsule_ambient_test
CFLAGS.capsule_ambient_test+=	-I${SRCTOP}/usr.sbin/capsule

ATF_TESTS_C+=	capsule_lifecycle_test
CFLAGS.capsule_lifecycle_test+=	-I${SRCTOP}/usr.sbin/capsule
CFLAGS.capsule_lifecycle_test+=	-I${SRCTOP}/lib/libcapsulert

ATF_TESTS_C+=	capsule_plane_test
CFLAGS.capsule_plane_test+=	-I${SRCTOP}/usr.sbin/capsule


ATF_TESTS_C+= system_release_test
CFLAGS.system_release_test+= -I${SRCTOP}/sys -I${SRCTOP}/usr.sbin/capsule
CFLAGS.system_release_test+= -I${SRCTOP}/lib/libcapsulert -I${SRCTOP}/lib/libcapbundle
CFLAGS.system_release_test+= -ffunction-sections -fdata-sections
LDFLAGS.system_release_test+= -Wl,--gc-sections


ATF_TESTS_C+= config_test
.PATH: ${SRCTOP}/usr.sbin/capsule ${SRCTOP}/usr.sbin/capsule/examples
SRCS.config_test= config_test.c config.c protected_crypto.c
CFLAGS.config_test+= -I${SRCTOP}/sys -I${SRCTOP}/usr.sbin/capsule
CFLAGS.config_test+= -I${SRCTOP}/lib/libcapsulert -I${SRCTOP}/lib/libcapbundle
CFLAGS.config_test+= -I${SRCTOP}/contrib/libucl/include
LIBADD.config_test= capsulert ucl md
NO_SHARED.config_test= yes
LDFLAGS.config_test+= -Wl,--wrap=malloc -Wl,--wrap=calloc
${PACKAGE}FILES+= capsule-daemon.conf

.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capsule-daemon.conf: ${SRCTOP}/usr.sbin/capsule/capsule-daemon.conf
	${CP} ${.ALLSRC} ${.TARGET}
all: ${.OBJDIR}/capsule-daemon.conf
CLEANFILES+= capsule-daemon.conf
.endif

.for profile in desktop server embedded broker
${PACKAGE}FILES+= ${profile}.conf
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/${profile}.conf: ${SRCTOP}/usr.sbin/capsule/examples/${profile}.conf
	${CP} ${.ALLSRC} ${.TARGET}
all: ${.OBJDIR}/${profile}.conf
CLEANFILES+= ${profile}.conf
.endif
.endfor

ATF_TESTS_C+= storage_test
SRCS.storage_test= storage_test.c protected_storage.c config.c
NO_SHARED.storage_test= yes
LIBADD.storage_test= md trustedzfs zfs zutil nvpair spl pthread capsulert ucl
CFLAGS+= -I${SRCTOP}/usr.sbin/capsule -I${SRCTOP}/lib/libtrustedzfs \
	-I${SRCTOP}/lib/libcapsulert -I${SRCTOP}/lib/libcapbundle \
	-I${SRCTOP}/contrib/libucl/include -I${SRCTOP}/tests/sys/zfshandle
CFLAGS.storage_test.c+= -I${SRCTOP}/sys
CFLAGS.config.c+= -I${SRCTOP}/sys
CFLAGS.protected_storage.c+= -DIN_BASE -DNEED_SOLARIS_BOOLEAN \
	-I${SRCTOP}/sys/contrib/openzfs/include \
	-I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include \
	-I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd \
	-I${SRCTOP}/sys -I${SRCTOP}/cddl/compat/opensolaris/include \
	-include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h \
	-include ${SRCTOP}/sys/modules/zfs/zfs_config.h

ATF_TESTS_C+= import_test
SRCS.import_test= import_test.c protected_storage.c config.c
NO_SHARED.import_test= yes
LIBADD.import_test= ${LIBADD.storage_test}
CFLAGS.import_test.c+= ${CFLAGS.protected_storage.c}

.include <bsd.test.mk>
