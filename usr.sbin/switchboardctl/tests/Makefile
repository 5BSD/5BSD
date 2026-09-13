.include <src.opts.mk>

CFLAGS+= -I${SRCTOP}/lib/libcapsulert

PACKAGE=	switchboardctl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/switchboardctl

.PATH: ${SRCTOP}/usr.sbin/capsule/tests
.PATH: ${SRCTOP}/usr.sbin/switchboard/tests
.PATH: ${SRCTOP}/usr.sbin/switchboardctl

ATF_TESTS_SH+=	switchboardctl_test
ATF_TESTS_SH+= lifecycle_ctl_test
ATF_TESTS_SH+= pkg_lifecycle_live_test
ATF_TESTS_SH+=	pkg_reclaim_test
ATF_TESTS_SH_SED_pkg_reclaim_test+=	-e 's,@SRCTOP@,${SRCTOP},g'

PROGS+=		capd_test_guardian
PROGS+=		capd_protocol_fixture
PROGS+=		switchboardctl_test_bin
PROGS+=		switchboardctl_success_bin
BINDIR=		${TESTSDIR}

SRCS.switchboardctl_test_bin=	switchboardctl.c deps.c install.c verify.c lifecycle.c
NO_SHARED.switchboardctl_test_bin=	yes
CFLAGS.switchboardctl_test_bin+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.switchboardctl_test_bin+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.switchboardctl_test_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.switchboardctl_test_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.switchboardctl_test_bin+=	capbundle service ucl elf md

SRCS.switchboardctl_success_bin=	switchboardctl_success_impl.c \
	deps_success_impl.c install_success_impl.c verify_success_impl.c lifecycle.c \
	fake_service.c
NO_SHARED.switchboardctl_success_bin=	yes
CFLAGS.switchboardctl_success_bin+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.switchboardctl_success_bin+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.switchboardctl_success_bin+=	-I${SRCTOP}/lib/libservice
CFLAGS.switchboardctl_success_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.switchboardctl_success_bin+=	capbundle ucl elf md

CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
LIBADD.capd_protocol_fixture+=	service channel capability

${PACKAGE}FILES+=	capd_test_harness.sh
${PACKAGE}FILES+=	pkg_reclaim_fake.sh

# ATF shell programs execute from the object directory before installation.
# Keep the shared authority harness beside the generated test program so object
# tree and installed test runs have identical inputs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: \
    ${SRCTOP}/usr.sbin/capsule/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	capd_test_harness.sh
.endif


# Keep the actual runtime hook source with the installed integration tests.
.PATH: ${SRCTOP}/packages/runtime
${PACKAGE}FILES+= runtime.ucl
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/runtime.ucl: ${SRCTOP}/packages/runtime/runtime.ucl
	${CP} ${.ALLSRC} ${.TARGET}
all: ${.OBJDIR}/runtime.ucl
CLEANFILES+= runtime.ucl
.endif

.include <bsd.test.mk>
