.include <src.opts.mk>

PACKAGE=	servicectl-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/servicectl

.PATH: ${SRCTOP}/usr.sbin/authorityd/tests
.PATH: ${SRCTOP}/usr.sbin/serviced/tests
.PATH: ${SRCTOP}/usr.sbin/servicectl

ATF_TESTS_SH+=	servicectl_test
ATF_TESTS_C+=	transport_test

PROGS+=		capd_test_guardian
PROGS+=		capd_protocol_fixture
PROGS+=		servicectl_test_bin
BINDIR=		${TESTSDIR}

SRCS.servicectl_test_bin=	servicectl.c deps.c install.c verify.c
NO_SHARED.servicectl_test_bin=	yes
CFLAGS.servicectl_test_bin+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.servicectl_test_bin+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.servicectl_test_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.servicectl_test_bin+=	capbundle ucl elf

CFLAGS.transport_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.transport_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.transport_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.transport_test+=	-ffunction-sections -fdata-sections
LDFLAGS.transport_test+=	-Wl,--gc-sections
NO_SHARED.transport_test=	yes

CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libauthorityrt

${PACKAGE}FILES+=	capd_test_harness.sh

# ATF shell programs execute from the object directory before installation.
# Keep the shared authority harness beside the generated test program so object
# tree and installed test runs have identical inputs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: \
    ${SRCTOP}/usr.sbin/authorityd/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	capd_test_harness.sh
.endif

.include <bsd.test.mk>
