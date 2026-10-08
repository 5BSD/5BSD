PACKAGE=	libsysctlcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDSysctl

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_SH+=	observability_test
ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c bsdsysctl.c config.c
CFLAGS.provider_test+=	-DSYSCTLCMP_TESTING
CFLAGS.provider_test+=	-I${.CURDIR}/..
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	channel sysctlcmp service ucl
NO_SHARED.provider_test=	yes

ATF_TESTS_SH_SED_observability_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	cddl/usr.sbin/bsdinstruments/profiles/capability-services.d \
		usr.sbin/BSDSysctl/bsdsysctl.c \
		usr.sbin/BSDSysctl/bsdsysctl_provider.d
.include "${SRCTOP}/tests/srctree.mk"

.include <bsd.test.mk>
