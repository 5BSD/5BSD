PACKAGE=	bsdnetwork-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNetwork

.PATH: ${.CURDIR}/..

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	resolver_test
SRCS.resolver_test=	resolver_test.c
LIBADD.resolver_test=	service

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c policy.c
CFLAGS.config_test+=	-I${SRCTOP}/sys
LIBADD.config_test=	ucl

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c networkcmp.c config.c policy.c resolver.c
CFLAGS.provider_test+=	-DNETWORKCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel networkcmp pthread service ucl
NO_SHARED.provider_test=	yes

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	usr.sbin/BSDFilesystem/bsdfilesystem.ucl \
		usr.sbin/BSDNetwork/bsdnetwork_provider.d \
		usr.sbin/BSDNetwork/networkcmp.c \
		usr.sbin/BSDNetwork/resolver.c
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= state_test
CFLAGS.state_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libnotify
CFLAGS.state_test+= -I${SRCTOP}/lib/libsysctlcmp -I${SRCTOP}/sys
LIBADD.state_test+= networkcmp notify channel service pthread
NO_SHARED.state_test= yes

ATF_TESTS_C+= state_plane_test
CFLAGS.state_plane_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libnotify
CFLAGS.state_plane_test+= -I${SRCTOP}/lib/libsysctlcmp -I${SRCTOP}/sys
LIBADD.state_plane_test+= networkcmp notify channel service pthread
NO_SHARED.state_plane_test= yes

.include <bsd.test.mk>
