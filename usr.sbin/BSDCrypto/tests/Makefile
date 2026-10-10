PACKAGE=	bsdcrypto-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDCrypto

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
.PATH:		${.CURDIR}/..

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c bsdcrypto.c policy.c
CFLAGS.provider_test+=	-DBSDCRYPTO_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptocmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libcryptodesc
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel cryptocmp cryptodesc service
NO_SHARED.provider_test=	yes

ATF_TESTS_SH+=	bundle_test

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	usr.sbin/BSDCrypto/Makefile \
		usr.sbin/BSDCrypto/bsdcrypto.c
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c policy.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/liblogcmp
LIBADD.lifecycle_test= auditcmp channel cryptocmp cryptodesc service logcmp capreclaim
NO_SHARED.lifecycle_test= yes


ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -I${SRCTOP}/lib/libcapreclaim -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

.include <bsd.test.mk>
