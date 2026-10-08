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
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
