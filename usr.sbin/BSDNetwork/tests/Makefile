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
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
