PACKAGE=	bsdtrace-provider-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTrace
.PATH:		${SRCTOP}/usr.sbin/BSDTrace

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_C+=	policy_test
ATF_TESTS_C+=	session_test
CFLAGS.policy_test+=	-I${SRCTOP}/usr.sbin/BSDTrace
SRCS.policy_test=	policy_test.c tracecmp_policy.c
CFLAGS.session_test+=	-DTRACECMP_TESTING
CFLAGS.session_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.session_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.session_test+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS.session_test+=	-I${SRCTOP}/usr.sbin/BSDTrace
CFLAGS.session_test+=	-I${SRCTOP}/sys
SRCS.session_test=	session_test.c tracecmp.c
LIBADD.session_test=	bsm channel service tracecmp
NO_SHARED.session_test=	yes
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	lib/libtracecmp/tracecmp.c \
		lib/libtracecmp/tracecmp_provider.d \
		usr.sbin/BSDTrace/bsdtrace_provider.d \
		usr.sbin/BSDTrace/tracecmp.c \
		usr.sbin/BSDTrace/tracecmp_policy.h
.include "${SRCTOP}/tests/srctree.mk"

ATF_TESTS_C+= shutdown_test
SRCS.shutdown_test= shutdown_test.c tracecmp_policy.c
CFLAGS.shutdown_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.shutdown_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.shutdown_test+= -I${SRCTOP}/sys
LIBADD.shutdown_test= bsm channel service tracecmp logcmp
NO_SHARED.shutdown_test= yes

ATF_TESTS_C+= lifecycle_test
SRCS.lifecycle_test= lifecycle_test.c tracecmp_policy.c
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.lifecycle_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.lifecycle_test+= -I${SRCTOP}/sys
LIBADD.lifecycle_test= bsm channel service tracecmp logcmp
NO_SHARED.lifecycle_test= yes

ATF_TESTS_C+= bootstrap_test
SRCS.bootstrap_test= bootstrap_test.c tracecmp_policy.c
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libservice
CFLAGS.bootstrap_test+= -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/liblogcmp
CFLAGS.bootstrap_test+= -I${SRCTOP}/sys
LIBADD.bootstrap_test= bsm channel service tracecmp logcmp
NO_SHARED.bootstrap_test= yes


ATF_TESTS_C+= quota_test
CFLAGS.quota_test+= -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libtracecmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys -ffunction-sections -fdata-sections
LDFLAGS.quota_test+= -Wl,--gc-sections
NO_SHARED.quota_test= yes

.include <bsd.test.mk>
