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
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
