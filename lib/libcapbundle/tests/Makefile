.include <src.opts.mk>

PACKAGE=	libcapbundle-tests
TESTSDIR=	${TESTSBASE}/lib/libcapbundle

# switchboardctl is a source helper rather than a generated ATF test program.
# Make it available when install is run from the object directory.
.PATH:	${.CURDIR}

ATF_TESTS_SH=	capbundle_format_test
ATF_TESTS_C+=	api_test
ATF_TESTS_C+=	manifest_activation_test
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.manifest_activation_test+=	capbundle
LDFLAGS.manifest_activation_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
ATF_TESTS_C+=	management_test
CFLAGS.management_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.management_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.management_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.management_test+=	capbundle
LDFLAGS.management_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle

ATF_TESTS_C+=	principal_policy_test
CFLAGS.principal_policy_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.principal_policy_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.principal_policy_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.principal_policy_test+=	capbundle
LDFLAGS.principal_policy_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
ATF_TESTS_C+=	manifest_policy_test
CFLAGS.manifest_policy_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_policy_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.manifest_policy_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.manifest_policy_test+=	capbundle
LDFLAGS.manifest_policy_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
ATF_TESTS_C+=	sysctl_isolate_test
CFLAGS.sysctl_isolate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.sysctl_isolate_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.sysctl_isolate_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.sysctl_isolate_test+=	-I${SRCTOP}/sys
LIBADD.sysctl_isolate_test+=	capbundle
LDFLAGS.sysctl_isolate_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
CFLAGS.api_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.api_test+=	-I${SRCTOP}/lib/libcapsulert
LIBADD.api_test+=	capbundle
LDFLAGS.api_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle

SCRIPTS+=	switchboardctl
SCRIPTSDIR_switchboardctl=	${TESTSDIR}

.if ${.OBJDIR} !=	${.CURDIR}
${.OBJDIR}/switchboardctl: ${.CURDIR}/switchboardctl
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/switchboardctl
CLEANFILES+=	switchboardctl
.endif

.include <bsd.test.mk>
