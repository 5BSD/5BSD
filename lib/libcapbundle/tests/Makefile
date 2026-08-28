.include <src.opts.mk>

PACKAGE=	libcapbundle-tests
TESTSDIR=	${TESTSBASE}/lib/libcapbundle

# servicectl is a source helper rather than a generated ATF test program.
# Make it available when install is run from the object directory.
.PATH:	${.CURDIR}

ATF_TESTS_SH=	capbundle_format_test
ATF_TESTS_C+=	api_test
ATF_TESTS_C+=	storage_key_test
ATF_TESTS_C+=	manifest_activation_test
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.manifest_activation_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.manifest_activation_test+=	capbundle
LDFLAGS.manifest_activation_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
ATF_TESTS_C+=	management_test
CFLAGS.management_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.management_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.management_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.management_test+=	capbundle
LDFLAGS.management_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
CFLAGS.api_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.api_test+=	-I${SRCTOP}/lib/liboraclert
LIBADD.api_test+=	capbundle
LDFLAGS.api_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle
CFLAGS.storage_key_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.storage_key_test+=	-I${SRCTOP}/lib/liboraclert
LIBADD.storage_key_test+=	capbundle
LDFLAGS.storage_key_test+=	-Wl,-rpath,${OBJTOP}/lib/libcapbundle

SCRIPTS+=	servicectl
SCRIPTSDIR_servicectl=	${TESTSDIR}

.include <bsd.test.mk>
