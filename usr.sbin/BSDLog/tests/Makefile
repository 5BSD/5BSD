PACKAGE=	bsdlog-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDLog
NO_SHARED=

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c session.c
LIBADD.session_test+=	logcmp shmring

ATF_TESTS_C+=	store_test
SRCS.store_test=	store_test.c store.c
LIBADD.store_test+=	logcmp md
LDFLAGS.store_test+= -Wl,--wrap=writev -Wl,--wrap=ftruncate -Wl,--wrap=lseek

ATF_TESTS_C+=	store_limit_test
SRCS.store_limit_test=	store_limit_test.c store_limit_impl.c
CFLAGS.store_limit_test+=	-DSTORE_RECLAIM_MAX=4 -DSTORE_OWNER_MAP_MAX=2
LIBADD.store_limit_test+=	logcmp md

ATF_TESTS_C+=	storage_test
SRCS.storage_test=	storage_test.c storage.c store.c
LIBADD.storage_test+=	logcmp md service shmring capsulert capreclaim
CFLAGS.storage_test+= -I${SRCTOP}/lib/libcapsulert

ATF_TESTS_C+= storage_barrier_test
SRCS.storage_barrier_test= storage_barrier_test.c store.c
LIBADD.storage_barrier_test+= logcmp md service shmring capsulert capreclaim
CFLAGS.storage_barrier_test+= -I${SRCTOP}/lib/libcapsulert
LDFLAGS.storage_barrier_test+= -Wl,--wrap=shmring_read_record \
    -Wl,--wrap=shmring_consumer_arm -Wl,--wrap=logcmp_store_append \
    -Wl,--wrap=logcmp_store_flush

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c logcmp.c session.c
CFLAGS.provider_test+=	-DLOGCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	channel logcmp service shmring
NO_SHARED.provider_test=	yes
.PATH:	${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	lib/liblogcmp/logcmp.c \
		lib/liblogcmp/logcmp_provider.d \
		usr.sbin/BSDLog/BSDLog.8 \
		usr.sbin/BSDLog/bsdlog_provider.d \
		usr.sbin/BSDLog/capbundle/bsdlog.conf \
		usr.sbin/BSDLog/logcmp.c
.include "${SRCTOP}/tests/srctree.mk"

.include <bsd.test.mk>
