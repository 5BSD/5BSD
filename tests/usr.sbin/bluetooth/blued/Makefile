PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/usr.sbin/bluetooth/blued
BINDIR=		${TESTSDIR}

ATF_TESTS_C+=	smp_crypto_test
ATF_TESTS_C+=	att_test
ATF_TESTS_C+=	conn_test
ATF_TESTS_C+=	ctl_test
ATF_TESTS_C+=	peripheral_test
ATF_TESTS_C+=	config_test
ATF_TESTS_C+=	hci_hw_test
ATF_TESTS_C+=	smp_pairing_test
ATF_TESTS_C+=	adv_data_test
ATF_TESTS_C+=	gatt_test
ATF_TESTS_C+=	hci_log_test
ATF_TESTS_C+=	hci_offline_test
ATF_TESTS_C+=	hogp_test
ATF_TESTS_C+=	libble_test

SRCS.smp_crypto_test=	smp_crypto_test.c
SRCS.att_test=		att_test.c
SRCS.gatt_test=		gatt_test.c
SRCS.conn_test=		conn_test.c
SRCS.ctl_test=		ctl_test.c
SRCS.peripheral_test=	peripheral_test.c
SRCS.config_test=	config_test.c
SRCS.hci_hw_test=	hci_hw_test.c
SRCS.smp_pairing_test=	smp_pairing_test.c
SRCS.hci_log_test=	hci_log_test.c
SRCS.adv_data_test=	adv_data_test.c

CFLAGS+=	-I${SRCTOP}/usr.sbin/bluetooth/blued
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.libble_test+=	-I${SRCTOP}/lib/libble
CFLAGS.adv_data_test+=	-I${SRCTOP}/usr.sbin/bluetooth/hccontrol
CFLAGS.adv_data.c+=	-Wno-ignored-qualifiers -Wno-sign-compare

.PATH:		${SRCTOP}/usr.sbin/bluetooth/blued
.PATH:		${SRCTOP}/usr.sbin/bluetooth/hccontrol
.PATH:		${SRCTOP}/lib/libble
SRCS.smp_crypto_test+=	smp.c
SRCS.smp_pairing_test+=	smp.c
SRCS.att_test+=		att.c att_server.c
SRCS.peripheral_test+=	att.c att_server.c
SRCS.conn_test+=	conn.c
SRCS.ctl_test+=		ctl.c conn.c att.c att_server.c gatt.c config.c
SRCS.config_test+=	config.c
SRCS.hci_hw_test+=	hci_util.c hci_log.c
SRCS.hci_log_test+=	hci_log.c
SRCS.gatt_test+=	att.c att_server.c gatt.c
SRCS.adv_data_test+=	adv_data.c
SRCS.hci_offline_test=	hci_offline_test.c hci_util.c hci_log.c
SRCS.hogp_test=		hogp_test.c
LIBADD.hogp_test=
SRCS.libble_test=	libble_test.c ble.c

LIBADD+=	bluetooth crypto
LIBADD.ctl_test+=	pthread ucl
LIBADD.config_test+=	ucl

.include <bsd.test.mk>
