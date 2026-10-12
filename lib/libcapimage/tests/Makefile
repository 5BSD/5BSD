.include <src.opts.mk>
PACKAGE= libcapimage-tests
TESTSDIR= ${TESTSBASE}/lib/libcapimage
ATF_TESTS_C= capimage_test
CFLAGS+= -I${SRCTOP}/lib/libcapimage
LIBADD= capimage crypto

PLAIN_TESTS_C+= capimage_handle_client_test
.PATH: ${SRCTOP}/lib/libcapimage
SRCS.capimage_handle_client_test= capimage_handle_client_test.c capimage.c
LIBADD.capimage_handle_client_test= crypto
CFLAGS.capimage_handle_client_test+= -I${SRCTOP}/lib/libcapimage
LDFLAGS.capimage_handle_client_test+= -Wl,--wrap=mac_syscall

.include <bsd.test.mk>
