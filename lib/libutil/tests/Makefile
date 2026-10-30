TAP_TESTS_C+=	flopen_test
TAP_TESTS_C+=	grp_test
TAP_TESTS_C+=	humanize_number_test
TAP_TESTS_C+=	pidfile_test
TAP_TESTS_C+=	trimdomain_test
TAP_TESTS_C+=	trimdomain-nodomain_test
ATF_TESTS_C+=	cpuset_test
ATF_TESTS_C+=	expand_number_test
ATF_TESTS_C+=	forkpty_test
ATF_TESTS_C+=	getlocalbase_test
ATF_TESTS_C+=	login_time_error_test
.PATH: ${SRCTOP}/lib/libutil
SRCS.login_time_error_test= login_time_error_test.c login_ok.c login_times.c
LDFLAGS.login_time_error_test+= -Wl,--wrap=localtime -Wl,--wrap=localtime_r

ATF_TESTS_C+= login_cap_list_test
.PATH: ${SRCTOP}/lib/libc/gen
SRCS.login_cap_list_test= login_cap_list_test.c login_cap.c getcap.c
LDFLAGS.login_cap_list_test+= -Wl,--wrap=cgetstr -Wl,--wrap=free -Wl,--wrap=realloc -Wl,--wrap=reallocarray
CFLAGS.login_cap_list_test+= -I${SRCTOP}/lib/libutil -I${SRCTOP}/include -I${SRCTOP}/lib/libc/include

WARNS?=		2
LIBADD+=	util

.include <bsd.test.mk>
