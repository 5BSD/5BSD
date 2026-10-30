PACKAGE= pam-tests
TESTSDIR= ${TESTSBASE}/lib/libpam
.PATH: ${SRCTOP}/contrib/openpam/lib/libpam
ATF_TESTS_C+= kerberos_config_pam_test
TEST_METADATA.kerberos_config_pam_test+= required_configs="module"
ATF_TESTS_C+= basic_dispatch_test
TEST_METADATA.basic_dispatch_test+= required_configs="permit_module deny_module"
ATF_TESTS_C+= module_resolution_test
SRCS.module_resolution_test= module_resolution_test.c openpam_dynamic.c openpam_load.c openpam_static.c openpam_check_owner_perms.c
ATF_TESTS_C+= policy_include_test
SRCS.policy_include_test= policy_include_test.c openpam_configure.c pam_start.c openpam_check_owner_perms.c
TEST_METADATA.policy_include_test+= timeout="15"
.PATH: ${SRCTOP}/lib/libpam/modules/pam_lastlog
ATF_TESTS_C+= lastlog_session_test
SRCS.lastlog_session_test= lastlog_session_test.c pam_lastlog.c openpam_static.c openpam_configure.c pam_start.c openpam_check_owner_perms.c
TEST_METADATA.lastlog_session_test+= required_user="root" timeout="30"
.PATH: ${SRCTOP}/lib/libutil ${SRCTOP}/lib/libc/gen
ATF_TESTS_C+= password_hash_pam_test
ATF_TESTS_C+= account_resolution_pam_test
LDFLAGS.account_resolution_pam_test+= -Wl,--export-dynamic
LDFLAGS.password_hash_pam_test+= -Wl,--export-dynamic
LIBADD.password_hash_pam_test= pam crypt
.PATH: ${SRCTOP}/lib/libpam/modules/pam_unix
LIBADD= pam
CFLAGS+= -I${SRCTOP}/contrib/openpam/include \
    -I${SRCTOP}/contrib/openpam/lib/libpam \
    -DOPENPAM_STATIC_MODULES -DLIB_MAJ=${SHLIB_MAJOR} -DHAVE_DLFUNC=1 -DHAVE_FDLOPEN=1 -DHAVE_STRLCAT=1 -DHAVE_STRLCPY=1
.include <bsd.test.mk>
