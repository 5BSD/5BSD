.include <src.opts.mk>

PACKAGE=		tests

ATF_TESTS_SH+=		libcrypto_test

.if ${MK_OPENSSL_FIPS} != "no"
ATF_TESTS_SH+= fips_test
.endif

.include <bsd.test.mk>
