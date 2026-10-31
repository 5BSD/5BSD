.include <bsd.init.mk>

PACKAGE=	bsdinstall-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/bsdinstall

ATF_TESTS_SH=	adduser_test \
		config_test \
		documentation_test \
		firmware_fetch_test \
		hostname_test \
		jail_test \
		ports_test \
		pkgbase_selection_test \
		repository_test \
		storage_requirement_test \
		tzfspool_test

# The tests exercise the installed installer and fwget scripts.  The source
# files they compare against are installed beneath ${TESTSDIR}/srctree,
# mirroring the source layout, so they do not depend on the build machine's
# source tree:
# - the native book (docs/book/src), which documentation_test compares
#   byte for byte with the installed /usr/share/doc/5bsd;
# - docs/book/tools/check-book.sh and the code the book's claims are checked
#   against: the system call table and the sys/sys headers the system call
#   appendix names plus the constant-family headers selected by check-book.sh.
#   The manual page and sysctl inventories of the tree are collected at build
#   time by check-book.sh itself.
BOOK_FILES!=	cd ${SRCTOP} && find docs/book/src -type f | LC_ALL=C sort
BOOK_HEADERS!=	sh ${SRCTOP}/docs/book/tools/check-book.sh -g headers ${SRCTOP}

SRCTREE_FILES=	docs/book/tools/check-book.sh \
		release/tools/vmimage.subr \
		sys/kern/syscalls.master \
		usr.sbin/bsdinstall/bsdinstall.8 \
		${BOOK_FILES} \
		${BOOK_HEADERS}
.include "${SRCTOP}/tests/srctree.mk"

CHECK_BOOK=	sh ${SRCTOP}/docs/book/tools/check-book.sh
${PACKAGE}FILES+=	book-man-pages book-sysctls
CLEANFILES+=	book-man-pages book-sysctls
book-man-pages: ${SRCTOP}/docs/book/tools/check-book.sh
	${CHECK_BOOK} -g man ${SRCTOP} > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
book-sysctls: ${SRCTOP}/docs/book/tools/check-book.sh
	${CHECK_BOOK} -g sysctl ${SRCTOP} > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

.include <bsd.test.mk>
