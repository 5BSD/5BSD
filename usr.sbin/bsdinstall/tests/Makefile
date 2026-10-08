.include <bsd.init.mk>

PACKAGE=	bsdinstall-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/bsdinstall

ATF_TESTS_SH=	config_test \
		documentation_test \
		firmware_fetch_test \
		hostname_test \
		jail_test \
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
#   appendix names (plus file.h, user.h and socket.h, as check-book.sh does).
#   The manual page and sysctl inventories of the tree are collected at build
#   time by check-book.sh itself.
BOOK_FILES!=	cd ${SRCTOP} && find docs/book/src -type f | LC_ALL=C sort
BOOK_HEADERS!=	cd ${SRCTOP} && { grep -ohE 'sys/sys/[A-Za-z0-9_]+\.h' \
		    docs/book/src/appendix/syscalls-and-sysctls.md; \
		    echo sys/sys/file.h; echo sys/sys/user.h; \
		    echo sys/sys/socket.h; } | LC_ALL=C sort -u

SRCTREE_FILES=	docs/book/tools/check-book.sh \
		release/tools/vmimage.subr \
		sys/kern/syscalls.master \
		usr.sbin/bsdinstall/bsdinstall.8 \
		${BOOK_FILES} \
		${BOOK_HEADERS}
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

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
