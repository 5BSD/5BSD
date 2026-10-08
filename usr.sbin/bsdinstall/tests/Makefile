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

# The tests exercise the installed installer and fwget scripts.  The chapter
# list of the native book and the source-only fixtures below are installed
# with the tests so they do not depend on the build machine's source tree.
BOOKSRC=	${SRCTOP}/docs/book/src
BOOK_CHAPTERS!=	cd ${BOOKSRC} && find . -type f -name '*.md' | \
		    sed 's,^\./,,' | LC_ALL=C sort
${PACKAGE}FILES+=	book-chapters
CLEANFILES+=	book-chapters
book-chapters: ${BOOK_CHAPTERS:S,^,${BOOKSRC}/,}
	printf '%s\n' ${BOOK_CHAPTERS} > ${.TARGET}

SRCTREE_FILES=	release/tools/vmimage.subr \
		usr.sbin/bsdinstall/bsdinstall.8
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
