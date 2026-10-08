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
# source tree.  This includes the whole native book (docs/book/src), which
# documentation_test compares byte for byte with /usr/share/doc/5bsd.
BOOK_FILES!=	cd ${SRCTOP} && find docs/book/src -type f | LC_ALL=C sort

SRCTREE_FILES=	release/tools/vmimage.subr \
		usr.sbin/bsdinstall/bsdinstall.8 \
		${BOOK_FILES}
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
