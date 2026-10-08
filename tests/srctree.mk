#
# Install source-tree fixtures beneath ${TESTSDIR}/srctree so installed tests
# do not depend on the build machine's source tree.
#
# Set SRCTREE_FILES to paths relative to ${SRCTOP}, then include this file
# before <bsd.test.mk>.  Every directory from srctree/ down to each file's
# parent is declared through DIRS, so NO_ROOT installs record the whole
# hierarchy in METALOG (makefs and pkg need every parent directory).
#

.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

# srctree itself and every ancestor of the fixture directories.
_SRCTREE_DIRS!=	for d in ${SRCTREE_FILES:H:O:u}; do \
		    p=; for c in $$(echo $$d | tr / ' '); do \
			p=$${p:+$$p/}$$c; echo $$p; \
		    done; \
		done | sort -u
DIRS+=		SRCTREE_DIR_
SRCTREE_DIR_=	${TESTSDIR}/srctree
SRCTREE_DIR_PACKAGE=	${PACKAGE}
.for _d in ${_SRCTREE_DIRS}
DIRS+=		SRCTREE_DIR_${_d:S,/,_,g:S,.,_,g:S,-,_,g}
SRCTREE_DIR_${_d:S,/,_,g:S,.,_,g:S,-,_,g}=	${TESTSDIR}/srctree/${_d}
SRCTREE_DIR_${_d:S,/,_,g:S,.,_,g:S,-,_,g}PACKAGE=	${PACKAGE}
.endfor
