.if !target(__<bsd.suffixes-extra.mk>__)
__<bsd.suffixes-extra.mk>__:	.NOTMAIN

# prefer .s to a .c, remove stuff not used in the BSD libraries
# .pico used for PIC object files
# .nossppico used for NOSSP PIC object files
# .pieo used for PIE object files
.SUFFIXES: .out .o .bc .ll .pico .nossppico .pieo .S .asm .s .c .cc .cpp .cxx .C .f .y .l .ln

PICFLAG?=-fpic
PIEFLAG?=-fpie

# Share effective NOSSP policy with native graph exporters. Keep these recursive
# so per-source automatic-variable flags are expanded in the compiler context.
_NOSSP_CFLAGS= ${CFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//:C/^-fsanitize.*$//}
_NOSSP_SHARED_CFLAGS= ${SHARED_CFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//:C/^-fsanitize.*$//}
_NOSSP_CXXFLAGS= ${CXXFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//:C/^-fsanitize.*$//}
_NOSSP_SHARED_CXXFLAGS= ${SHARED_CXXFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//:C/^-fsanitize.*$//}
_NOSSP_ASFLAGS= ${CFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//}
_NOSSP_SHARED_ASFLAGS= ${SHARED_CFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//}

.c.pico:
	${CC} ${PICFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.c.nossppico:
	${CC} ${PICFLAG} -DPIC \
	    ${_NOSSP_SHARED_CFLAGS} \
	    ${_NOSSP_CFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.c.pieo:
	${CC} ${PIEFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.cc.pico .C.pico .cpp.pico .cxx.pico:
	${CXX} ${PICFLAG} -DPIC \
	    ${SHARED_CXXFLAGS} ${CXXFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}

.cc.nossppico .C.nossppico .cpp.nossppico .cxx.nossppico:
	${CXX} ${PICFLAG} -DPIC \
	    ${_NOSSP_SHARED_CXXFLAGS} \
	    ${_NOSSP_CXXFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}

.cc.pieo .C.pieo .cpp.pieo .cxx.pieo:
	${CXX} ${PIEFLAG} ${SHARED_CXXFLAGS} ${CXXFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}

.f.pico:
	${FC} ${PICFLAG} -DPIC ${FFLAGS} -o ${.TARGET} -c ${.IMPSRC}
	${CTFCONVERT_CMD}

.f.nossppico:
	${FC} ${PICFLAG} -DPIC \
	    ${FFLAGS:C/^-fstack-protector.*$//:C/^-fstack-clash-protection.*$//} \
	    -o ${.TARGET} -c ${.IMPSRC}
	${CTFCONVERT_CMD}

.s.pico .s.nossppico .s.pieo:
	${CC:N${CCACHE_BIN}} -x assembler ${ACFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.asm.pico:
	${CC:N${CCACHE_BIN}} -x assembler-with-cpp ${PICFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.asm.nossppico:
	${CC:N${CCACHE_BIN}} -x assembler-with-cpp ${PICFLAG} -DPIC \
	    ${_NOSSP_SHARED_ASFLAGS} \
	    ${_NOSSP_ASFLAGS} \
	    ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.asm.pieo:
	${CC:N${CCACHE_BIN}} -x assembler-with-cpp ${PIEFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.S.pico:
	${CC:N${CCACHE_BIN}} ${PICFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.S.nossppico:
	${CC:N${CCACHE_BIN}} ${PICFLAG} -DPIC \
	    ${_NOSSP_SHARED_ASFLAGS} \
	    ${_NOSSP_ASFLAGS} \
	    ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.S.pieo:
	${CC:N${CCACHE_BIN}} ${PIEFLAG} -DPIC \
	    ${SHARED_CFLAGS} ${CFLAGS} ${ACFLAGS} \
	    -c ${.IMPSRC} -o ${.TARGET}
	${CTFCONVERT_CMD}

.endif	# !target(__<bsd.suffixes-extra.mk>__)
