# SPDX-License-Identifier: BSD-2-Clause
#
# protoc, the Protocol Buffers compiler, with the C++ generator built in;
# C code for libupb comes from the protoc-gen-upb, protoc-gen-upb_minitable
# and protoc-gen-upbdefs plugins.  Installed in ${PROTOC_BINDIR}
# (lib/protobuf/protobuf.dirs.mk: /usr/libexec, off the default PATH).
# buildworld builds a bootstrap copy (static) in the bootstrap-tools stage,
# which lib/protobuf/protoc-gen.mk runs to generate code at build time.

.include <src.opts.mk>

PROTOBUF=	${SRCTOP}/contrib/protobuf
ABSL=		${SRCTOP}/contrib/abseil-cpp

.include "${SRCTOP}/lib/protobuf/protobuf.dirs.mk"

PACKAGE=	protobuf
PROG_CXX=	protoc
BINDIR=		${PROTOC_BINDIR}
SRCS=		main.cc
CXXSTD=		c++17
WARNS?=		1

CXXFLAGS+=	-I${PROTOBUF}/src -I${ABSL}

LIBADD=		protoc protobuf absl

.include <bsd.prog.mk>
