# SPDX-License-Identifier: BSD-2-Clause

PROTOBUF=	${SRCTOP}/contrib/protobuf
ABSL=		${SRCTOP}/contrib/abseil-cpp

PACKAGE?=	protobuf
CXXSTD=		c++17
WARNS?=		1

CFLAGS+=	-I${PROTOBUF}/src \
		-I${PROTOBUF}/third_party/utf8_range
CXXFLAGS+=	-I${ABSL}

# Sources are named relative to the import root, installed headers and
# .proto files relative to src/.
.PATH:		${PROTOBUF} ${PROTOBUF}/src
