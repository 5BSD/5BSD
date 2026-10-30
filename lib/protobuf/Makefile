# SPDX-License-Identifier: BSD-2-Clause
#
# Protocol Buffers (contrib/protobuf): the C++ runtime as private shared
# libraries (libprivateprotobuf, libprivateprotobuf-lite), the protoc
# compiler library (internal, linked into protoc) and upb, the C runtime
# used by base C consumers (internal, static as upstream requires).

SUBDIR=		libprotobuf-lite \
		libprotobuf \
		libprotoc \
		libupb
SUBDIR_DEPEND_libprotoc= libprotobuf
SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
