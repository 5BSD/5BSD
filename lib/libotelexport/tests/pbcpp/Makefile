# SPDX-License-Identifier: BSD-2-Clause
#
# otlp_pb_oracle: the independent OTLP protobuf oracle for the
# libotelexport tests, built on the C++ protobuf runtime
# (libprivateprotobuf) and C++ code generated from opentelemetry-proto,
# so it shares nothing with the library's upb encoder.  A directory of its
# own keeps the C++ flags and libraries away from the C test programs.

.include <src.opts.mk>

PACKAGE=	libotelexport-tests
PROG_CXX=	otlp_pb_oracle
SRCS=		otlp_pb_oracle.cc
BINDIR=		${TESTSBASE}/lib/libotelexport
MAN=
CXXSTD=		c++17
WARNS?=		3

PROTO_SETS=	otlpcpp
PROTO_LANG.otlpcpp= cpp
PROTO_ROOT.otlpcpp= ${SRCTOP}/contrib/opentelemetry-proto
PROTO_FILES.otlpcpp= \
		opentelemetry/proto/common/v1/common.proto \
		opentelemetry/proto/resource/v1/resource.proto \
		opentelemetry/proto/logs/v1/logs.proto \
		opentelemetry/proto/metrics/v1/metrics.proto \
		opentelemetry/proto/trace/v1/trace.proto \
		opentelemetry/proto/collector/logs/v1/logs_service.proto \
		opentelemetry/proto/collector/metrics/v1/metrics_service.proto \
		opentelemetry/proto/collector/trace/v1/trace_service.proto
.include "${SRCTOP}/lib/protobuf/protoc-gen.mk"

# Generated code and the protobuf/abseil headers are not -W clean at
# WARNS 3.
CXXWARNFLAGS+=	-Wno-unused-parameter -Wno-sign-compare
LIBADD+=	absl

.include <bsd.prog.mk>
