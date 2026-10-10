# SPDX-License-Identifier: BSD-2-Clause
.include <src.opts.mk>

PACKAGE= libfidl
LIB_CXX= fidl_bsd
SHLIB_MAJOR= 1
CXXSTD= c++20
WARNS?= 0

.include "runtime-includes.mk"
.PATH: ${FUCHSIA}/sdk/lib/fidl/cpp/wire ${FUCHSIA}/sdk/lib/fidl/cpp \
    ${FUCHSIA}/sdk/lib/fidl_base ${FUCHSIA}/sdk/lib/zircon-assert \
    ${FUCHSIA}/sdk/lib/utf-utils ${FUCHSIA}/sdk/lib/utf-utils/internal
# Only the codec closure reachable from native natural bindings and the
# runtime. Wire messaging, arenas and message formatting are not part of
# the native backend; tools/build/fuchsia/check-closure.py verifies this.
SRCS= runtime.cc runtime_c.cc coding_errors.cc incoming_message.cc \
    outgoing_message.cc status.cc transport.cc wire_coding_traits.cc \
    wire_decoder.cc wire_encoder.cc transport_channel_host.cc \
    natural_coding_traits.cc natural_decoder.cc natural_encoder.cc \
    handle_close_many.cc internal.c wire_format_metadata.cc zx_panic_libc.cc \
    utf-utils.cc scalar.cc

LIBADD= channel pthread cplusplus
MAN= libfidl_bsd.3

.include "headers.mk"

FILESGROUPS+= FIDL_PC
FIDL_PC= fidl.pc
FIDL_PCDIR= ${LIBDATADIR}/pkgconfig
FIDL_PCPACKAGE= libfidl-dev

FILESGROUPS+= FIDL_LICENSES
FIDL_LICENSES= ${FUCHSIA}/LICENSE ${FUCHSIA}/PATENTS
FIDL_LICENSESDIR= /usr/share/licenses/libfidl

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>

