# SPDX-License-Identifier: BSD-2-Clause
# Shared source-tree include paths for the runtime and native test targets.
FUCHSIA= ${SRCTOP}/contrib/fuchsia
CFLAGS+= -I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel \
    -I${SRCTOP}/sys -I${FUCHSIA}/sdk \
    -I${FUCHSIA}/src/zircon/lib/zircon/include \
    -I${FUCHSIA}/zircon/system/public
.for part in fidl_base fidl/cpp fidl/cpp/wire fit stdcompat
CFLAGS+= -I${FUCHSIA}/sdk/lib/${part}/include
.endfor

# zircon-assert exports its zircon/ headers directly from the package root.
CFLAGS+= -I${FUCHSIA}/sdk/lib/zircon-assert
