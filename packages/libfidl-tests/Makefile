# SPDX-License-Identifier: BSD-2-Clause
WORLDPACKAGE= libfidl-tests
SUBPACKAGES= dbg
PKG_SETS= tests
PKG_LICENSES= BSD2CLAUSE BSD3CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC= ${SRCTOP}/release/packages/ucl/libfidl-tests-all.ucl
# Test executables contain the runtime and GoogleTest statically.
PKG_DEPS.libfidl-tests= kyua set-base
.include <bsd.pkg.mk>
