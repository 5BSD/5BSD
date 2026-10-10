# SPDX-License-Identifier: BSD-2-Clause
WORLDPACKAGE= libfidl
SUBPACKAGES= dbg dev man
# The optional host SDK is staged separately from world.
SUBPACKAGES.${FIDL_SDK:Uno}+= tools
PKG_LICENSES= BSD2CLAUSE BSD3CLAUSE
PKG_LICENSELOGIC= multi
PKG_DEPS.libfidl= libchannel clibs
PKG_DEPS.libfidl-dev= libchannel-dev clibs-dev
UCLSRC= ${SRCTOP}/release/packages/ucl/libfidl-all.ucl
.if ${FIDL_SDK:Uno} == "yes"
# Use the versions from the selected target ports build, not the build host.
.if empty(FIDL_PYTHON_VERSION) || empty(FIDL_RE2_VERSION)
.error FIDL_SDK requires FIDL_PYTHON_VERSION and FIDL_RE2_VERSION from the target ports packages
.endif
UCLSRC.libfidl-tools= ${SRCTOP}/release/packages/ucl/libfidl-tools.ucl
# fidlc embeds the FXL ICU UTF helper.
PKG_LICENSES+= ICU
PKG_UCLVARS+= FIDL_PYTHON_VERSION "${FIDL_PYTHON_VERSION}" \
    FIDL_RE2_VERSION "${FIDL_RE2_VERSION}"
.endif
.include <bsd.pkg.mk>
