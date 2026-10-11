# SPDX-License-Identifier: BSD-2-Clause
#
# Fail the build when a checked-in FIDL binding tree no longer matches its
# schema.  FIDL_BINDINGS names generated library directories relative to
# SRCTOP (for example lib/libtimecmp/generated/fidl/bsd.time.v1).  Each holds
# a SOURCE.sha256 stamp, written by `make -C tools/build/fuchsia regen`, with
# one "SHA256 (path) = digest" line per input schema; this fragment checks
# those lines with base tools only (sh and sha256(1)) before anything is
# built.  It does not detect hand-edited generated files: `make -C
# tools/build/fuchsia check-bindings` regenerates and diffs for that.
#
# Include before <bsd.lib.mk>, <bsd.prog.mk> or <bsd.test.mk>.  When the
# bindings are generated into the object tree at build time, this fragment
# and the stamps go away together.

.if !empty(FIDL_BINDINGS) && !defined(_FIDL_BINDINGS_MK_)
_FIDL_BINDINGS_MK_=
FIDL_SHA256?=	sha256 -q
FIDL_REGEN_HINT=	run make -C tools/build/fuchsia regen and commit the result

beforebuild: fidl-bindings-check
fidl-bindings-check: .PHONY .NOTMAIN
.for _b in ${FIDL_BINDINGS}
	@stamp=${SRCTOP}/${_b}/SOURCE.sha256; \
	if ! grep -q '^SHA256 (' "$$stamp" 2>/dev/null; then \
		echo "${_b}/SOURCE.sha256 is missing; ${FIDL_REGEN_HINT}" >&2; \
		exit 1; \
	fi; \
	grep '^SHA256 (' "$$stamp" | while IFS= read -r line; do \
		file=$${line#SHA256 (}; file=$${file%%) = *}; \
		want=$${line##* = }; \
		have=$$(cd ${SRCTOP} && ${FIDL_SHA256} "$$file" 2>/dev/null) || \
		    have=; \
		if [ "$$have" != "$$want" ]; then \
			echo "$$file changed; ${FIDL_REGEN_HINT}" >&2; \
			exit 1; \
		fi; \
	done
.endfor
.endif
