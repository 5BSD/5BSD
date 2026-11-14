# SPDX-License-Identifier: BSD-2-Clause
# Record the source options resolved in the target world environment.  Keep
# this export driven by src.opts.mk; no parallel inventory of options lives here.

src-options-metadata: .PHONY .META .NOTMAIN
.if !defined(OBJTOP) || empty(OBJTOP) || !defined(SRC_OPT_LIST) || empty(SRC_OPT_LIST)
	@echo "src-options-metadata requires OBJTOP and SRC_OPT_LIST" >&2
	@false
.else
	@mkdir -p ${OBJTOP:Q}
	@printf '%s\n' ${SRC_OPT_LIST:O:u:@_srcopt_record@${_srcopt_record:Q}@} > ${OBJTOP:Q}/.src_opts.tmp
	@mv ${OBJTOP:Q}/.src_opts.tmp ${OBJTOP:Q}/.src_opts
.endif
