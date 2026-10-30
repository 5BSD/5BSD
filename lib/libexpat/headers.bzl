# SPDX-License-Identifier: BSD-2-Clause
"""Declared BSD public-header transformations for Expat."""
def _headers(ctx):
    header = ctx.actions.declare_file("bsdxml.h")
    external = ctx.actions.declare_file("bsdxml_external.h")
    ctx.actions.expand_template(template = ctx.file.header, output = header,
        substitutions = {"XmlParse_INCLUDED": "_BSD_XML_H_", "COPYING": "src/contrib/expat/COPYING", "expat_external": "bsdxml_external"})
    ctx.actions.expand_template(template = ctx.file.external, output = external, substitutions = {})
    return [DefaultInfo(files = depset([header, external])),
            OutputGroupInfo(public_header = depset([header]), external_header = depset([external]))]
bsdxml_headers = rule(implementation = _headers, attrs = {
    "header": attr.label(allow_single_file = True, mandatory = True),
    "external": attr.label(allow_single_file = True, mandatory = True),
})
