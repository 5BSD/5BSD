# SPDX-License-Identifier: BSD-2-Clause
"""Local source view with 5BSD BUILD metadata and unchanged imported sources."""
# These roots contain headers, not upstream Bazel packages. The source compiler
# selection belongs to the BUILD template; no Make evaluation occurs here.
_PATHS = ['sdk/lib/fidl_base/include', 'sdk/lib/fidl/cpp/include', 'sdk/lib/fidl/cpp/wire/include', 'sdk/lib/fit/include', 'sdk/lib/stdcompat/include', 'src/zircon/lib/zircon/include', 'zircon/system/public/zircon', 'sdk/lib/zircon-assert/zircon', 'sdk/lib/utf-utils/internal', 'LICENSE', 'PATENTS', 'sdk/lib/utf-utils/utf-utils.h', 'sdk/lib/fidl/cpp/wire/coding_errors.cc', 'sdk/lib/fidl/cpp/wire/incoming_message.cc', 'sdk/lib/fidl/cpp/wire/outgoing_message.cc', 'sdk/lib/fidl/cpp/wire/status.cc', 'sdk/lib/fidl/cpp/wire/transport.cc', 'sdk/lib/fidl/cpp/wire/wire_coding_traits.cc', 'sdk/lib/fidl/cpp/wire/wire_decoder.cc', 'sdk/lib/fidl/cpp/wire/wire_encoder.cc', 'sdk/lib/fidl/cpp/wire/transport_channel_host.cc', 'sdk/lib/fidl/cpp/natural_coding_traits.cc', 'sdk/lib/fidl/cpp/natural_decoder.cc', 'sdk/lib/fidl/cpp/natural_encoder.cc', 'sdk/lib/fidl_base/handle_close_many.cc', 'sdk/lib/fidl_base/wire_format_metadata.cc', 'sdk/lib/zircon-assert/zx_panic_libc.cc', 'sdk/lib/utf-utils/utf-utils.cc', 'sdk/lib/fidl_base/internal.c']
_COMPILER_PATHS = ['tools/fidl/fidlc/src', 'tools/fidl/fidlc/cmd/fidlc/main.cc', 'tools/fidl/fidlc/gen-json-schema.sh', 'tools/fidl/fidlc/schema.json', 'src/lib/cmdline/args_parser.cc', 'src/lib/cmdline/include', 'src/lib/fxl/strings', 'src/lib/fxl/third_party/icu', 'src/lib/fxl/macros.h', 'src/lib/fxl/fxl_export.h', 'src/lib/fxl/build_config.h']
_BINDING_TEMPLATES = ['tools/fidl/fidlgen_cpp/codegen/file_markers.tmpl', 'tools/fidl/fidlgen_cpp/codegen/file_common_types_header.tmpl', 'tools/fidl/fidlgen_cpp/codegen/file_common_types_source.tmpl', 'tools/fidl/fidlgen_cpp/codegen/file_natural_types_header.tmpl', 'tools/fidl/fidlgen_cpp/codegen/file_natural_types_source.tmpl', 'tools/fidl/fidlgen_cpp/codegen/natural_struct.tmpl', 'tools/fidl/fidlgen_cpp/codegen/natural_table.tmpl', 'tools/fidl/fidlgen_cpp/codegen/natural_union.tmpl', 'tools/fidl/fidlgen_cpp/codegen/fragment_enum.tmpl', 'tools/fidl/fidlgen_cpp/codegen/fragment_bits.tmpl', 'tools/fidl/fidlgen_cpp/codegen/fragment_const.tmpl', 'tools/fidl/fidlgen_cpp/codegen/fragment_alias.tmpl']
def _impl(ctx):
    root = ctx.path(ctx.attr.source_marker).dirname
    for relative in _PATHS + _COMPILER_PATHS + _BINDING_TEMPLATES:
        source = root.get_child(relative)
        if not source.exists:
            fail("missing imported Fuchsia source: " + relative)
        ctx.symlink(source, relative)
    ctx.symlink(ctx.path(ctx.attr.build_file), "BUILD.bazel")
fuchsia_runtime_repository = repository_rule(
    implementation = _impl,
    attrs = {
        "source_marker": attr.label(allow_single_file = True, mandatory = True),
        "build_file": attr.label(allow_single_file = True, mandatory = True),
    },
    local = True,
)
