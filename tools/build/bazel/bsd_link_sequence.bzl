# SPDX-License-Identifier: BSD-2-Clause
"""Explicit static dependency precedence for consumers with overlapping symbols.

Ordinary C++ dependency DAG traversal does not promise BUILD-list link order.
This boundary visits each requested dependency's complete linker-input sequence
in declaration order, retaining the first occurrence of each input. It encodes
that sequence as a chain, preserving LibraryToLink objects, owners, flags and
additional inputs. Native cc_binary still owns the actual link action/toolchain.
Use only at a final consumer boundary; flattening every library would be costly.
"""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _impl(ctx):
    inputs = []
    seen = {}
    # Program objects precede libraries, even when their implementation depends
    # on those libraries. Keep their remaining dependency inputs for the tail.
    for group in ctx.attr.object_groups:
        own = [item for item in group[CcInfo].linking_context.linker_inputs.to_list() if item.owner == group.label]
        if not own:
            fail("object group has no owned linker input: " + str(group.label))
        for item in own:
            if item not in seen:
                seen[item] = True
                inputs.append(item)
    for dep in ctx.attr.deps + ctx.attr.object_groups:
        for item in dep[CcInfo].linking_context.linker_inputs.to_list():
            if item not in seen:
                seen[item] = True
                inputs.append(item)
    chain = depset(order = "topological")
    for item in reversed(inputs):
        chain = depset([item], transitive = [chain], order = "topological")
    merged = cc_common.merge_cc_infos(cc_infos = [dep[CcInfo] for dep in ctx.attr.object_groups + ctx.attr.deps])
    return [CcInfo(compilation_context = merged.compilation_context,
                   linking_context = cc_common.create_linking_context(linker_inputs = chain))]

bsd_link_sequence = rule(implementation = _impl,
    attrs = {"deps": attr.label_list(providers = [CcInfo], mandatory = True),
             "object_groups": attr.label_list(providers = [CcInfo], doc = "Program-owned compilation groups placed before library inputs.")})
