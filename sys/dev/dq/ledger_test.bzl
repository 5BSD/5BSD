# SPDX-License-Identifier: BSD-2-Clause
"""The DescriptorQueue resolution ledger check as a Bazel test.

The Make kernel build (sys/conf/files dq_resolve_ledger.chk) is the
authoritative check.  This test runs the same sys/tools/dq_resolve_ledger.sh
over the workspace's real sources; it must be tagged "local" and
"no-sandbox", since the ledger scans whole source trees.
"""

_SCRIPT = """#!/bin/sh
set -e
ws="${BUILD_WORKSPACE_DIRECTORY:-}"
if [ -z "$ws" ]; then
	# The ledger's runfiles entry is a symlink into the workspace.
	r="${TEST_SRCDIR:-$0.runfiles}/${TEST_WORKSPACE:-_main}"
	ledger=$(realpath "$r/sys/dev/dq/dq_resolve_ledger.txt")
	ws=${ledger%/sys/dev/dq/dq_resolve_ledger.txt}
fi
exec sh "$ws/sys/tools/dq_resolve_ledger.sh" check "$ws/sys" \\
    "$ws/sys/dev/dq/dq_resolve_ledger.txt"
"""

def _dq_ledger_test_impl(ctx):
    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(script, _SCRIPT, is_executable = True)
    return [DefaultInfo(executable = script,
        runfiles = ctx.runfiles(files = ctx.files.data))]

dq_ledger_test = rule(
    implementation = _dq_ledger_test_impl,
    test = True,
    attrs = {"data": attr.label_list(allow_files = True)},
)
