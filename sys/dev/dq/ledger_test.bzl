# SPDX-License-Identifier: BSD-2-Clause
"""Expose the required declared-input ledger action as a native Bazel test.

The checker executes in the producing action. A stale/invalid ledger fails that
build before this adapter can run. No test reads the live checkout.
"""

def _impl(ctx):
    check = ctx.file.check
    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(script, "#!/bin/sh\nset -eu\ntest -f \"${TEST_SRCDIR}/${TEST_WORKSPACE}/" + check.short_path + "\"\n", is_executable = True)
    return [DefaultInfo(executable = script, runfiles = ctx.runfiles(files = [check]))]

dq_ledger_test = rule(implementation = _impl, test = True, attrs = {
    "check": attr.label(allow_single_file = True, mandatory = True),
})
