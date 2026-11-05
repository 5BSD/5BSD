# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned rescue program selection using the maintained build settings.

PROGRAMS retains original default order. Each optional program is selected by
its actual src.opts condition; compiler metadata comes from its source owner.
No Make or filesystem inventory is queried during analysis or execution.
"""
load(":catalog.bzl", "PROGRAMS")

_CONDITIONS = {
    "csh": "//tools/build/bazel/config:tcsh_enabled",
    "ping": "//rescue/rescue:ping_enabled",
    "rtsol": "//tools/build/bazel/config:inet6_support_enabled",
    "pfctl": "//tools/build/bazel/config:pf_enabled",
    "bectl": "//tools/build/bazel/config:zfs_enabled",
    "zfs": "//tools/build/bazel/config:zfs_enabled",
    "zfsbootcfg": "//tools/build/bazel/config:zfs_enabled",
    "zpool": "//tools/build/bazel/config:zfs_enabled",
    "zdb": "//tools/build/bazel/config:zfs_enabled",
    "nc": "//tools/build/bazel/config:netcat_enabled",
    "vi": "//tools/build/bazel/config:vi_enabled",
    "iscsictl": "//tools/build/bazel/config:iscsi_enabled",
    "iscsid": "//tools/build/bazel/config:iscsi_enabled",
}

def selected_program_lists(values):
    """Compose list-valued attributes in original program order."""
    result = []
    for program in PROGRAMS:
        value = values[program]
        condition = _CONDITIONS.get(program)
        result += select({condition: value, "//conditions:default": []}) if condition else value
    return result

def selected_program_values(values):
    """Select one value per configured program."""
    return selected_program_lists({p: [values[p]] for p in PROGRAMS})

def selected_programs():
    return selected_program_values({p: p for p in PROGRAMS})
