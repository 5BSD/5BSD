# SPDX-License-Identifier: BSD-2-Clause
"""Maintained ordered static PAM module selection, shared by archive and test."""

_GROUPS = [
    (None, [
        "pam_capability", "pam_chroot", "pam_deny", "pam_echo", "pam_exec",
        "pam_ftpusers", "pam_group", "pam_guest",
    ]),
    ("//tools/build/bazel/config:pam_kerberos_selected", ["pam_krb5", "pam_ksu"]),
    (None, [
        "pam_lastlog", "pam_login_access", "pam_nologin", "pam_passwdqc",
        "pam_permit",
    ]),
    ("//tools/build/bazel/config:pam_radius_selected", ["pam_radius"]),
    (None, ["pam_rhosts", "pam_rootok", "pam_securetty", "pam_self"]),
    ("//tools/build/bazel/config:pam_openssh_selected", ["pam_ssh"]),
    (None, ["pam_tacplus", "pam_unix", "pam_xdg"]),
]

def _selected(archives):
    result = []
    for condition, names in _GROUPS:
        values = ["//lib/libpam/modules/" + name + ":static_archive" for name in names] if archives else names
        result += select({condition: values, "//conditions:default": []}) if condition else values
    return result

def pam_static_module_archives():
    return _selected(True)

def pam_static_module_names():
    return _selected(False)
