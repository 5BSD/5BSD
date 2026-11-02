# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned modules.inc order shared by static registration and family targets."""

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

def _selected(kind):
    result = []
    for condition, names in _GROUPS:
        values = names if kind == "names" else ["//lib/libpam/modules/" + name + ":" + (name if kind == "shared" else kind) for name in names]
        result += select({condition: values, "//conditions:default": []}) if condition else values
    return result

def pam_module_targets(kind):
    if kind not in ["shared", "static_archive", "install_archive"]:
        fail("unsupported PAM module family product: " + kind)
    return _selected(kind)

def pam_static_module_archives():
    return pam_module_targets("static_archive")

def pam_static_module_names():
    return _selected("names")
