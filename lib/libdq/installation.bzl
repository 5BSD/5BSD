# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

# One alias per documented function (lib/libdq/Makefile MLINKS).
MANUAL_ALIASES = [
    "dq_open",
    "dq_get_stats",
    "dq_set_queue_depth",
    "dq_policy_default",
    "dq_ident_from_stat",
    "dq_mint_file",
    "dq_mint_observer",
    "dq_revoke",
    "dq_set_ident",
    "dq_set_policy",
    "dq_read_events",
    "dq_event_first",
    "dq_event_next",
    "dq_event_body",
    "dq_reply",
    "dq_dispatch",
    "dq_observe_connect",
    "dq_observe_list_queues",
    "dq_observe_list_objects",
    "dq_observe_subscribe",
    "dq_get_stats2",
    "dq_mint_file_flags",
    "dq_push_vnode_note",
    "dq_push_invalidate",
    "dq_attach",
    "dq_attach_starts",
    "dq_attach_starts_flags",
    "dq_event_resolve_root",
    "dq_event_resolve",
    "dq_reply_resolve_pass",
    "dq_reply_resolve_errno",
    "dq_event_read",
    "dq_event_write",
    "dq_event_setattr",
    "dq_event_fsync",
    "dq_event_fallocate",
    "dq_event_fspacectl",
    "dq_event_lock",
    "dq_event_unlock_all",
    "dq_event_ioctl",
    "dq_event_interrupt",
    "dq_event_reply_record",
    "dq_reply_write",
    "dq_reply_fspacectl",
    "dq_reply_lock",
    "dq_reply_ioctl",
    "dq_reply_errno_allowed",
    "dq_resolve_errno_allowed",
    "dq_serve_state_create",
    "dq_serve_state_destroy",
    "dq_serve_state_owners",
    "dq_serve_file",
    "dq_resolve_accepts",
    "dq_resolve_errno_allowed_ev",
    "dq_event_resolve_ext",
    "dq_reply_resolve_fd",
    "dq_reply_resolve_attr",
    "dq_reply_resolve_link",
    "dq_reply_resolve_ok",
    "dq_reply_resolve_swap",
    "dq_tree_create",
    "dq_tree_destroy",
    "dq_tree_objects",
    "dq_serve_tree",
    "dq_tree_root",
    "dq_policy_default_dir",
    "dq_mint_dir",
    "dq_ident_from_lstat",
    "dq_reply_resolve_fd_symlink",
    "dq_reply_resolve_real",
    "dq_event_readdir",
    "dq_dirent_add",
    "dq_reply_readdir"
]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":dq_shared",
        binary_name = name + "/libdq.so.1", debug_name = name + "/libdq.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libdq.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=dq-man"], "//conditions:default": ["package=dq-dev"]})
    files = [
        ("libdq.h", "/usr/include/libdq.h", ["package=dq", "dev"], False),
        # Kernel ABI headers belong to the include installation, as in Make.
        (":static_archive", "/usr/lib/libdq.a", ["package=dq", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libdq.so.1", ["package=dq"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libdq.so.1.debug", ["package=dq", "dbg"], False),
    ]
    bsd_compress(name = name + "_manual", src = "libdq.3",
        output = name + "/libdq.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libdq.3.gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libdq.so", target = "libdq.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=dq", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libdq.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
