# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":ibverbs_shared",
        binary_name = name + "/libibverbs.so.1", debug_name = name + "/libibverbs.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libibverbs.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libibverbs.a", ["package=rdma", "dev"], False),
        (":" + name + "_stripped", "/lib/libibverbs.so.1", ["package=rdma", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libibverbs.so.1.debug", ["package=rdma", "dbg"], False),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=rdma-man"], "//conditions:default": ["package=rdma-dev"]})
    for manual in ['ibv_alloc_mw', 'ibv_alloc_pd', 'ibv_attach_mcast', 'ibv_bind_mw', 'ibv_create_ah', 'ibv_create_ah_from_wc', 'ibv_create_comp_channel', 'ibv_create_cq', 'ibv_create_cq_ex', 'ibv_create_flow', 'ibv_create_qp', 'ibv_create_qp_ex', 'ibv_create_rwq_ind_table', 'ibv_create_srq', 'ibv_create_srq_ex', 'ibv_create_wq', 'ibv_event_type_str', 'ibv_fork_init', 'ibv_get_async_event', 'ibv_get_cq_event', 'ibv_get_device_guid', 'ibv_get_device_list', 'ibv_get_device_name', 'ibv_get_srq_num', 'ibv_inc_rkey', 'ibv_modify_qp', 'ibv_modify_srq', 'ibv_modify_wq', 'ibv_open_device', 'ibv_open_qp', 'ibv_open_xrcd', 'ibv_poll_cq', 'ibv_post_recv', 'ibv_post_send', 'ibv_post_srq_recv', 'ibv_query_device', 'ibv_query_device_ex', 'ibv_query_gid', 'ibv_query_pkey', 'ibv_query_port', 'ibv_query_qp', 'ibv_query_rt_values_ex', 'ibv_query_srq', 'ibv_rate_to_mbps', 'ibv_rate_to_mult', 'ibv_reg_mr', 'ibv_req_notify_cq', 'ibv_rereg_mr', 'ibv_resize_cq']:
        bsd_compress(name = name + "_" + manual, src = "//contrib/ofed/libibverbs:man/" + manual + ".3",
            output = name + "/" + manual + ".3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + name + "_" + manual, "/usr/share/man/man3/" + manual + ".3.gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libibverbs.so", target = "../../lib/libibverbs.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=rdma", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
