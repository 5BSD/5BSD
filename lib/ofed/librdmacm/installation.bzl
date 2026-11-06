# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":rdmacm_shared",
        binary_name = name + "/librdmacm.so.1", debug_name = name + "/librdmacm.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/librdmacm.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/librdmacm.a", ["package=rdma", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/librdmacm.so.1", ["package=rdma", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/librdmacm.so.1.debug", ["package=rdma", "dbg"], False),
    ]
    for manual in ['rdma_accept.3', 'rdma_ack_cm_event.3', 'rdma_bind_addr.3', 'rdma_connect.3', 'rdma_create_ep.3', 'rdma_create_event_channel.3', 'rdma_create_id.3', 'rdma_create_qp.3', 'rdma_create_srq.3', 'rdma_dereg_mr.3', 'rdma_destroy_ep.3', 'rdma_destroy_event_channel.3', 'rdma_destroy_id.3', 'rdma_destroy_qp.3', 'rdma_destroy_srq.3', 'rdma_disconnect.3', 'rdma_event_str.3', 'rdma_free_devices.3', 'rdma_get_cm_event.3', 'rdma_get_devices.3', 'rdma_get_dst_port.3', 'rdma_get_local_addr.3', 'rdma_get_peer_addr.3', 'rdma_get_recv_comp.3', 'rdma_get_request.3', 'rdma_get_send_comp.3', 'rdma_get_src_port.3', 'rdma_getaddrinfo.3', 'rdma_join_multicast.3', 'rdma_leave_multicast.3', 'rdma_listen.3', 'rdma_migrate_id.3', 'rdma_notify.3', 'rdma_post_read.3', 'rdma_post_readv.3', 'rdma_post_recv.3', 'rdma_post_recvv.3', 'rdma_post_send.3', 'rdma_post_sendv.3', 'rdma_post_ud_send.3', 'rdma_post_write.3', 'rdma_post_writev.3', 'rdma_reg_msgs.3', 'rdma_reg_read.3', 'rdma_reg_write.3', 'rdma_reject.3', 'rdma_resolve_addr.3', 'rdma_resolve_route.3', 'rdma_set_option.3']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/ofed/librdmacm:man/" + manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", select({"//tools/build/bazel/config:split_manpages_enabled": ["package=rdma-man"], "//conditions:default": ["package=rdma-dev"]}), True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/librdmacm.so", target = "librdmacm.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=rdma", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
