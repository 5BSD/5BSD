# SPDX-License-Identifier: BSD-2-Clause
"""Maintained user-visible RPC headers; complete include composition is separate."""
load("//tools/build/bazel:bsd_rpcgen.bzl", "bsd_rpcgen")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive", "bsd_install_archive_set")

_HEADERS = ["auth.h", "auth_unix.h", "clnt.h", "clnt_soc.h", "clnt_stat.h", "nettype.h",
    "pmap_clnt.h", "pmap_prot.h", "pmap_rmt.h", "raw.h", "rpc.h", "rpc_msg.h", "rpcb_clnt.h",
    "rpcent.h", "rpc_com.h", "rpcsec_gss.h", "svc.h", "svc_auth.h", "svc_soc.h", "svc_dg.h",
    "xdr.h", "auth_des.h", "des.h", "des_crypt.h", "auth_kerb.h"]

def rpc_installation():
    bsd_rpcgen(name = "rpcbind_public_header", source = "rpc/rpcb_prot.x", output = "public_rpc/rpcb_prot.h",
        mode = "-h", flags = ["-C", "-DWANT_NFS3"], cpp_flags = ["-E", "-x", "c", "-nostdinc"],
        rpcgen = "//usr.bin/rpcgen:rpcgen", cpp = "@bsd_sdk//toolchain:bin/cpp",
        compiler_inputs = "@bsd_sdk//toolchain:compile_inputs", runtime = ["@bsd_sdk//toolchain:cpp_runtime"])
    files = {"rpc/" + name: name for name in _HEADERS} | {
        "//sys/rpc:clnt_nl.h": "clnt_nl.h", "rpc/rpcb_prot.x": "rpcb_prot.x",
        ":rpcbind_public_header": "rpcb_prot.h",
    }
    for index, (source, name) in enumerate(files.items()):
        bsd_install_file(name = "rpc_header_" + str(index), src = source,
            destination = "/usr/include/rpc/" + name, owner = "root", group = "wheel",
            mode = "0444", install_tags = ["package=clibs", "dev"])
    bsd_install_manifest(name = "rpc_install_manifest", entries = select({
        "//tools/build/bazel/config:includes_enabled": [":rpc_header_" + str(index) for index in range(len(files))],
        "//conditions:default": [],
    }))
    bsd_install_archive(name = "rpc_install_archive", manifests = [":rpc_install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include"},
        passwd = "//etc:master.passwd", group = "//etc:group",
        mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
    bsd_install_archive_set(name = "rpc_installation_archives",
        archives = [":rpc_install_archive", "//include/rpcsvc:install_archive"], visibility = ["//visibility:public"])
