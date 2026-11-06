# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned package traversal for supported world architectures."""
load(":bsd_pkg_family.bzl", "bsd_pkg_family_set")

def world_package_families():
    # Like packages/Makefile: these declarations select metadata, not payload.
    families = []
    families += [
        "//packages/bsd-build:family",
        "//packages/bsdaudit:family",
        "//packages/bsdconfig:family",
        "//packages/bzip2:family",
        "//packages/clibs:family",
        "//packages/cron:family",
        "//packages/ctl:family",
        "//packages/capsule:family",
        "//packages/capsulectl:family",
        "//packages/oes:family",
        "//packages/switchboard:family",
        "//packages/switchboardctl:family",
        "//packages/sysextctl:family",
        "//packages/bsdcrypto:family",
        "//packages/bsddevice:family",
        "//packages/bsdlog:family",
        "//packages/bsdnetwork:family",
        "//packages/bsdnotify:family",
        "//packages/bsdmemory:family",
        "//packages/mac-abac:family",
        "//packages/devd:family",
        "//packages/devmatch:family",
        "//packages/dhclient:family",
        "//packages/fetch:family",
        "//packages/flua:family",
        "//packages/firmware-iwm:family",
        "//packages/fwget:family",
        "//packages/geom:family",
        "//packages/ggate:family",
        "//packages/hwstat:family",
        "//packages/otel:family",
        "//packages/lib9p:family",
        "//packages/libauditcmp:family",
        "//packages/libarchive:family",
        "//packages/libcapability:family",
        "//packages/libcapbundle:family",
        "//packages/libcapimage:family",
        "//packages/libchannel:family",
        "//packages/libfidl:family",
        "//packages/libcryptocmp:family",
        "//packages/libcryptodesc:family",
        "//packages/libdevicecmp:family",
        "//packages/liblogcmp:family",
        "//packages/libnetworkcmp:family",
        "//packages/libsysctlcmp:family",
        "//packages/libtimecmp:family",
        "//packages/libpowercmp:family",
        "//packages/libextensioncmp:family",
        "//packages/libfilesystemcmp:family",
        "//packages/libnamespacecmp:family",
        "//packages/libvmcmp:family",
        "//packages/libcache:family",
        "//packages/libcapreclaim:family",
        "//packages/libnotify:family",
        "//packages/libcapsulert:family",
        "//packages/libservice:family",
        "//packages/libshmring:family",
        "//packages/libbegemot:family",
        "//packages/libblocksruntime:family",
        "//packages/libbsdstat:family",
        "//packages/libcasper:family",
        "//packages/libcompat:family",
        "//packages/libcompiler_rt:family",
        "//packages/libdwarf:family",
        "//packages/libevent1:family",
        "//packages/libexecinfo:family",
        "//packages/libpathconv:family",
        "//packages/librss:family",
        "//packages/libsqlite3:family",
        "//packages/libalias:family",
        "//packages/libthread_db:family",
        "//packages/libucl:family",
        "//packages/libnghttp2:family",
        "//packages/protobuf:family",
        "//packages/libyaml:family",
        "//packages/locales:family",
        "//packages/mandoc:family",
        "//packages/mtree:family",
        "//packages/ncurses:family",
        "//packages/netmap:family",
        "//packages/newsyslog:family",
        "//packages/nfs:family",
        "//packages/nvme-tools:family",
        "//packages/pam:family",
        "//packages/periodic:family",
        "//packages/powerd:family",
        "//packages/ppp:family",
        "//packages/rc:family",
        "//packages/resolvconf:family",
        "//packages/runtime:family",
        "//packages/smart:family",
        "//packages/syslogd:family",
        "//packages/tcpd:family",
        "//packages/toolchain:family",
        "//packages/ufs:family",
        "//packages/utilities:family",
        "//packages/xz:family",
        "//packages/zlib:family",
        "//packages/zstd:family",
    ]
    families += select({"//tools/build/bazel/config:package_acct_or_utmpx": ["//packages/acct:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_clang_or_lld_or_lldb_or_llvm_binutils": ["//packages/clang:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_authpf_or_pf": ["//packages/pf:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_caroot_openssl": ["//packages/certctl:family", "//packages/capsign:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:caroot_enabled": ["//packages/caroot:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:at_enabled": ["//packages/at:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:audit_enabled": ["//packages/audit:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:autofs_enabled": ["//packages/autofs:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:blocklist_enabled": ["//packages/blocklist:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:bluetooth_enabled": ["//packages/bluetooth:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:boot_enabled": ["//packages/bootloader:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:bsdinstall_enabled": ["//packages/bsdinstall:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:bsnmp_enabled": ["//packages/bsnmp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:cuse_enabled": ["//packages/libcuse:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:cxgbetool_enabled": ["//packages/cxgbe-tools:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:dmagent_enabled": ["//packages/dma:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:dtrace_enabled": ["//packages/bsdinstruments:family", "//packages/bsdtrace-provider:family", "//packages/ctf:family", "//packages/dtrace:family", "//packages/dwatch:family", "//packages/libtracecmp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:ee_enabled": ["//packages/ee:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:efi_enabled": ["//packages/efi-tools:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:examples_enabled": ["//packages/examples:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:file_enabled": ["//packages/libmagic:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:ftp_enabled": ["//packages/ftp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:games_enabled": ["//packages/games:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:googletest_enabled": ["//packages/googletest:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:hast_enabled": ["//packages/hast:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:hyperv_enabled": ["//packages/hyperv-tools:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:inetd_enabled": ["//packages/inetd:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:dummynet_enabled": ["//packages/dummynet:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:iscsi_enabled": ["//packages/iscsi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:jail_enabled": ["//packages/jail:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:kerberos_enabled": ["//packages/kerberos:family", "//packages/kerberos-kdc:family", "//packages/librpcsec_gss:family", "//packages/gssd:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:ldns_enabled": ["//packages/libldns:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:legacy_console_enabled": ["//packages/console-tools:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:lld_enabled": ["//packages/lld:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:lldb_enabled": ["//packages/lldb:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:lpr_enabled": ["//packages/lp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:make_enabled": ["//packages/bmake:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:man_enabled": ["//packages/kernel-man:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:mlx5tool_enabled": ["//packages/mlx-tools:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:nis_enabled": ["//packages/yp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:ntp_enabled": ["//packages/ntp:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:nuageinit_enabled": ["//packages/nuageinit:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:ofed_enabled": ["//packages/rdma:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:openssh_enabled": ["//packages/ssh:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:openssl_enabled": ["//packages/openssl:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:pkgbootstrap_enabled": ["//packages/pkg-bootstrap:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:pkgconf_enabled": ["//packages/pkgconf:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:pmc_enabled": ["//packages/pmc:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:quotas_enabled": ["//packages/quotacheck:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:rescue_enabled": ["//packages/rescue:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:sendmail_enabled": ["//packages/sendmail:family", "//packages/libmilter:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:sound_enabled": ["//packages/sound:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tcsh_enabled": ["//packages/csh:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:telnet_enabled": ["//packages/telnet:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bsdinstall_tests": ["//packages/bsdinstall-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bluetooth_tests": ["//packages/bluetooth-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_tests": ["//packages/waspnest-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsd-build-tests:family", "//packages/libjail-tests:family", "//packages/runtime-tests:family", "//packages/pam-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_openssl_tests": ["//packages/capsign-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/capsule-tests:family", "//packages/capsulectl-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_dtrace_tests": ["//packages/bsdinstruments-tests:family", "//packages/bsdtrace-provider-tests:family", "//packages/libtracecmp-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/hwstat-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/switchboard-tests:family", "//packages/switchboardctl-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libcapability-tests:family", "//packages/libcapbundle-tests:family", "//packages/libcapimage-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libauditcmp-tests:family", "//packages/bsdaudit-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libchannel-tests:family", "//packages/libshmring-tests:family", "//packages/libfidl-tests:family", "//packages/bsdtime-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libcryptocmp-tests:family", "//packages/libcryptodesc-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libnetworkcmp-tests:family", "//packages/libsysctlcmp-tests:family", "//packages/libtimecmp-tests:family", "//packages/libpowercmp-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libcapreclaim-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/liblogcmp-tests:family", "//packages/libnotify-tests:family", "//packages/libcache-tests:family", "//packages/bsdmemory-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libotelexport-tests:family", "//packages/otel-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libtrustedzfs-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libcapsulert-tests:family", "//packages/libservice-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/mac-capability-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/mac-abac-tests:family", "//packages/oes-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/netmap-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsdnetwork-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsdcrypto-tests:family", "//packages/bsddevice-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/libdevicecmp-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsdlog-tests:family", "//packages/bsdnotify-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsdextension-tests:family", "//packages/tzfs-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/sysextctl-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_enabled": ["//packages/bsdnamespace-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:tests_support_enabled": ["//packages/atf:family", "//packages/kyua:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:unbound_enabled": ["//packages/local-unbound:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:vi_enabled": ["//packages/vi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:vt_enabled": ["//packages/vt-data:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:wireless_enabled": ["//packages/hostapd:family", "//packages/wpa:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:zfs_enabled": ["//packages/zfs:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:zoneinfo_enabled": ["//packages/zoneinfo:family"], "//conditions:default": []})
    families += select({"@platforms//cpu:x86_64": ["//packages/libvgl:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_acpi_amd64": ["//packages/acpi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_apm_amd64": ["//packages/apm:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_amd64": ["//packages/bhyve:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_amd64": ["//packages/libvmmapi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_pmc_amd64": ["//packages/libipt:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_pmc_amd64": ["//packages/bsdtrace:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_pmc_tests_amd64": ["//packages/bsdtrace-tests:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_acpi_arm64": ["//packages/acpi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_arm64": ["//packages/bhyve:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_arm64": ["//packages/libvmmapi:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_riscv64": ["//packages/bhyve:family"], "//conditions:default": []})
    families += select({"//tools/build/bazel/config:package_bhyve_riscv64": ["//packages/libvmmapi:family"], "//conditions:default": []})
    # src.opts.mk retires syscons and rejects requests; no syscons payload selected.
    # Fail unsupported target CPUs even if every architecture option is disabled.
    families += select({"@platforms//cpu:x86_64": [], "@platforms//cpu:aarch64": [], "@platforms//cpu:riscv64": []}, no_match_error = "World packages support amd64, arm64 and riscv64")
    bsd_pkg_family_set(name = "world_family_manifests", families = families,
        visibility = ["//visibility:public"])
