# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory; maintained alongside the public interface.

MANUALS = [
    "kvm.3",
    "kvm_getcptime.3",
    "kvm_geterr.3",
    "kvm_getloadavg.3",
    "kvm_getpcpu.3",
    "kvm_getprocs.3",
    "kvm_getswapinfo.3",
    "kvm_kerndisp.3",
    "kvm_native.3",
    "kvm_nlist.3",
    "kvm_open.3",
    "kvm_read.3",
]

MANUAL_LINKS = [
    ("kvm_getpcpu.3", "kvm_getmaxcpu.3"),
    ("kvm_getpcpu.3", "kvm_dpcpu_setcpu.3"),
    ("kvm_getpcpu.3", "kvm_read_zpcpu.3"),
    ("kvm_getpcpu.3", "kvm_counter_u64_fetch.3"),
    ("kvm_getprocs.3", "kvm_getargv.3"),
    ("kvm_getprocs.3", "kvm_getenvv.3"),
    ("kvm_nlist.3", "kvm_nlist2.3"),
    ("kvm_open.3", "kvm_close.3"),
    ("kvm_open.3", "kvm_open2.3"),
    ("kvm_open.3", "kvm_openfiles.3"),
    ("kvm_read.3", "kvm_read2.3"),
    ("kvm_read.3", "kvm_write.3"),
]
