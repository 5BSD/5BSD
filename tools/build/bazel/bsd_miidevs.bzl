# SPDX-License-Identifier: BSD-2-Clause
"""The maintained MII generator's explicit device-ID action contract."""
load(":bsd_device_ids.bzl", "bsd_device_ids_header")

def bsd_miidevs_header(name, src = "//sys/dev/mii:miidevs", generator = "//sys/tools:miidevs2h.awk", **kwargs):
    bsd_device_ids_header(name = name, src = src, generator = generator,
        header = "miidevs.h", arguments = [], mnemonic = "BSDMiiDeviceIds", **kwargs)
