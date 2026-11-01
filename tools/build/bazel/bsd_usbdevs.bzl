# SPDX-License-Identifier: BSD-2-Clause
"""The maintained USB generator's explicit device-ID action contract."""
load(":bsd_device_ids.bzl", "bsd_device_ids_header")

def bsd_usbdevs_header(name, src = "//sys/dev/usb:usbdevs", generator = "//sys/tools:usbdevs2h.awk", **kwargs):
    bsd_device_ids_header(name = name, src = src, generator = generator,
        header = "usbdevs.h", arguments = ["-h"], mnemonic = "BsdUsbDeviceIds", **kwargs)
