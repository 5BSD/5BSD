# SPDX-License-Identifier: BSD-2-Clause
"""Preserve the amd64 firmware API using the shared native firmware pipeline."""
load(":bsd_firmware_module.bzl", "bsd_firmware_module")


def amd64_firmware_module(module, images, license = "", export_all = False, package = "kernel", extra_objects = [], extra_object_order = []):
    bsd_firmware_module(arch = "amd64", module = module, images = images,
        license = license, export_all = export_all, package = package,
        extra_objects = extra_objects, extra_object_order = extra_object_order)
