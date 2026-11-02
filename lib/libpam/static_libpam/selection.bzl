# SPDX-License-Identifier: BSD-2-Clause
"""Compatibility entry points backed by the common source-owned module order."""
load("//lib/libpam/modules:selection.bzl", _archives = "pam_static_module_archives", _names = "pam_static_module_names")

def pam_static_module_archives():
    return _archives()

def pam_static_module_names():
    return _names()
