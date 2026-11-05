# SPDX-License-Identifier: BSD-2-Clause
"""Maintained version-map interface to the shared declared sed producer."""
load(":bsd_sed_output.bzl", "sed_output_rule")
bsd_version_filter = sed_output_rule("BSDVersionFilter")
