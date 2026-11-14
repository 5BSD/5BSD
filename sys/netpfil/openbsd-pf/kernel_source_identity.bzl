# SPDX-License-Identifier: BSD-2-Clause
"""Built-in PF source identity from the kernel's ../contrib input declarations.

Modules use their own source-path policy. These compiler inputs preserve the
source filenames used by kernel config, including the logical sys parent step.
"""
PF_BUILTIN_SOURCE_PATH_FLAGS = [
    "-ffile-prefix-map=contrib/openbsd-pf/=/usr/src/sys/../contrib/openbsd-pf/",
    "-ffile-prefix-map=./contrib/openbsd-pf/=/usr/src/sys/../contrib/openbsd-pf/",
]
