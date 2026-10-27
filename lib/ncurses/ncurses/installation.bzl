# SPDX-License-Identifier: BSD-2-Clause
load("//lib/ncurses:installation.bzl", "library_installation")
def install_library(name):
    library_installation(name = name, library = 'ncurses',
        headers = {},
        manuals = [],
        aliases = [])
