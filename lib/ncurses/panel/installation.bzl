# SPDX-License-Identifier: BSD-2-Clause
load("//lib/ncurses:installation.bzl", "library_installation")
def install_library(name):
    library_installation(name = name, library = 'panel',
        headers = {'panel.h': '//contrib/ncurses:panel/panel.h'},
        manuals = ['panel.3'],
        aliases = [('panel.3', 'bottom_panel.3'), ('panel.3', 'del_panel.3'), ('panel.3', 'hide_panel.3'), ('panel.3', 'move_panel.3'), ('panel.3', 'new_panel.3'), ('panel.3', 'panel_above.3'), ('panel.3', 'panel_below.3'), ('panel.3', 'panel_hidden.3'), ('panel.3', 'panel_userptr.3'), ('panel.3', 'panel_window.3'), ('panel.3', 'replace_panel.3'), ('panel.3', 'set_panel_userptr.3'), ('panel.3', 'show_panel.3'), ('panel.3', 'top_panel.3'), ('panel.3', 'update_panels.3')])
