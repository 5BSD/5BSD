/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#ifndef CAPSIGN_TREE_H
#define CAPSIGN_TREE_H
#include <stdbool.h>
void capsign_tree(const char *, const char *, const char *, const char *);
void capsign_tree_resign(const char *, const char *, const char *, const char *);
void capsign_tree_preview(const char *, const char *, const char *, const char *, bool);
void capsign_tree_remove(const char *, const char *);
#endif
