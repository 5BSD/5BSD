#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
set -eu
[ "$#" -eq 4 ] || exit 64
cat "$@"
