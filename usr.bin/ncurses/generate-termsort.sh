#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
set -eu
set -o pipefail
[ "$#" -eq 2 ] || exit 64
exec sh -e -o pipefail "$1" awk "$2"
