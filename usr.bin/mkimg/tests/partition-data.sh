#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
read -r repetitions
exec jot -b P "$repetitions"
