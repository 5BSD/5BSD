# SPDX-License-Identifier: BSD-2-Clause
# files.amd64: export the defined trampoline symbol offsets.
set -eu
set -o pipefail
nm -n --defined-only "$1" | while read -r offset dummy what; do
    printf '#define\t%s\t0x%s\n' "$what" "$offset"
done
