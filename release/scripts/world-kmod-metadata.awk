# SPDX-License-Identifier: BSD-2-Clause
# Kernel and DTB payloads use their own packaging paths. Only explicit world
# package assignments belong in world staging and its generated plists.
/^[^#]/ {
    package = ""
    for (i = 2; i <= NF; i++) {
        if ($i ~ /^tags=/) {
            tags = $i
            sub(/^tags=/, "", tags)
            n = split(tags, values, ",")
            for (j = 1; j <= n; j++) {
                if (values[j] ~ /^package=/) {
                    package = values[j]
                    sub(/^package=/, "", package)
                }
            }
        }
    }
    if (package != "" && package != "kernel" && package != "dtb") print
}
