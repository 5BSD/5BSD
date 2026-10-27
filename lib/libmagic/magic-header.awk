# SPDX-License-Identifier: BSD-2-Clause
# Read the maintained configuration first, then expand the upstream template.
FILENAME == ARGV[1] {
    if ($1 == "#define" && $2 == "VERSION") {
        version = $3
        gsub(/[".]/, "", version)
        if (version !~ /^[0-9]+$/) exit 1
    }
    next
}
{
    if (version == "") exit 1
    gsub(/X[.]YY/, version)
    print
}
END { if (version == "") exit 1 }
