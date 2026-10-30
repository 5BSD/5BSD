# SPDX-License-Identifier: BSD-2-Clause
# Read the maintained version before expanding the upstream pkg-config template.
FILENAME == ARGV[1] {
    if ($1 == "#define" && $2 == "PACKAGE_VERSION") {
        version = $3
        gsub(/"/, "", version)
        if (version !~ /^[0-9]+([.][0-9]+)*$/) exit 1
    }
    next
}
{
    if (version == "") exit 1
    gsub(/@prefix@/, "/usr")
    gsub(/@exec_prefix@/, "${prefix}")
    gsub(/@libdir@/, "/usr/lib")
    gsub(/@sharedlibdir@/, "/usr/lib")
    gsub(/@includedir@/, "/usr/include")
    gsub(/@VERSION@/, version)
    gsub(/@LIBS@/, "")
    print
}
END { if (version == "") exit 1 }
