# SPDX-License-Identifier: BSD-2-Clause
FILENAME == ARGV[1] {
    if ($1 == "#define" && $2 == "VERSION") version = $3
    next
}
{
    if (version == "") exit 1
    gsub(/__FSECTION__/, "5")
    gsub(/__CSECTION__/, "1")
    gsub(/__VERSION__/, version)
    # Literal insertion: an ampersand in a path is not an awk replacement token.
    remaining = $0
    result = ""
    while ((position = index(remaining, "__MAGIC__")) != 0) {
        result = result substr(remaining, 1, position - 1) magic
        remaining = substr(remaining, position + 9)
    }
    print result remaining
}
END { if (version == "") exit 1 }
