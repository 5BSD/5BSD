# SPDX-License-Identifier: BSD-2-Clause
FILENAME != layout {
    if ($0 ~ /^#/ || NF == 0) next
    key = FILENAME SUBSEP $1
    for (i = 2; i <= NF; i++) names[key] = names[key] " " $i
    next
}
{
    split($0, fields, "\t")
    if (fields[1] == "H") {
        if (groups++) {
            print "" > directory
            print "" > aliases
        }
        print "# " fields[2] > directory
        print "# " fields[2] > aliases
    } else if (fields[1] == "E") {
        printf "%-32s%s\n", fields[2], fields[3] > directory
        key = fields[5] SUBSEP fields[4]
        count = split(names[key], values, " ")
        for (i = 1; i <= count; i++)
            printf "%-32s%s\n", values[i], fields[2] > aliases
    } else exit 1
}
