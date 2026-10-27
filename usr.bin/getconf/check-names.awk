# SPDX-License-Identifier: BSD-2-Clause
# Match Make's name extraction and exact-line uniqueness check.
/^[_A-Z]/ {
    sub(/,$/, "")
    if (seen[$0]++) {
        print "Name conflicts found: " $0 > "/dev/stderr"
        failed = 1
    }
}
END { if (failed) exit 1; print "names validated" }
