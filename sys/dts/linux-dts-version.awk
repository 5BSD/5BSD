# SPDX-License-Identifier: BSD-2-Clause
# The maintained property supplies a C string; reject ambiguous input.
/^[ \t]*freebsd,dts-version[ \t]*=/ {
    count++
    if (NF != 3 || $2 != "=" || $3 !~ /^"([^"\\]|\\.)*";$/)
        invalid = 1
    value = $3
    sub(/;$/, "", value)
}
END {
    if (count != 1 || invalid) {
        print "expected one quoted freebsd,dts-version property" > "/dev/stderr"
        exit 1
    }
    print "#define LINUX_DTS_VERSION " value
}
