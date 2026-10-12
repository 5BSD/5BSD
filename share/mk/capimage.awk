# SPDX-License-Identifier: BSD-2-Clause
# od decimal bytes in, target assembler out. No target executable is run.
{ for (i = 1; i <= NF; i++) {
    if ($i !~ /^[0-9]+$/ || $i > 255 || n >= 1048576) { bad = 1; exit 1 }
    bytes[n++] = $i
} }
END {
    if (bad || n == 0) exit 1
    print ".section .5bsd.policy,\"\",%progbits"
    for (i = 0; i < n; i++) print ".byte " bytes[i]
    print ".section .note.GNU-stack,\"\",%progbits"
}
