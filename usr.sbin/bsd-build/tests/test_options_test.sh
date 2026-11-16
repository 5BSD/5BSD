# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The test-kernel option ledger, sys/conf/test-options, against the source
# tree in /usr/src: config(8) itself shows that only the allowed
# configuration carries each option, and the options file and the sources
# agree with every row.  The check script lists the ledger
# (check-test-kernel.sh -L), so a row it cannot read fails here too.
#
# Everything here is sh, and reads /usr/src without writing to it.

LEDGER=/usr/src/sys/conf/test-options

setup()
{
    [ -f /usr/src/Makefile ] || atf_fail 'these cases read the source tree in /usr/src'
    [ -f "$LEDGER" ] || atf_fail "$LEDGER is missing"
    check="$(atf_get_srcdir)/check-test-kernel.sh"
    [ -f "$check" ] || atf_fail 'check-test-kernel.sh not installed beside the test'
    atf_check -s exit:0 -o save:rows -e empty sh "$check" -l "$LEDGER" -L
    [ -s rows ] || atf_fail 'the ledger lists no option'
}

# field number: one field of every row, in ledger order.
field()
{
    cut -d '|' -f "$1" rows
}

atf_test_case config_sweep
config_sweep_head()
{
    atf_set descr 'config(8) shows each test-kernel option only in the configuration the ledger allows'
    atf_set require.progs config
    atf_set timeout 3600
}
config_sweep_body()
{
    setup
    : > configured
    : > failed
    : > notes-family
    for confdir in /usr/src/sys/*/conf; do
        [ -d "$confdir" ] || continue
        arch=${confdir%/conf}
        arch=${arch##*/}
        for file in "$confdir"/*; do
            name=${file##*/}
            [ -f "$file" ] || continue
            [ -r "$file" ] || atf_fail "cannot read $file"
            # A configuration has its own ident line.  NOTES lists every
            # option for compile tests and is read through LINT; the LINT
            # family is not read here (ledger_tree checks NOTES instead).
            case $name in
            NOTES|DEFAULTS|*.hints|*.env|Makefile|BUILD.bazel) continue ;;
            LINT|LINT-*) echo "$arch/$name" >> notes-family; continue ;;
            esac
            grep -q '^[[:space:]]*ident[[:space:]]' "$file" || continue
            out=$PWD/out/$arch/$name
            mkdir -p "$out"
            if ! (cd "$confdir" && config -s /usr/src/sys -d "$out" \
                -I "$confdir" "$file") > "$out.log" 2>&1; then
                echo "$arch/$name" >> failed
                continue
            fi
            echo "$arch/$name" >> configured
            # The options it defines, from every generated header.
            cat "$out"/opt_*.h 2>/dev/null |
                awk '$1 == "#define" { print $2 }' | sort -u > "$out.defined"
            for option in $(field 1); do
                allowed=$(awk -F '|' -v o="$option" '$1 == o { print $3 }' rows)
                status=$(awk -F '|' -v o="$option" '$1 == o { print $2 }' rows)
                if grep -qx "$option" "$out.defined"; then
                    [ "$status" = live ] && [ "$name" = "$allowed" ] ||
                        atf_fail "$arch/$name carries options $option; the ledger allows ${allowed} only (status $status)"
                elif [ "$status" = live ] && [ "$name" = "$allowed" ]; then
                    atf_fail "$arch/$name does not carry options $option, which the ledger gives it"
                fi
            done
        done
    done
    if [ -s failed ]; then
        for c in $(cat failed); do
            echo "config(8) failed on $c:"; tail -n 5 "out/$c.log"
        done
        atf_fail "config(8) could not read $(wc -l < failed | tr -d ' ') configuration(s); nothing is concluded from a configuration that was not read"
    fi
    [ -s configured ] || atf_fail 'no configuration was read'
    echo "configurations read by config(8): $(wc -l < configured | tr -d ' ')"
    [ ! -s notes-family ] ||
        echo "NOT READ by config(8) (NOTES through LINT; see ledger_tree): $(tr '\n' ' ' < notes-family)"
    # Each allowed configuration exists and was read.
    for option in $(field 1); do
        status=$(awk -F '|' -v o="$option" '$1 == o { print $2 }' rows)
        allowed=$(awk -F '|' -v o="$option" '$1 == o { print $3 }' rows)
        [ "$status" = live ] || continue
        grep -q "/$allowed\$" configured ||
            atf_fail "$option: the allowed configuration $allowed was not read"
    done
}

atf_test_case ledger_tree
ledger_tree_head()
{
    atf_set descr 'The options file and the kernel sources agree with every ledger row'
    atf_set timeout 1800
}
ledger_tree_body()
{
    setup
    # Option names: every live row is in sys/conf/options, and no reserved
    # one is (a reserved row cannot be built).
    awk '!/^#/ && NF { print $1 }' /usr/src/sys/conf/options | sort -u > options
    for option in $(field 1); do
        status=$(awk -F '|' -v o="$option" '$1 == o { print $2 }' rows)
        if grep -qx "$option" options; then
            [ "$status" = live ] ||
                atf_fail "$option is in sys/conf/options but its ledger row is $status"
        else
            [ "$status" = reserved ] ||
                atf_fail "$option is live in the ledger but not in sys/conf/options"
        fi
    done

    # NOTES (read through LINT, which config_sweep does not read) names
    # no ledger option: a test-kernel option is never compile-tested there.
    for notes in /usr/src/sys/conf/NOTES /usr/src/sys/*/conf/NOTES; do
        [ -f "$notes" ] || continue
        sed -e 's/#.*//' "$notes" | tr ' \t,=' '\n\n\n\n' > notes-words
        for option in $(field 1); do
            ! grep -qx "$option" notes-words ||
                atf_fail "$notes names options $option"
        done
    done

    # Markers: every marker string in the kernel sources is a ledger row,
    # a live row's marker is in them, a reserved row's is not.
    grep -r -h -o -E --include='*.c' --include='*.h' \
        '@\(#\)5BSD [A-Z0-9_]+ [a-z]+ kernel: not for publication' \
        /usr/src/sys | sort -u > markers
    field 5 | sort -u > ledger-markers
    atf_check -s exit:0 -o empty -e empty comm -23 markers ledger-markers
    for option in $(field 1); do
        status=$(awk -F '|' -v o="$option" '$1 == o { print $2 }' rows)
        marker=$(awk -F '|' -v o="$option" '$1 == o { print $5 }' rows)
        prefix=$(awk -F '|' -v o="$option" '$1 == o { print $4 }' rows)
        if grep -qxF "$marker" markers; then
            [ "$status" = live ] ||
                atf_fail "$option is reserved but its marker is in the kernel sources"
        else
            [ "$status" = reserved ] ||
                atf_fail "$option is live but its marker is not in the kernel sources"
        fi
        # A live prefix names the option's own symbols.
        if [ "$status" = live ] && [ "$prefix" != - ]; then
            grep -r -q -F --include='*.c' -e "$prefix" /usr/src/sys ||
                atf_fail "$option: no kernel source uses the prefix $prefix"
        fi
    done

    # The test kernel configuration has one name.
    for old in /usr/src/sys/*/conf/GENERIC-DQTEST; do
        [ ! -e "$old" ] || atf_fail "$old still exists: GENERIC-TEST replaced it"
    done
}

atf_init_test_cases()
{
    atf_add_test_case config_sweep
    atf_add_test_case ledger_tree
}
