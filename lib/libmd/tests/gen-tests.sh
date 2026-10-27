#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Emit the common ATF body for an explicit maintained digest list.
set -eu
[ "$#" -gt 0 ] || { echo "digest list required" >&2; exit 1; }
for digest do
    case "$digest" in
        ''|*[!a-zA-Z0-9_]*|[0-9]*) echo "invalid digest name: $digest" >&2; exit 1 ;;
    esac
done
for digest do
    printf 'atf_test_case %s\n' "$digest"
    printf '%s_body() {\n' "$digest"
    printf '\tatf_check -o file:$(atf_get_srcdir)/%s.ref \\\n' "$digest"
    printf '\t$(atf_get_srcdir)/%sdriver\n' "$digest"
    printf '}\n'
done
printf 'atf_init_test_cases() {\n'
for digest do
    printf '\tatf_add_test_case %s\n' "$digest"
done
printf '}\n'
