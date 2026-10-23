#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Common parser acceptance corpus. Parse only; never load these rules.
set -eu
[ -f /root/pf-parity-disposable ] || exit 1
case $(uname -s) in OpenBSD|FreeBSD|5BSD) ;; *) exit 1;; esac
work=$(mktemp -d /tmp/pf-parser.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
cd "$work"
check()
{
    name=$1
    expected=$2
    cat > "$name.conf"
    result=accept
    pfctl -n -f "$name.conf" > "$name.stdout" 2> "$name.stderr" || result=reject
    if [ "$result" != "$expected" ]; then
        cat "$name.stdout" "$name.stderr"
        echo "PF_PARSER_FAILURE $name expected=$expected actual=$result"
        exit 1
    fi
    echo "PF_PARSER_CASE $name $result"
}
check basic accept <<'RULES'
block all
pass out inet proto tcp to port 443 keep state
RULES
check macros_lists accept <<'RULES'
clients = "192.0.2.0/24"
ports = "{ 80, 443 }"
pass in inet proto tcp from $clients to any port $ports flags S/SA keep state
RULES
check quoted_label accept <<'RULES'
pass inet from 192.0.2.1 label "a label with spaces"
RULES
check ipv6 accept <<'RULES'
pass inet6 proto { tcp, udp } from 2001:db8::/32 to any port 53
RULES
check negation accept <<'RULES'
block in inet from ! 192.0.2.0/24 to any
RULES
check table accept <<'RULES'
table <clients> persist { 192.0.2.1, 2001:db8::1 }
pass from <clients>
RULES
check nested_anchors accept <<'RULES'
anchor "outer" {
    anchor "inner" {
        pass inet proto icmp
    }
}
RULES
printf 'included_net = "198.51.100.0/24"\n' > included.conf
check include accept <<'RULES'
include "included.conf"
pass from $included_net
RULES
check undefined_macro reject <<'RULES'
pass from $never_defined
RULES
check port_overflow reject <<'RULES'
pass proto tcp to port 65536
RULES
check invalid_prefix reject <<'RULES'
pass inet from 192.0.2.0/33
RULES
check missing_include reject <<'RULES'
include "missing-file.conf"
RULES
check invalid_action reject <<'RULES'
not_a_pf_action all
RULES
check unclosed_anchor reject <<'RULES'
anchor "unclosed" {
    pass
RULES
check invalid_state_limit reject <<'RULES'
pass keep state (max -1)
RULES
echo PF_PARSER_DONE 15
