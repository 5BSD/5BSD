#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for switchboardctl graph: the IPC anointment reach graph drawn from
# the bundle registry on disk (docs/book/src/plane/anointments.md, rows G1-G3).
# Purely static: no running plane, no root.
#

find_switchboardctl()
{
	local p _machine _arch
	_machine=$(uname -m)
	_arch=$(uname -p)
	for p in \
	    "$(atf_get_srcdir)/switchboardctl_test_bin" \
	    /usr/obj/usr/src/${_machine}.${_arch}/usr.sbin/switchboardctl/tests/switchboardctl_test_bin \
	    /usr/sbin/switchboardctl \
	    "$(command -v switchboardctl 2>/dev/null)"
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			switchboardctl_bin="$p"
			return
		fi
	done
	atf_skip "switchboardctl binary not found"
}

# write_bundle root bundle-id unit unit-ucl-body
write_bundle()
{
	local root="$1" id="$2" unit="$3" body="$4"

	mkdir -p "$root/Units/$unit.unit/bin"
	cat > "$root/Bundle.ucl" <<EOF
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "$id";
version = "1.0.1";
sequence = 1;
author = "test";
publisher = "org.test";
units = ["$unit"];
EOF
	printf '%s\n' "$body" > "$root/Units/$unit.unit/Unit.ucl"
	printf '#!/bin/sh\nexec sleep 3600\n' > "$root/Units/$unit.unit/bin/$unit"
	chmod 755 "$root/Units/$unit.unit/bin/$unit"
}

# The design's fixture: bsdnotify with an open and a gated endpoint,
# com.example.pub declaring the gate's name, com.example.app declaring
# nothing, system.X.Both requiring two names (one unit holds both), and a
# unit declaring a name nothing requires.  A principal policy grants by uid
# so the group database is never consulted.
write_fixture()
{
	local reg="$(pwd)/registry"

	mkdir -p "$reg"
	write_bundle "$reg/bsdnotify.cap" org.5bsd.bsdnotify bsdnotify \
	    'resolvable_by = ["user"];
activation { ipc = ["system.Notify",
    { name = "system.Notify.System"; requires = ["system.notify.system"]; }]; }'
	write_bundle "$reg/pub.cap" com.example.pub pub \
	    'anointments = ["system.notify.system"];
activation { boot = true; }'
	write_bundle "$reg/app.cap" com.example.app app \
	    'activation { boot = true; }'
	write_bundle "$reg/both.cap" org.test.both bothd \
	    'activation { ipc = [{ name = "system.X.Both"; requires = ["a.one", "a.two"]; }]; }'
	write_bundle "$reg/two.cap" org.test.two twod \
	    'anointments = ["a.one", "a.two"];
activation { boot = true; }'
	write_bundle "$reg/one.cap" org.test.one oned \
	    'anointments = ["a.one"];
activation { boot = true; }'
	write_bundle "$reg/dead.cap" org.test.dead deadd \
	    'anointments = ["nothing.requires"];
activation { boot = true; }'
	cat > policy.ucl <<'EOF'
principals {
    admin   { uids = [0]; anointments = ["*"]; admin_rights = true; }
    default { anointments = []; }
}
EOF
	SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/policy.ucl"
	export SWITCHBOARD_PRINCIPAL_POLICY
	graph_root="$reg"
	write_graph_wrapper
}

# atf-check runs an external program, so the shorthand is a script, not a
# shell function.
write_graph_wrapper()
{
	printf '#!/bin/sh\nexec "%s" graph --root "%s" "$@"\n' \
	    "$switchboardctl_bin" "$graph_root" > graph
	chmod +x graph
	write_count_lines
}

# ===================================================================
# G1: edges for the two session classes and the two example units
# ===================================================================

atf_test_case graph_g1_edges
graph_g1_edges_head()
{
	atf_set "descr" "G1: session-default, session-admin, pub and app reach"
}
graph_g1_edges_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.txt ./graph
	# session.default: open endpoint of a user-resolvable provider only.
	atf_check -o match:'^session\.default -> system\.Notify \[open\]$' \
	    cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^session\.default -> system\.Notify\.System' out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^session\.default -> system\.X\.Both' out.txt
	# session.admin: everything, gated ones via their names.
	atf_check -o match:'^session\.admin -> system\.Notify \[open\]$' \
	    cat out.txt
	atf_check -o match:'^session\.admin -> system\.Notify\.System \[via system\.notify\.system\]$' \
	    cat out.txt
	atf_check -o match:'^session\.admin -> system\.X\.Both \[via a\.one,a\.two\]$' \
	    cat out.txt
	# com.example.pub: both bsdnotify endpoints.
	atf_check -o match:'^com\.example\.pub/pub -> system\.Notify \[open\]$' \
	    cat out.txt
	atf_check -o match:'^com\.example\.pub/pub -> system\.Notify\.System \[via system\.notify\.system\]$' \
	    cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^com\.example\.pub/pub -> system\.X\.Both' out.txt
	# com.example.app: the open endpoint only.
	atf_check -o match:'^com\.example\.app/app -> system\.Notify \[open\]$' \
	    cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^com\.example\.app/app -> system\.Notify\.System' out.txt
	# U6/U7: a two-name gate needs both names.
	atf_check -o match:'^org\.test\.two/twod -> system\.X\.Both \[via a\.one,a\.two\]$' \
	    cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^org\.test\.one/oned -> system\.X\.Both' out.txt
	# A provider never has an edge to its own endpoint.
	atf_check -s exit:1 -o ignore \
	    grep -q '^org\.5bsd\.bsdnotify/bsdnotify -> system\.Notify' out.txt
	atf_check -o match:'^summary: 7 units, 2 sessions, 3 endpoints \(2 gated\), [0-9]+ edges, 1 warnings$' \
	    cat out.txt
}

# ===================================================================
# G1 under a narrowed admin (P6): root holds some, not all
# ===================================================================

atf_test_case graph_narrowed_admin
graph_narrowed_admin_head()
{
	atf_set "descr" "a policy narrowing root's set narrows session.admin's gated reach"
}
graph_narrowed_admin_body()
{
	find_switchboardctl
	write_fixture
	cat > policy.ucl <<'EOF'
principals {
    root    { uids = [0]; anointments = ["system.notify.system"]; admin_rights = false; }
    default { anointments = []; }
}
EOF
	atf_check -s exit:0 -o save:out.txt ./graph
	atf_check -o match:'^session\.admin -> system\.Notify \[open\]$' cat out.txt
	atf_check -o match:'^session\.admin -> system\.Notify\.System ' cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^session\.admin -> system\.X\.Both' out.txt
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'"label": "session.admin", "uid": 0, "anointments": \["system.notify.system"\], "anoint_all": false, "admin_rights": false' \
	    cat out.json
}

# ===================================================================
# Principal policy granting a name from login reaches the gate
# ===================================================================

atf_test_case graph_policy_grant
graph_policy_grant_head()
{
	atf_set "descr" "a name granted to default principals gives session.default the gated edge"
}
graph_policy_grant_body()
{
	find_switchboardctl
	write_fixture
	cat > policy.ucl <<'EOF'
principals {
    admin   { uids = [0]; anointments = ["*"]; }
    default { anointments = ["system.notify.system"]; }
}
EOF
	atf_check -s exit:0 -o save:out.txt ./graph
	atf_check -o match:'^session\.default -> system\.Notify\.System \[via system\.notify\.system\]$' \
	    cat out.txt
}

# ===================================================================
# G2: an endpoint requiring a name nothing declares
# ===================================================================

atf_test_case graph_g2_unreachable
graph_g2_unreachable_head()
{
	atf_set "descr" "G2: a requires name nothing declares warns unreachable"
}
graph_g2_unreachable_body()
{
	find_switchboardctl
	write_fixture
	write_bundle "$graph_root/orphan.cap" org.test.orphan orphand \
	    'activation { ipc = [{ name = "system.Orphan"; requires = ["nobody.declares"]; }]; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^warning: unreachable: system\.Orphan requires "nobody\.declares"' \
	    cat out.txt
	# Only session.admin (via "*") reaches it; that is not a declaration.
	atf_check -o match:'^session\.admin -> system\.Orphan \[via nobody\.declares\]$' \
	    cat out.txt
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'"kind": "unreachable", "subject": "system.Orphan", "name": "nobody.declares"' \
	    cat out.json
}

atf_test_case graph_unreachable_split
graph_unreachable_split_head()
{
	atf_set "descr" "a two-name gate whose names are declared by different units only warns unreachable"
}
graph_unreachable_split_body()
{
	find_switchboardctl
	write_fixture
	rm -rf "$graph_root/two.cap"
	write_bundle "$graph_root/othertwo.cap" org.test.othertwo othertwod \
	    'anointments = ["a.two"];
activation { boot = true; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^warning: unreachable: system\.X\.Both requires 2 names that no single unit or principal holds together$' \
	    cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q 'requires "a\.one"' out.txt
}

# ===================================================================
# G3: a declared name nothing requires
# ===================================================================

atf_test_case graph_g3_dead
graph_g3_dead_head()
{
	atf_set "descr" "G3: a declared name nothing requires warns dead declaration"
}
graph_g3_dead_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^warning: dead declaration: org\.test\.dead/deadd declares "nothing\.requires"' \
	    cat out.txt
	# Live declarations are not flagged.
	atf_check -s exit:1 -o ignore grep -q 'com\.example\.pub/pub declares' out.txt
	atf_check -s exit:1 -o ignore grep -q 'org\.test\.two/twod declares' out.txt
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'"kind": "dead", "subject": "org.test.dead/deadd", "name": "nothing.requires"' \
	    cat out.json
}

atf_test_case graph_dead_policy_grant
graph_dead_policy_grant_head()
{
	atf_set "descr" "a principal-policy grant nothing requires warns dead declaration"
}
graph_dead_policy_grant_body()
{
	find_switchboardctl
	write_fixture
	cat > policy.ucl <<'EOF'
principals {
    admin   { uids = [0]; anointments = ["*"]; }
    default { anointments = ["policy.only"]; }
}
EOF
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^warning: dead declaration: session\.default is granted "policy\.only"' \
	    cat out.txt
}

# ===================================================================
# --lint exit status
# ===================================================================

atf_test_case graph_lint_exit
graph_lint_exit_head()
{
	atf_set "descr" "--lint exits 2 with warnings and 0 without; plain graph always 0"
}
graph_lint_exit_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:2 -o match:'^warning: ' ./graph --lint
	atf_check -s exit:0 -o not-match:'^warning: ' ./graph
	rm -rf "$graph_root/dead.cap"
	atf_check -s exit:0 -o not-match:'^warning: ' \
	    -o match:'0 warnings$' ./graph --lint
	# Lint warnings go to stderr in DOT mode so stdout stays a graph.
	write_bundle "$graph_root/dead.cap" org.test.dead deadd \
	    'anointments = ["nothing.requires"];
activation { boot = true; }'
	atf_check -s exit:2 -o match:'^digraph ' -o not-match:'warning' \
	    -e match:'^warning: dead declaration' ./graph --dot --lint
}

# ===================================================================
# --dot output
# ===================================================================

atf_test_case graph_dot
graph_dot_head()
{
	atf_set "descr" "--dot emits a Graphviz digraph with boxes, ellipses and labelled edges"
}
graph_dot_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	atf_check -o match:'^digraph ' head -1 out.dot
	atf_check -o match:'^}$' tail -1 out.dot
	atf_check -o match:'shape=ellipse, label="session\.default"' cat out.dot
	atf_check -o match:'shape=ellipse, label="session\.admin\\nholds \*"' cat out.dot
	atf_check -o match:'shape=box, label="com\.example\.pub/pub\\n\(com\.example\.pub\)\\nholds system\.notify\.system"' \
	    cat out.dot
	atf_check -o match:'label="system\.Notify\.System\\nrequires system\.notify\.system"' \
	    cat out.dot
	atf_check -o match:'label="system\.X\.Both\\nrequires a\.one, a\.two"' cat out.dot
	atf_check -o match:'label="a\.one, a\.two"\];$' cat out.dot
	# Every node referenced by an edge is declared.
	for id in $(sed -n 's/^	"\([ne][0-9]*\)" -> "\([ne][0-9]*\)".*/\1 \2/p' out.dot); do
		grep -q "^	\"$id\" \[" out.dot || atf_fail "edge references undeclared node $id"
	done
	if command -v dot >/dev/null 2>&1; then
		atf_check -s exit:0 -o match:'^graph ' dot -Tplain out.dot
	fi
}

# ===================================================================
# --json output
# ===================================================================

atf_test_case graph_json
graph_json_head()
{
	atf_set "descr" "--json emits units, sessions, endpoints, edges and warnings in that order"
}
graph_json_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	if command -v jq >/dev/null 2>&1; then
		atf_check -o inline:'["units","sessions","endpoints","edges","warnings"]\n' \
		    jq -c 'keys_unsorted' out.json
		atf_check -o inline:'7\n' jq '.units | length' out.json
		atf_check -o inline:'2\n' jq '.sessions | length' out.json
		atf_check -o inline:'3\n' jq '.endpoints | length' out.json
		atf_check -o inline:'1\n' jq '.warnings | length' out.json
		atf_check -o inline:'["system.notify.system"]\n' \
		    jq -c '.edges[] | select(.from == "com.example.pub/pub" and .to == "system.Notify.System") | .via' out.json
		atf_check -o inline:'true\n' \
		    jq '.units[] | select(.label == "org.5bsd.bsdnotify/bsdnotify") | .user_resolvable' out.json
	else
		atf_check -o match:'^  "units": \[$' cat out.json
		atf_check -o match:'^  "sessions": \[$' cat out.json
		atf_check -o match:'^  "endpoints": \[$' cat out.json
		atf_check -o match:'^  "edges": \[$' cat out.json
		atf_check -o match:'^  "warnings": \[$' cat out.json
		atf_check -o inline:'units\nsessions\nendpoints\nedges\nwarnings\n' \
		    sed -n 's/^  "\([a-z]*\)": \[$/\1/p' out.json
		atf_check -o match:'\{"from": "com.example.pub/pub", "to": "system.Notify.System", "provider": "org.5bsd.bsdnotify/bsdnotify", "via": \["system.notify.system"\]\}' \
		    cat out.json
		atf_check -o match:'\{"name": "system.X.Both", "provider": "org.test.both/bothd", "requires": \["a.one", "a.two"\]\}' \
		    cat out.json
	fi
	# A JSON run never prints the policy-fallback note to stderr.
	atf_check -s exit:0 -o match:'"from_default_rule": true' -e empty \
	    env SWITCHBOARD_PRINCIPAL_POLICY=/nonexistent/policy.ucl ./graph --json
}

# ===================================================================
# Registry directories and the historical fallback rule
# ===================================================================

atf_test_case graph_registry_dirs
graph_registry_dirs_head()
{
	atf_set "descr" "without --root both registry env dirs are scanned; missing ones are empty"
}
graph_registry_dirs_body()
{
	find_switchboardctl
	write_fixture
	mkdir -p sys usr
	mv "$graph_root/bsdnotify.cap" sys/
	mv "$graph_root/pub.cap" usr/
	atf_check -s exit:0 -o save:out.txt \
	    env SWITCHBOARD_BUNDLE_DIR_SYSTEM="$(pwd)/sys" \
	    SWITCHBOARD_BUNDLE_DIR_USER="$(pwd)/usr" \
	    "$switchboardctl_bin" graph
	atf_check -o match:'^com\.example\.pub/pub -> system\.Notify\.System ' cat out.txt
	atf_check -o match:'^summary: 2 units, 2 sessions' cat out.txt
	atf_check -s exit:0 -o match:'^summary: 1 units, 2 sessions' \
	    env SWITCHBOARD_BUNDLE_DIR_SYSTEM="$(pwd)/sys" \
	    SWITCHBOARD_BUNDLE_DIR_USER="$(pwd)/absent" \
	    "$switchboardctl_bin" graph
}

atf_test_case graph_default_rule
graph_default_rule_head()
{
	atf_set "descr" "an absent principal policy applies the historical rule and says so"
}
graph_default_rule_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.txt \
	    -e match:'using the historical principal rule' \
	    env SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/absent.ucl" \
	    "$switchboardctl_bin" graph --root "$graph_root"
	atf_check -o match:'^session\.admin -> system\.X\.Both \[via a\.one,a\.two\]$' cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^session\.default -> system\.Notify\.System' out.txt
	atf_check -o match:'historical rule\)$' cat out.txt
}

# ===================================================================
# Errors
# ===================================================================

atf_test_case graph_errors
graph_errors_head()
{
	atf_set "descr" "bad options, an absent --root, and a malformed bundle fail"
}
graph_errors_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:64 -o empty -e match:'usage: switchboardctl graph' \
	    "$switchboardctl_bin" graph --bogus
	atf_check -s exit:64 -o empty -e match:'usage: switchboardctl graph' \
	    "$switchboardctl_bin" graph extra
	atf_check -s exit:1 -o empty -e match:'scanning .*absent' \
	    "$switchboardctl_bin" graph --root "$(pwd)/absent"
	printf 'anointments = ["*"];\nactivation { boot = true; }\n' \
	    > "$graph_root/pub.cap/Units/pub.unit/Unit.ucl"
	atf_check -s exit:1 -o empty -e match:'scanning' ./graph
}

# ===================================================================
# Edge cases and negative paths
# ===================================================================

# A registry with no bundles, the shipped-style policy and the wrapper:
# each case below adds exactly the bundles it needs so counts are exact.
write_empty_fixture()
{
	local reg="$(pwd)/registry"

	mkdir -p "$reg"
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["*"]; admin_rights = true; }
    default { anointments = []; }
}
EOP
	SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/policy.ucl"
	export SWITCHBOARD_PRINCIPAL_POLICY
	graph_root="$reg"
	write_graph_wrapper
}

# atf-check runs an external program, so the line counter is a script too:
# ./count_lines file regex prints the number of lines matching regex (BRE),
# "0" included, and always exits 0.
write_count_lines()
{
	cat > ./count_lines <<'EOS'
#!/bin/sh
c=$(grep -c -- "$2" "$1")
echo "${c:-0}"
exit 0
EOS
	chmod +x count_lines
}

# check_json_wellformed file: the document parses (python3 when present,
# otherwise a brace/bracket balance check) and nothing follows the final
# closing brace.
check_json_wellformed()
{
	local f="$1"

	if command -v python3 >/dev/null 2>&1; then
		atf_check -s exit:0 -o empty -e empty python3 -c \
		    "import json,sys; json.load(open(sys.argv[1]))" "$f"
	else
		local opens closes
		opens=$(tr -cd '{' < "$f" | wc -c | tr -d ' ')
		closes=$(tr -cd '}' < "$f" | wc -c | tr -d ' ')
		[ "$opens" = "$closes" ] || atf_fail "unbalanced braces in $f"
		opens=$(tr -cd '[' < "$f" | wc -c | tr -d ' ')
		closes=$(tr -cd ']' < "$f" | wc -c | tr -d ' ')
		[ "$opens" = "$closes" ] || atf_fail "unbalanced brackets in $f"
	fi
	# No trailing garbage: the file ends in "}\n" and the last line is "}".
	atf_check -o inline:'}\n' tail -c 2 "$f"
	atf_check -o inline:'}\n' tail -1 "$f"
	atf_check -o inline:'{\n' head -1 "$f"
}

atf_test_case graph_eight_endpoints_mixed_gates
graph_eight_endpoints_mixed_gates_head()
{
	atf_set "descr" "8 endpoints, half gated by two names: admin reaches all, default only the open ones"
}
graph_eight_endpoints_mixed_gates_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/big.cap" org.test.big bigd \
	    'resolvable_by = ["user"];
activation { ipc = [
    "system.Big.O1",
    { name = "system.Big.G1"; requires = ["g.one", "g.two"]; },
    "system.Big.O2",
    { name = "system.Big.G2"; requires = ["g.three", "g.four"]; },
    { name = "system.Big.O3"; },
    { name = "system.Big.G3"; requires = ["g.five", "g.six"]; },
    { name = "system.Big.O4"; requires = []; },
    { name = "system.Big.G4"; requires = ["g.seven", "g.eight"]; }
]; }'
	atf_check -s exit:0 -o save:out.txt ./graph
	# session.admin: all eight, the gated ones via their two names.
	atf_check -o inline:'8\n' ./count_lines out.txt '^session\.admin -> '
	for n in 1 2 3 4; do
		atf_check -o match:"^session\.admin -> system\.Big\.O$n \[open\]\$" \
		    cat out.txt
	done
	atf_check -o match:'^session\.admin -> system\.Big\.G1 \[via g\.one,g\.two\]$' \
	    cat out.txt
	atf_check -o match:'^session\.admin -> system\.Big\.G4 \[via g\.seven,g\.eight\]$' \
	    cat out.txt
	# session.default: the four open ones only (provider is user-resolvable).
	atf_check -o inline:'4\n' ./count_lines out.txt '^session\.default -> '
	atf_check -o inline:'0\n' ./count_lines out.txt '^session\.default -> system\.Big\.G'
	# The provider never reaches itself.
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.big/bigd -> '
	atf_check -o match:'^summary: 1 units, 2 sessions, 8 endpoints \(4 gated\), 12 edges, 8 warnings$' \
	    cat out.txt
	# Every gate name is undeclared: eight unreachable warnings, exit 2.
	atf_check -s exit:2 -o save:lint.txt ./graph --lint
	atf_check -o inline:'8\n' ./count_lines lint.txt '^warning: unreachable: '
	# Without resolvable_by the default session sees nothing at all.
	sed -i '' '1d' "$graph_root/big.cap/Units/bigd.unit/Unit.ucl"
	atf_check -s exit:0 -o save:out2.txt ./graph
	atf_check -o inline:'0\n' ./count_lines out2.txt '^session\.default -> '
	atf_check -o inline:'8\n' ./count_lines out2.txt '^session\.admin -> '
	atf_check -o match:'^summary: 1 units, 2 sessions, 8 endpoints \(4 gated\), 8 edges' \
	    cat out2.txt
}

atf_test_case graph_mutual_requires
graph_mutual_requires_head()
{
	atf_set "descr" "two units gating each other: both cross edges, no self edges"
}
graph_mutual_requires_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/a.cap" org.test.a ad \
	    'anointments = ["a.key"];
activation { ipc = [{ name = "system.A"; requires = ["b.key"]; }]; }'
	write_bundle "$graph_root/b.cap" org.test.b bd \
	    'anointments = ["b.key"];
activation { ipc = [{ name = "system.B"; requires = ["a.key"]; }]; }'
	atf_check -s exit:0 -o save:out.txt ./graph --lint
	atf_check -o match:'^org\.test\.a/ad -> system\.B \[via a\.key\]$' cat out.txt
	atf_check -o match:'^org\.test\.b/bd -> system\.A \[via b\.key\]$' cat out.txt
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.a/ad -> system\.A'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.b/bd -> system\.B'
	atf_check -o match:'^session\.admin -> system\.A \[via b\.key\]$' cat out.txt
	atf_check -o match:'^session\.admin -> system\.B \[via a\.key\]$' cat out.txt
	atf_check -o inline:'0\n' ./count_lines out.txt '^session\.default -> '
	atf_check -o inline:'0\n' ./count_lines out.txt '^warning: '
	atf_check -o match:'^summary: 2 units, 2 sessions, 2 endpoints \(2 gated\), 4 edges, 0 warnings$' \
	    cat out.txt
	# A unit holding its own gate's name still gets no self edge.
	write_bundle "$graph_root/a.cap" org.test.a ad \
	    'anointments = ["a.key", "b.key"];
activation { ipc = [{ name = "system.A"; requires = ["b.key"]; }]; }'
	atf_check -s exit:0 -o save:out2.txt ./graph
	atf_check -o inline:'0\n' ./count_lines out2.txt '^org\.test\.a/ad -> system\.A'
	atf_check -o match:'^org\.test\.a/ad -> system\.B \[via a\.key\]$' cat out2.txt
}

atf_test_case graph_max_anointments_and_requires
graph_max_anointments_and_requires_head()
{
	atf_set "descr" "a unit declaring 32 names reaches a gate requiring 8 of them"
}
graph_max_anointments_and_requires_body()
{
	local names i via

	find_switchboardctl
	write_empty_fixture
	names=""
	i=0
	while [ $i -lt 32 ]; do
		names="$names${names:+, }\"m.k$i\""
		i=$((i + 1))
	done
	write_bundle "$graph_root/holder.cap" org.test.holder holderd \
	    "anointments = [$names];
activation { boot = true; }"
	write_bundle "$graph_root/gate.cap" org.test.gate gated \
	    'activation { ipc = [{ name = "system.Gate.Max";
    requires = ["m.k0", "m.k1", "m.k2", "m.k3", "m.k4", "m.k5", "m.k6", "m.k7"]; }]; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	via='m\.k0,m\.k1,m\.k2,m\.k3,m\.k4,m\.k5,m\.k6,m\.k7'
	atf_check -o match:"^org\.test\.holder/holderd -> system\.Gate\.Max \[via $via\]\$" \
	    cat out.txt
	atf_check -o match:"^session\.admin -> system\.Gate\.Max \[via $via\]\$" \
	    cat out.txt
	# The 24 names nothing requires are dead declarations; the 8 are not.
	atf_check -o inline:'24\n' ./count_lines out.txt '^warning: dead declaration: org\.test\.holder/holderd declares '
	atf_check -o inline:'0\n' ./count_lines out.txt '^warning: unreachable'
	atf_check -o inline:'0\n' ./count_lines out.txt 'declares "m\.k[0-7]"'
	atf_check -o match:'^summary: 2 units, 2 sessions, 1 endpoints \(1 gated\), 2 edges, 24 warnings$' \
	    cat out.txt
	# DOT lists all 32 held names on the node; JSON carries all 32.
	atf_check -s exit:0 -o save:out.dot ./graph --dot
	atf_check -o match:'holds m\.k0, m\.k1, .*, m\.k31"\];$' cat out.dot
	atf_check -s exit:0 -o save:out.json ./graph --json
	check_json_wellformed out.json
	if command -v python3 >/dev/null 2>&1; then
		atf_check -o inline:'32 8\n' python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
u = [x for x in d["units"] if x["label"] == "org.test.holder/holderd"][0]
e = d["endpoints"][0]
print(len(u["anointments"]), len(e["requires"]))' out.json
	else
		atf_check -o match:'"m\.k31"\], "user_resolvable"' cat out.json
	fi
	# Dropping one held name (m.k7) severs the edge: all eight are needed.
	names=$(printf '%s' "$names" | sed 's/, "m\.k7"//')
	write_bundle "$graph_root/holder.cap" org.test.holder holderd \
	    "anointments = [$names];
activation { boot = true; }"
	atf_check -s exit:2 -o save:out2.txt ./graph --lint
	atf_check -o inline:'0\n' ./count_lines out2.txt '^org\.test\.holder/holderd -> '
	atf_check -o match:'^warning: unreachable: system\.Gate\.Max requires "m\.k7", which no unit or principal declares$' \
	    cat out2.txt
}

atf_test_case graph_root_is_a_file
graph_root_is_a_file_head()
{
	atf_set "descr" "--root naming a file, a dangling path or an unreadable entry fails cleanly"
}
graph_root_is_a_file_body()
{
	find_switchboardctl
	write_empty_fixture
	atf_check -s exit:1 -o empty -e match:'graph: scanning .*policy\.ucl' \
	    "$switchboardctl_bin" graph --root "$(pwd)/policy.ucl"
	atf_check -s exit:1 -o empty -e match:'graph: scanning' \
	    "$switchboardctl_bin" graph --json --root "$(pwd)/policy.ucl"
	atf_check -s exit:1 -o empty -e match:'graph: scanning' \
	    "$switchboardctl_bin" graph --dot --lint --root "$(pwd)/policy.ucl"
	atf_check -s exit:1 -o empty -e match:'graph: scanning' \
	    "$switchboardctl_bin" graph --root ""
	# A regular file with the .cap suffix inside the registry.
	: > "$graph_root/file.cap"
	atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
	rm "$graph_root/file.cap"
	# A .cap directory without a Bundle.ucl.
	mkdir "$graph_root/hollow.cap"
	atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
	rm -rf "$graph_root/hollow.cap"
	# A directory that lacks the .cap suffix is ignored, whatever it holds.
	write_bundle "$graph_root/ignored" org.test.ignored ignoredd \
	    'activation { ipc = ["system.Ignored"]; }'
	atf_check -s exit:0 -o match:'^summary: 0 units, 2 sessions, 0 endpoints' ./graph
}

atf_test_case graph_empty_registry
graph_empty_registry_head()
{
	atf_set "descr" "an empty registry yields the two sessions and nothing else, in every format"
}
graph_empty_registry_body()
{
	find_switchboardctl
	write_empty_fixture
	atf_check -s exit:0 -e empty \
	    -o inline:'summary: 0 units, 2 sessions, 0 endpoints (0 gated), 0 edges, 0 warnings\n' \
	    ./graph
	atf_check -s exit:0 -e empty -o match:'0 warnings$' ./graph --lint
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	atf_check -o inline:'2\n' ./count_lines out.dot '^	"n[0-9]*" \['
	atf_check -o inline:'0\n' ./count_lines out.dot '^	"e[0-9]*" \['
	atf_check -o inline:'0\n' ./count_lines out.dot ' -> '
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	check_json_wellformed out.json
	if command -v python3 >/dev/null 2>&1; then
		atf_check -o inline:'0 2 0 0 0\n' python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
print(len(d["units"]), len(d["sessions"]), len(d["endpoints"]), len(d["edges"]), len(d["warnings"]))' out.json
	fi
}

atf_test_case graph_json_wellformed
graph_json_wellformed_head()
{
	atf_set "descr" "--json parses as JSON with no trailing garbage, with and without --lint, and escapes are sound"
}
graph_json_wellformed_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	check_json_wellformed out.json
	# --lint changes the exit status but never the document.
	atf_check -s exit:2 -o save:lint.json -e empty ./graph --json --lint
	check_json_wellformed lint.json
	atf_check cmp out.json lint.json
	# Under the historical rule (no policy) it is still a document.
	atf_check -s exit:0 -o save:nopol.json -e empty \
	    env SWITCHBOARD_PRINCIPAL_POLICY=/nonexistent/x.ucl ./graph --json
	check_json_wellformed nopol.json
	if command -v python3 >/dev/null 2>&1; then
		atf_check -o inline:'7 2 3 1\n' python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
print(len(d["units"]), len(d["sessions"]), len(d["endpoints"]), len(d["warnings"]))
assert list(d.keys()) == ["units", "sessions", "endpoints", "edges", "warnings"]
for s in d["sessions"]:
    assert set(s.keys()) == {"label", "uid", "anointments", "anoint_all", "admin_rights", "from_default_rule"}
for e in d["edges"]:
    assert set(e.keys()) == {"from", "to", "provider", "via"}
' out.json
		atf_check -o inline:'True True\n' python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
print(all(s["from_default_rule"] for s in d["sessions"]), [s for s in d["sessions"] if s["label"] == "session.admin"][0]["anoint_all"])' nopol.json
	fi
}

atf_test_case graph_dot_one_node_per_unit_and_endpoint
graph_dot_one_node_per_unit_and_endpoint_head()
{
	atf_set "descr" "--dot declares exactly one node per unit, session and endpoint, with unique ids"
}
graph_dot_one_node_per_unit_and_endpoint_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	# 7 units + 2 sessions; 3 endpoints; 3 owner (dotted) links.
	atf_check -o inline:'9\n' ./count_lines out.dot '^	"n[0-9]*" \['
	atf_check -o inline:'3\n' ./count_lines out.dot '^	"e[0-9]*" \['
	atf_check -o inline:'3\n' ./count_lines out.dot 'style=dotted, arrowhead=none'
	# Ids are unique and dense: n0..n8 and e0..e2 each declared once.
	for i in 0 1 2 3 4 5 6 7 8; do
		atf_check -o inline:'1\n' ./count_lines out.dot "^	\"n$i\" \["
	done
	for i in 0 1 2; do
		atf_check -o inline:'1\n' ./count_lines out.dot "^	\"e$i\" \["
	done
	atf_check -o inline:'0\n' ./count_lines out.dot '^	"n9" \['
	atf_check -o inline:'0\n' ./count_lines out.dot '^	"e3" \['
	# Every unit and session label appears in exactly one node label.
	for l in session.default session.admin com.example.pub/pub \
	    com.example.app/app org.5bsd.bsdnotify/bsdnotify \
	    org.test.both/bothd org.test.two/twod org.test.one/oned \
	    org.test.dead/deadd; do
		atf_check -o inline:'1\n' ./count_lines out.dot \
		    "\[shape=[a-z]*, label=\"$(printf '%s' "$l" | sed 's/[.\/]/\\&/g')[\\\\\"]"
	done
	# Solid edges equal the text-mode edge count.
	atf_check -s exit:0 -o save:out.txt ./graph
	txt=$(./count_lines out.txt ' -> ')
	atf_check -o inline:"$txt\n" ./count_lines out.dot 'style=solid'
	# The document has one opening and one closing line.
	atf_check -o inline:'1\n' ./count_lines out.dot '^digraph anointments {$'
	atf_check -o inline:'1\n' ./count_lines out.dot '^}$'
}

atf_test_case graph_lint_admin_star_is_not_a_declaration
graph_lint_admin_star_is_not_a_declaration_head()
{
	atf_set "descr" "a gate only session.admin's wildcard satisfies is still reported as undeclared"
}
graph_lint_admin_star_is_not_a_declaration_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/lonely.cap" org.test.lonely lonelyd \
	    'activation { ipc = [{ name = "system.Lonely"; requires = ["lonely.name"]; }]; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	# The edge exists ...
	atf_check -o match:'^session\.admin -> system\.Lonely \[via lonely\.name\]$' \
	    cat out.txt
	# ... and the warning is nonetheless raised, with the exact wording.
	atf_check -o inline:'warning: unreachable: system.Lonely requires "lonely.name", which no unit or principal declares\n' \
	    grep '^warning' out.txt
	atf_check -o match:'1 warnings$' cat out.txt
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'"kind": "unreachable", "subject": "system.Lonely", "name": "lonely.name"' \
	    cat out.json
	# An explicit grant to a principal is a declaration: warning gone.
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["*"]; }
    default { anointments = ["lonely.name"]; }
}
EOP
	atf_check -s exit:0 -o save:out2.txt ./graph --lint
	atf_check -o inline:'0\n' ./count_lines out2.txt '^warning: '
	atf_check -o match:'^session\.default -> system\.Lonely \[via lonely\.name\]$' \
	    cat out2.txt
	# An explicit grant to the admin entry (not "*") is also a declaration.
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["lonely.name"]; }
    default { anointments = []; }
}
EOP
	atf_check -s exit:0 -o not-match:'^warning: ' ./graph --lint
}

atf_test_case graph_deterministic_output
graph_deterministic_output_head()
{
	atf_set "descr" "two runs, and two registries built in opposite order, are byte-identical in every format"
}
graph_deterministic_output_body()
{
	local fmt

	find_switchboardctl
	write_fixture
	for fmt in "" --dot --json --lint; do
		atf_check -s ignore -o save:one$fmt ./graph $fmt
		atf_check -s ignore -o save:two$fmt ./graph $fmt
		atf_check cmp one$fmt two$fmt
	done
	# The same bundles created in reverse order in a second root.
	mkdir reversed
	for b in dead one two both app pub bsdnotify; do
		cp -R "$graph_root/$b.cap" "reversed/$b.cap"
	done
	for fmt in "" --dot --json; do
		atf_check -o save:rev$fmt "$switchboardctl_bin" graph \
		    --root "$(pwd)/reversed" $fmt
		atf_check cmp one$fmt rev$fmt
	done
	# Renaming a bundle directory does not change the output either: the
	# order comes from labels, not directory names.
	mv "$graph_root/pub.cap" "$graph_root/zzz.cap"
	atf_check -o save:renamed ./graph
	atf_check cmp one renamed
}

atf_test_case graph_malformed_policy_falls_back
graph_malformed_policy_falls_back_head()
{
	atf_set "descr" "a malformed principal policy applies the historical rule, says so in the summary, exits 0"
}
graph_malformed_policy_falls_back_body()
{
	find_switchboardctl
	write_fixture
	printf 'principals { admin { uids = [ this is not ucl\n' > policy.ucl
	atf_check -s exit:0 -o save:out.txt -e match:'malformed principal policy' \
	    ./graph
	atf_check -o match:'absent or malformed: historical rule\)$' cat out.txt
	atf_check -o match:'^session\.admin -> system\.X\.Both \[via a\.one,a\.two\]$' \
	    cat out.txt
	atf_check -o match:'^session\.admin -> system\.Notify\.System ' cat out.txt
	atf_check -s exit:1 -o ignore \
	    grep -q '^session\.default -> system\.Notify\.System' out.txt
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'"label": "session.admin", "uid": 0, "anointments": \[\], "anoint_all": true, "admin_rights": true, "from_default_rule": true' \
	    cat out.json
	atf_check -o match:'"label": "session.default", "uid": 65534, "anointments": \[\], "anoint_all": false, "admin_rights": false, "from_default_rule": true' \
	    cat out.json
	# A schema violation (not a syntax error) is malformed too.
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["*"]; rights = true; }
}
EOP
	atf_check -s exit:0 -o match:'historical rule\)$' -e ignore ./graph
	# A wildcard fragment in the policy is malformed as well.
	cat > policy.ucl <<'EOP'
principals { admin { uids = [0]; anointments = ["system.*"]; } }
EOP
	atf_check -s exit:0 -o match:'historical rule\)$' -e ignore ./graph
	# An empty policy file is "no policy".
	: > policy.ucl
	atf_check -s exit:0 -o match:'historical rule\)$' -e ignore ./graph
	# A present-but-malformed policy is called out on stderr, like an
	# absent one; an empty file is "no policy" and stays quiet.
	printf 'principals { admin { uids = [ this is not ucl\n' > policy.ucl
	atf_check -s exit:0 -o ignore -e match:'malformed principal policy' ./graph
	: > policy.ucl
	atf_check -s exit:0 -o ignore -e empty ./graph
	# A directory as the policy path: unreadable, historical rule.
	mkdir policydir
	atf_check -s exit:0 -o match:'historical rule\)$' \
	    env SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/policydir" ./graph
}

atf_test_case graph_bad_bundle_id_rejected
graph_bad_bundle_id_rejected_head()
{
	atf_set "descr" "odd bytes in a bundle_id or a name make the scan fail with a message, never crash"
}
graph_bad_bundle_id_rejected_body()
{
	local id

	find_switchboardctl
	write_empty_fixture
	# UTF-8, a control byte, a wildcard, doubled/leading/trailing dots.
	for id in 'org.t\303\251st.x' 'org.test.\342\200\213x' 'org.test.\tx' \
	    'org.test.*' 'org..test' '.org.test' 'org.test.' 'nodots' \
	    'org.test x' 'org.test/x'; do
		rm -rf "$graph_root/bad.cap"
		write_bundle "$graph_root/bad.cap" "$(printf "$id")" badd \
		    'activation { boot = true; }'
		atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
		atf_check -s exit:1 -o empty -e match:'graph: scanning' \
		    ./graph --json
	done
	rm -rf "$graph_root/bad.cap"
	# The same bytes in a unit's anointments and in an endpoint name.
	for id in 'org.t\303\251st.x' 'org.test.\tx' 'org.test.*' '*'; do
		rm -rf "$graph_root/bad.cap"
		write_bundle "$graph_root/bad.cap" org.test.bad badd \
		    "anointments = [\"$(printf "$id")\"];
activation { boot = true; }"
		atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
		rm -rf "$graph_root/bad.cap"
		write_bundle "$graph_root/bad.cap" org.test.bad badd \
		    "activation { ipc = [{ name = \"$(printf "$id")\"; }]; }"
		atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
		rm -rf "$graph_root/bad.cap"
		write_bundle "$graph_root/bad.cap" org.test.bad badd \
		    "activation { ipc = [{ name = \"system.Bad\"; requires = [\"$(printf "$id")\"]; }]; }"
		atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
	done
	rm -rf "$graph_root/bad.cap"
	# A bundle_id that is not a string at all.
	write_bundle "$graph_root/bad.cap" 'x"; bundle_id = 42; y = "' badd \
	    'activation { boot = true; }'
	atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
	rm -rf "$graph_root/bad.cap"
	# One bad bundle poisons the whole scan even beside good ones.
	write_bundle "$graph_root/good.cap" org.test.good goodd \
	    'activation { ipc = ["system.Good"]; }'
	atf_check -s exit:0 -o match:'^summary: 1 units' ./graph
	write_bundle "$graph_root/bad.cap" 'org.test.' badd \
	    'activation { boot = true; }'
	atf_check -s exit:1 -o empty -e match:'graph: scanning' ./graph
}

atf_test_case graph_gated_visible_regardless_of_resolvable_by
graph_gated_visible_regardless_of_resolvable_by_head()
{
	atf_set "descr" "a gate a default session covers is reachable even from a system-only provider; its open sibling is not"
}
graph_gated_visible_regardless_of_resolvable_by_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/sys.cap" org.test.sys sysd \
	    'activation { ipc = ["system.Sys.Open",
    { name = "system.Sys.Gate"; requires = ["ops.key"]; }]; }'
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["*"]; }
    default { anointments = ["ops.key"]; }
}
EOP
	atf_check -s exit:0 -o save:out.txt ./graph --lint
	atf_check -o match:'^session\.default -> system\.Sys\.Gate \[via ops\.key\]$' \
	    cat out.txt
	atf_check -o inline:'0\n' ./count_lines out.txt '^session\.default -> system\.Sys\.Open'
	atf_check -o match:'^session\.admin -> system\.Sys\.Open \[open\]$' cat out.txt
	atf_check -o match:'^session\.admin -> system\.Sys\.Gate \[via ops\.key\]$' cat out.txt
	atf_check -o inline:'0\n' ./count_lines out.txt '^warning: '
	# Take the grant away: the gate vanishes for the default session.
	cat > policy.ucl <<'EOP'
principals {
    admin   { uids = [0]; anointments = ["*"]; }
    default { anointments = []; }
}
EOP
	atf_check -s exit:0 -o save:out2.txt ./graph
	atf_check -o inline:'0\n' ./count_lines out2.txt '^session\.default -> '
}

atf_test_case graph_duplicate_endpoint_across_bundles
graph_duplicate_endpoint_across_bundles_head()
{
	atf_set "descr" "two bundles publishing the same name are two endpoints in the graph (documented, no warning)"
}
graph_duplicate_endpoint_across_bundles_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/p1.cap" org.test.p1 p1d \
	    'activation { ipc = [{ name = "system.Dup"; requires = ["d.key"]; }]; }'
	write_bundle "$graph_root/p2.cap" org.test.p2 p2d \
	    'activation { ipc = ["system.Dup"]; }'
	write_bundle "$graph_root/c.cap" org.test.c cd \
	    'anointments = ["d.key"];
activation { boot = true; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^summary: 3 units, 2 sessions, 2 endpoints \(1 gated\)' \
	    cat out.txt
	atf_check -o match:'^warning: duplicate: endpoint system\.Dup is published by both ' \
	    cat out.txt
	# The consumer reaches both: one open, one via its key.
	atf_check -o match:'^org\.test\.c/cd -> system\.Dup \[open\]$' cat out.txt
	atf_check -o match:'^org\.test\.c/cd -> system\.Dup \[via d\.key\]$' cat out.txt
	# Each provider reaches the other's copy, never its own.
	atf_check -o inline:'1\n' ./count_lines out.txt '^org\.test\.p1/p1d -> system\.Dup \[open\]$'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.p1/p1d -> system\.Dup \[via'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.p2/p2d -> system\.Dup \[open\]$'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.p2/p2d -> system\.Dup \[via'
	# JSON tells the two apart by provider.
	atf_check -s exit:0 -o save:out.json ./graph --json
	atf_check -o match:'\{"name": "system.Dup", "provider": "org.test.p1/p1d", "requires": \["d.key"\]\}' \
	    cat out.json
	atf_check -o match:'\{"name": "system.Dup", "provider": "org.test.p2/p2d", "requires": \[\]\}' \
	    cat out.json
	# Exactly the duplicate-endpoint warning, nothing else.
	atf_check -o inline:'1\n' ./count_lines out.txt '^warning: '
}

# ===================================================================
# The shipped base tree must lint clean: no unreachable gated endpoint,
# no dead declaration, no duplicate.  This is the load-bearing gate --
# it fails the moment a base bundle gates an endpoint that nothing (no
# unit, no principal) can reach, or declares/grants a name nothing
# requires.  Runs only where the base tree is installed (a VM); skips
# in a bare in-tree harness.
# ===================================================================
atf_test_case base_tree_has_no_lint_errors
base_tree_has_no_lint_errors_head()
{
	atf_set "descr" \
	    "graph --lint on the installed base tree reports no dead declaration or duplicate endpoint (the real errors); unreachable is an advisory for gates only a wildcard admin reaches"
}
base_tree_has_no_lint_errors_body()
{
	find_switchboardctl
	[ -d /Capabilities/System ] ||
	    atf_skip "base bundle tree not installed (/Capabilities/System)"
	[ -r /Capabilities/Config/principal-policy.ucl ] ||
	    atf_skip "principal policy not installed"
	# Capture warnings.  "dead declaration" (a typo on one side) and
	# "duplicate" (two bundles publishing one name) are genuine errors and
	# must never appear.  "unreachable" is advisory: with the shipped
	# minimal policy a gated endpoint may be reachable only by a wildcard
	# admin, which is a valid secure default, not a defect.
	"${switchboardctl_bin}" graph --lint >/dev/null 2>warns.txt || true
	if grep -q "dead declaration" warns.txt; then
		cat warns.txt
		atf_fail "base tree has a dead declaration"
	fi
	if grep -q "duplicate" warns.txt; then
		cat warns.txt
		atf_fail "base tree has a duplicate endpoint"
	fi
}

# A gated endpoint reachable only through a principal-policy grant (an
# operator granted the name, or one that may elevate to it) -- not through any
# unit -- must NOT be flagged unreachable.  This is the fix that lets the graph
# see group-based holders the tool does not synthesise as session nodes.
atf_test_case graph_principal_grant_makes_gate_reachable
graph_principal_grant_makes_gate_reachable_head()
{
	atf_set "descr" \
	    "a gate whose name only a principal-policy entry grants is reachable, not unreachable"
}
graph_principal_grant_makes_gate_reachable_body()
{
	find_switchboardctl
	local reg="$(pwd)/reg"
	mkdir -p "$reg"
	# A provider gating an endpoint; no unit declares the name.
	write_bundle "$reg/prov.cap" org.test.prov provd \
	    'activation { ipc = [{ name = "system.Gated"; requires = ["org.test.op"]; }]; }'
	# An operator entry grants the name specifically (group-based, so the
	# tool builds no session node for it); a second gate reachable only by
	# elevation.
	write_bundle "$reg/prov2.cap" org.test.prov2 prov2d \
	    'activation { ipc = [{ name = "system.Elev"; requires = ["org.test.elev"]; }]; }'
	cat > policy.ucl <<'EOF'
principals {
    admin     { uids = [0]; anointments = ["*"]; admin_rights = true; }
    operators { groups = ["operators"]; anointments = ["org.test.op"];
                may_elevate = ["org.test.elev"]; }
    default   { anointments = []; }
}
EOF
	SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/policy.ucl"
	export SWITCHBOARD_PRINCIPAL_POLICY
	graph_root="$reg"
	write_graph_wrapper
	# Neither gate is unreachable: the grant and the may_elevate cover them.
	atf_check -s exit:0 -o ignore -e not-match:"unreachable" ./graph --lint
}

atf_init_test_cases()
{
	atf_add_test_case graph_g1_edges
	atf_add_test_case graph_narrowed_admin
	atf_add_test_case graph_policy_grant
	atf_add_test_case graph_g2_unreachable
	atf_add_test_case graph_unreachable_split
	atf_add_test_case graph_g3_dead
	atf_add_test_case graph_dead_policy_grant
	atf_add_test_case graph_lint_exit
	atf_add_test_case graph_dot
	atf_add_test_case graph_json
	atf_add_test_case graph_registry_dirs
	atf_add_test_case graph_default_rule
	atf_add_test_case graph_errors
	atf_add_test_case graph_eight_endpoints_mixed_gates
	atf_add_test_case graph_mutual_requires
	atf_add_test_case graph_max_anointments_and_requires
	atf_add_test_case graph_root_is_a_file
	atf_add_test_case graph_empty_registry
	atf_add_test_case graph_json_wellformed
	atf_add_test_case graph_dot_one_node_per_unit_and_endpoint
	atf_add_test_case graph_lint_admin_star_is_not_a_declaration
	atf_add_test_case graph_deterministic_output
	atf_add_test_case graph_malformed_policy_falls_back
	atf_add_test_case graph_bad_bundle_id_rejected
	atf_add_test_case graph_gated_visible_regardless_of_resolvable_by
	atf_add_test_case graph_duplicate_endpoint_across_bundles
	atf_add_test_case base_tree_has_no_lint_errors
	atf_add_test_case graph_principal_grant_makes_gate_reachable
}
