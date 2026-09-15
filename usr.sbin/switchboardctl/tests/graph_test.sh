#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for switchboardctl graph: the IPC anointment reach graph drawn from
# the bundle registry on disk (docs/ipc-anointments-design.md, rows G1-G3).
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
}
