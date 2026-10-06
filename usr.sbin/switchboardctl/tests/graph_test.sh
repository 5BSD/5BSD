#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for switchboardctl graph: the IPC attribute reach graph drawn from
# the bundle registry on disk (docs/book/src/plane/attributes.md, rows G1-G3).
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
# unit declaring an attribute nothing requires.
write_fixture()
{
	local reg="$(pwd)/registry"

	mkdir -p "$reg"
	write_bundle "$reg/bsdnotify.cap" org.5bsd.bsdnotify bsdnotify \
	    'visible = ["user"];
activation { ipc = ["system.Notify",
    { name = "system.Notify.System"; requires = ["system.notify.system"]; }]; }'
	write_bundle "$reg/pub.cap" com.example.pub pub \
	    'attributes = ["system.notify.system"];
activation { boot = true; }'
	write_bundle "$reg/app.cap" com.example.app app \
	    'activation { boot = true; }'
	write_bundle "$reg/both.cap" org.test.both bothd \
	    'activation { ipc = [{ name = "system.X.Both"; requires = ["a.one", "a.two"]; }]; }'
	write_bundle "$reg/two.cap" org.test.two twod \
	    'attributes = ["a.one", "a.two"];
activation { boot = true; }'
	write_bundle "$reg/one.cap" org.test.one oned \
	    'attributes = ["a.one"];
activation { boot = true; }'
	write_bundle "$reg/dead.cap" org.test.dead deadd \
	    'attributes = ["nothing.requires"];
activation { boot = true; }'
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
# G1: edges for software clients
# ===================================================================

atf_test_case graph_g1_edges
graph_g1_edges_head()
{
	atf_set "descr" "Software clients must hold every required attribute"
}
graph_g1_edges_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.txt ./graph
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
	atf_check -o match:'^summary: 7 units, 3 endpoints \(2 gated\), [0-9]+ edges, 1 warnings$' \
	    cat out.txt
}

# ===================================================================
# G1 under a narrowed admin (P6): root holds some, not all
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
	# No software declares the required attribute.
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
	    'attributes = ["a.two"];
activation { boot = true; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^warning: unreachable: system\.X\.Both requires 2 names that no single unit holds together$' \
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
	    'attributes = ["nothing.requires"];
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
	atf_set "descr" "--dot emits a Graphviz digraph with software boxes and labelled edges"
}
graph_dot_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	atf_check -o match:'^digraph ' head -1 out.dot
	atf_check -o match:'^}$' tail -1 out.dot
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
	atf_set "descr" "JSON reports software units, attributes, endpoints and edges"
}
graph_json_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	check_json_wellformed out.json
	atf_check -o inline:'units\nendpoints\nedges\nwarnings\n' \
	    sed -n 's/^  "\([a-z]*\)": \[$/\1/p' out.json
	atf_check -o match:'"attributes": \["system.notify.system"\]' cat out.json
	atf_check -s exit:1 -o ignore grep -E 'sessions|anointments|admin_rights|from_default_rule' out.json

}

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
	atf_check -o match:'^summary: 2 units' cat out.txt
	atf_check -s exit:0 -o match:'^summary: 1 units' \
	    env SWITCHBOARD_BUNDLE_DIR_SYSTEM="$(pwd)/sys" \
	    SWITCHBOARD_BUNDLE_DIR_USER="$(pwd)/absent" \
	    "$switchboardctl_bin" graph
}

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
	printf 'attributes = ["*"];\nactivation { boot = true; }\n' \
	    > "$graph_root/pub.cap/Units/pub.unit/Unit.ucl"
	atf_check -s exit:1 -o empty -e match:'scanning' ./graph
}

# ===================================================================
# Edge cases and negative paths
# ===================================================================

# A registry with no bundles and the wrapper:
# each case below adds exactly the bundles it needs so counts are exact.
write_empty_fixture()
{
	local reg="$(pwd)/registry"

	mkdir -p "$reg"
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
	atf_set "descr" "Eight endpoints require attributes on actual software clients"
}
graph_eight_endpoints_mixed_gates_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/big.cap" org.test.big bigd \
	    'activation { ipc = ["system.Big.O1", "system.Big.O2", "system.Big.O3", "system.Big.O4",
{name="system.Big.G1";requires=["g.one","g.two"];},
{name="system.Big.G2";requires=["g.one","g.two"];},
{name="system.Big.G3";requires=["g.one","g.two"];},
{name="system.Big.G4";requires=["g.one","g.two"];}]; }'
	write_bundle "$graph_root/client.cap" org.test.client client \
	    'program="client"; activation {exec=true;} attributes=["g.one","g.two"];'
	write_bundle "$graph_root/plain.cap" org.test.plain plain \
	    'program="plain"; activation {exec=true;}'
	atf_check -s exit:0 -o save:out.txt -e empty ./graph --lint
	atf_check -o inline:'8\n' ./count_lines out.txt '^org\.test\.client/client -> '
	atf_check -o inline:'4\n' ./count_lines out.txt '^org\.test\.plain/plain -> '
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.plain/plain -> system\.Big\.G'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.big/bigd -> '

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
	    'attributes = ["a.key"];
activation { ipc = [{ name = "system.A"; requires = ["b.key"]; }]; }'
	write_bundle "$graph_root/b.cap" org.test.b bd \
	    'attributes = ["b.key"];
activation { ipc = [{ name = "system.B"; requires = ["a.key"]; }]; }'
	atf_check -s exit:0 -o save:out.txt ./graph --lint
	atf_check -o match:'^org\.test\.a/ad -> system\.B \[via a\.key\]$' cat out.txt
	atf_check -o match:'^org\.test\.b/bd -> system\.A \[via b\.key\]$' cat out.txt
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.a/ad -> system\.A'
	atf_check -o inline:'0\n' ./count_lines out.txt '^org\.test\.b/bd -> system\.B'
	atf_check -o inline:'0\n' ./count_lines out.txt '^warning: '
	atf_check -o match:'^summary: 2 units, 2 endpoints \(2 gated\), 2 edges, 0 warnings$' \
	    cat out.txt
	# A unit holding its own gate's name still gets no self edge.
	write_bundle "$graph_root/a.cap" org.test.a ad \
	    'attributes = ["a.key", "b.key"];
activation { ipc = [{ name = "system.A"; requires = ["b.key"]; }]; }'
	atf_check -s exit:0 -o save:out2.txt ./graph
	atf_check -o inline:'0\n' ./count_lines out2.txt '^org\.test\.a/ad -> system\.A'
	atf_check -o match:'^org\.test\.a/ad -> system\.B \[via a\.key\]$' cat out2.txt
}

atf_test_case graph_max_attributes_and_requires
graph_max_attributes_and_requires_head()
{
	atf_set "descr" "a unit declaring 32 names reaches a gate requiring 8 of them"
}
graph_max_attributes_and_requires_body()
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
	    "attributes = [$names];
activation { boot = true; }"
	write_bundle "$graph_root/gate.cap" org.test.gate gated \
	    'activation { ipc = [{ name = "system.Gate.Max";
    requires = ["m.k0", "m.k1", "m.k2", "m.k3", "m.k4", "m.k5", "m.k6", "m.k7"]; }]; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	via='m\.k0,m\.k1,m\.k2,m\.k3,m\.k4,m\.k5,m\.k6,m\.k7'
	atf_check -o match:"^org\.test\.holder/holderd -> system\.Gate\.Max \[via $via\]\$" \
	    cat out.txt
	    cat out.txt
	# The 24 names nothing requires are dead declarations; the 8 are not.
	atf_check -o inline:'24\n' ./count_lines out.txt '^warning: dead declaration: org\.test\.holder/holderd declares '
	atf_check -o inline:'0\n' ./count_lines out.txt '^warning: unreachable'
	atf_check -o inline:'0\n' ./count_lines out.txt 'declares "m\.k[0-7]"'
	atf_check -o match:'^summary: 2 units, 1 endpoints \(1 gated\), 1 edges, 24 warnings$' \
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
print(len(u["attributes"]), len(e["requires"]))' out.json
	else
		atf_check -o match:'"m\.k31"\], "user_resolvable"' cat out.json
	fi
	# Dropping one held name (m.k7) severs the edge: all eight are needed.
	names=$(printf '%s' "$names" | sed 's/, "m\.k7"//')
	write_bundle "$graph_root/holder.cap" org.test.holder holderd \
	    "attributes = [$names];
activation { boot = true; }"
	atf_check -s exit:2 -o save:out2.txt ./graph --lint
	atf_check -o inline:'0\n' ./count_lines out2.txt '^org\.test\.holder/holderd -> '
	atf_check -o match:'^warning: unreachable: system\.Gate\.Max requires "m\.k7", which no unit declares$' \
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
	atf_check -s exit:0 -o match:'^summary: 0 units, 0 endpoints' ./graph
}

atf_test_case graph_empty_registry
graph_empty_registry_head()
{
	atf_set "descr" "Empty registry produces empty software graph in every format"
}
graph_empty_registry_body()
{
	find_switchboardctl
	write_empty_fixture
	atf_check -s exit:0 -e empty -o inline:'summary: 0 units, 0 endpoints (0 gated), 0 edges, 0 warnings\n' ./graph
	atf_check -s exit:0 -e empty -o match:'0 warnings$' ./graph --lint
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	atf_check -o inline:'0\n' ./count_lines out.dot 'shape='
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	check_json_wellformed out.json
	atf_check -s exit:1 -o ignore grep 'session' out.json

}

atf_test_case graph_json_wellformed
graph_json_wellformed_head()
{
	atf_set "descr" "Lint preserves JSON and retired principal policy has no effect"
}
graph_json_wellformed_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.json -e empty ./graph --json
	check_json_wellformed out.json
	atf_check -s exit:2 -o save:lint.json -e empty ./graph --json --lint
	atf_check cmp out.json lint.json
	printf 'not valid policy' > retired-policy
	atf_check -s exit:0 -o save:ignored.json -e empty \
	    env SWITCHBOARD_PRINCIPAL_POLICY="$(pwd)/retired-policy" ./graph --json
	atf_check cmp out.json ignored.json

}

atf_test_case graph_dot_one_node_per_unit_and_endpoint
graph_dot_one_node_per_unit_and_endpoint_head()
{
	atf_set "descr" "--dot declares exactly one node per unit and endpoint, with unique ids"
}
graph_dot_one_node_per_unit_and_endpoint_body()
{
	find_switchboardctl
	write_fixture
	atf_check -s exit:0 -o save:out.dot -e empty ./graph --dot
	# 7 units; 3 endpoints; 3 owner (dotted) links.
	atf_check -o inline:'7\n' ./count_lines out.dot '^	"n[0-9]*" \['
	atf_check -o inline:'3\n' ./count_lines out.dot '^	"e[0-9]*" \['
	atf_check -o inline:'3\n' ./count_lines out.dot 'style=dotted, arrowhead=none'
	# Ids are unique and dense: n0..n6 and e0..e2 each declared once.
	for i in 0 1 2 3 4 5 6; do
		atf_check -o inline:'1\n' ./count_lines out.dot "^	\"n$i\" \["
	done
	for i in 0 1 2; do
		atf_check -o inline:'1\n' ./count_lines out.dot "^	\"e$i\" \["
	done
	atf_check -o inline:'0\n' ./count_lines out.dot '^	"n9" \['
	atf_check -o inline:'0\n' ./count_lines out.dot '^	"e3" \['
	# Every unit label appears in exactly one node label.
	for l in com.example.pub/pub \
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
	atf_check -o inline:'1\n' ./count_lines out.dot '^digraph attributes {$'
	atf_check -o inline:'1\n' ./count_lines out.dot '^}$'
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
	# The same bytes in a unit's attributes and in an endpoint name.
	for id in 'org.t\303\251st.x' 'org.test.\tx' 'org.test.*' '*'; do
		rm -rf "$graph_root/bad.cap"
		write_bundle "$graph_root/bad.cap" org.test.bad badd \
		    "attributes = [\"$(printf "$id")\"];
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

atf_test_case graph_attribute_removal
graph_attribute_removal_head()
{
 atf_set "descr" "Removing a software attribute removes its static gated edge"
}
graph_attribute_removal_body()
{
 find_switchboardctl
 write_empty_fixture
 write_bundle "$graph_root/sys.cap" org.test.sys sysd 'activation {ipc=[{name="system.Sys.Gate";requires=["ops.key"];}];}'
 write_bundle "$graph_root/client.cap" org.test.client client 'program="client"; activation {exec=true;} attributes=["ops.key"];'
 atf_check -s exit:0 -o match:'org.test.client/client -> system.Sys.Gate' ./graph --lint
 write_bundle "$graph_root/client.cap" org.test.client client 'program="client"; activation {exec=true;}'
 atf_check -s exit:2 -o save:out.txt ./graph --lint
 atf_check -s exit:1 -o ignore grep ' -> system.Sys.Gate' out.txt
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
	    'attributes = ["d.key"];
activation { boot = true; }'
	atf_check -s exit:2 -o save:out.txt ./graph --lint
	atf_check -o match:'^summary: 3 units, 2 endpoints \(1 gated\)' \
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
# Exec-only applications participate in software attribute coverage.
atf_test_case graph_exec_application
graph_exec_application_head()
{
	atf_set "descr" "Exec-only application attributes satisfy a provider gate"
}
graph_exec_application_body()
{
	find_switchboardctl
	write_empty_fixture
	write_bundle "$graph_root/provider.cap" org.test.provider server \
	    'activation {ipc=[{name="system.Test";requires=["test.client"];}];}'
	write_bundle "$graph_root/client.cap" org.test.client client \
	    'program="client"; activation {exec=true;} attributes=["test.client"];'
	atf_check -s exit:0 -o match:'org.test.client/client -> system.Test' -e empty ./graph --lint

}

atf_init_test_cases()
{
	atf_add_test_case graph_g1_edges
	atf_add_test_case graph_g2_unreachable
	atf_add_test_case graph_unreachable_split
	atf_add_test_case graph_g3_dead
	atf_add_test_case graph_lint_exit
	atf_add_test_case graph_dot
	atf_add_test_case graph_json
	atf_add_test_case graph_registry_dirs
	atf_add_test_case graph_errors
	atf_add_test_case graph_eight_endpoints_mixed_gates
	atf_add_test_case graph_mutual_requires
	atf_add_test_case graph_max_attributes_and_requires
	atf_add_test_case graph_root_is_a_file
	atf_add_test_case graph_empty_registry
	atf_add_test_case graph_json_wellformed
	atf_add_test_case graph_dot_one_node_per_unit_and_endpoint
	atf_add_test_case graph_deterministic_output
	atf_add_test_case graph_bad_bundle_id_rejected
	atf_add_test_case graph_attribute_removal
	atf_add_test_case graph_duplicate_endpoint_across_bundles
	atf_add_test_case graph_exec_application
}
