# SPDX-License-Identifier: BSD-2-Clause

atf_test_case expansion
expansion_head()
{
	atf_set descr "Preserve strings and terminators during jail.conf expansion"
	atf_set require.progs jail
}

expansion_body()
{
	cat > jail.conf <<'EOF'
$root = "/srv";
$empty = "";
a {
	path = "$root/${name}";
	host.hostname = "pre${empty}post";
	exec.start = "${empty}";
}
a.child {
	path = "$root/${name}";
	host.hostname = "${empty}child${empty}";
}
EOF
	cat > expected <<'EOF'
name=a|path=/srv/a|host.hostname=prepost|exec.start=""
name=a.child|path=/srv/a.child|host.hostname=child
EOF
	atf_check -s exit:0 -o file:expected -e empty \
	    jail -f jail.conf -e '|'
}

atf_test_case large_expansion
large_expansion_head()
{
	atf_set descr "Grow jail.conf strings across allocation size classes"
	atf_set require.progs jail
}

large_expansion_body()
{
	long=$(awk 'BEGIN { for (i = 0; i < 8192; i++) printf "x" }')
	printf '$long = "%s";\n' "${long}" > jail.conf
	cat >> jail.conf <<'EOF'
growth {
	path = "prefix${long}middle${long}suffix";
}
EOF
	printf 'name=growth|path=prefix%smiddle%ssuffix\n' \
	    "${long}" "${long}" > expected
	atf_check -s exit:0 -o file:expected -e empty \
	    jail -f jail.conf -e '|'
}

atf_init_test_cases()
{
	atf_add_test_case expansion
	atf_add_test_case large_expansion
}
