#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# base-accounts(8): create missing base groups and users without touching
# local entries.  Every case works on a private root (pw -R), so no case
# changes the accounts of the system running the tests.

BA=${BASE_ACCOUNTS:-/usr/sbin/base-accounts}

# The shipped reference: an older release plus a new device group (audio),
# a new service identity (_svc), a member list and the superuser alias.
make_reference()
{
	mkdir -p ref
	cat > ref/group <<'EOF'
# comment lines are not accounts
wheel:*:0:root
operator:*:5:root
staff:*:20:
audio:*:43:root
video:*:44:
_svc:*:830:
nogroup:*:65533:
EOF
	cat > ref/master.passwd <<'EOF'
root::0:0::0:0:Charlie &:/root:/bin/sh
toor:*:0:0::0:0:Bourne-again Superuser:/root:
operator:*:2:5::0:0:System &:/:/usr/sbin/nologin
_svc:*:830:830::0:0:Service Identity:/var/empty:/usr/sbin/nologin
nobody:*:65534:65533::0:0:Unprivileged user:/nonexistent:/usr/sbin/nologin
EOF
}

# The installed system: the older release, locally modified as an
# administrator would (memberships, local groups and users).
make_root()
{
	mkdir -p root/etc
	cat > root/etc/group <<'EOF'
wheel:*:0:root,kory
operator:*:5:root
staff:*:20:
video:*:44:kory
nogroup:*:65533:
kory:*:1001:
sddm:*:620:
EOF
	cat > root/etc/master.passwd <<'EOF'
root:$6$local$hash:0:0::0:0:Charlie &:/root:/bin/sh
toor:*:0:0::0:0:Bourne-again Superuser:/root:
operator:*:2:5::0:0:System &:/:/usr/sbin/nologin
nobody:*:65534:65533::0:0:Unprivileged user:/nonexistent:/usr/sbin/nologin
kory:$6$kory$hash:1001:1001::0:0:Kory:/home/kory:/bin/sh
EOF
	chmod 600 root/etc/master.passwd
	pwd_mkdb -p -d root/etc root/etc/master.passwd || \
	    atf_fail "pwd_mkdb failed"
	cp root/etc/group group.orig
	cp root/etc/master.passwd master.passwd.orig
}

# Every line of the original file is still present, unchanged.
check_preserved()
{
	while IFS= read -r line; do
		grep -qxF -- "$line" "root/etc/$1" || \
		    atf_fail "local $1 entry changed or removed: $line"
	done < "$1.orig"
}

atf_test_case creates_missing
creates_missing_head()
{
	atf_set "descr" "Missing base groups and users are created with" \
	    "the shipped ids; local entries are preserved"
}
creates_missing_body()
{
	make_reference
	make_root
	atf_check -o match:"created group audio \(gid 43\)" \
	    -o match:"created group _svc \(gid 830\)" \
	    -o match:"created user _svc \(uid 830, gid 830\)" $BA -R $PWD/root -r $PWD/ref
	atf_check -o inline:"audio:*:43:root\n" grep '^audio:' root/etc/group
	atf_check -o inline:"_svc:*:830:\n" grep '^_svc:' root/etc/group
	atf_check -o inline:"_svc:*:830:830::0:0:Service Identity:/var/empty:/usr/sbin/nologin\n" \
	    grep '^_svc:' root/etc/master.passwd
	check_preserved group
	check_preserved master.passwd
	# The databases were rebuilt: pw reads the new user back.
	atf_check -o match:"^_svc:\*:830:830:" pw -R "$PWD/root" usershow _svc
	atf_check -o match:"^u:_svc$" -o match:"^g:audio$" \
	    cat root/var/db/base-accounts
}

atf_test_case idempotent
idempotent_head()
{
	atf_set "descr" "A second run changes nothing"
}
idempotent_body()
{
	make_reference
	make_root
	atf_check -o ignore $BA -R $PWD/root -r $PWD/ref
	cp root/etc/group group.1
	cp root/etc/master.passwd master.passwd.1
	atf_check -o empty -e empty $BA -R $PWD/root -r $PWD/ref
	atf_check cmp group.1 root/etc/group
	atf_check cmp master.passwd.1 root/etc/master.passwd
}

atf_test_case dry_run
dry_run_head()
{
	atf_set "descr" "-n reports and changes nothing"
}
dry_run_body()
{
	make_reference
	make_root
	atf_check -o match:"would create group audio \(gid 43\)" \
	    -o match:"would create user _svc \(uid 830, gid 830\)" $BA -R $PWD/root -r $PWD/ref -n
	atf_check cmp group.orig root/etc/group
	atf_check cmp master.passwd.orig root/etc/master.passwd
	atf_check test ! -e root/var/db/base-accounts
}

atf_test_case gid_taken
gid_taken_head()
{
	atf_set "descr" "A base group whose gid a local group uses is refused"
}
gid_taken_body()
{
	make_reference
	make_root
	echo 'mysound:*:43:kory' >> root/etc/group
	cp root/etc/group group.orig
	atf_check -s exit:2 -o match:"created group _svc" \
	    -e match:"REFUSED group audio \(gid 43\): gid 43 belongs to local group mysound" \
	    $BA -R $PWD/root -r $PWD/ref
	atf_check -s exit:1 grep '^audio:' root/etc/group
	check_preserved group
	# Refusals are not recorded: the next run reports them again.
	atf_check -s exit:1 grep -x 'g:audio' root/var/db/base-accounts
	atf_check -s exit:2 -e match:"REFUSED group audio" $BA -R $PWD/root -r $PWD/ref
}

atf_test_case uid_taken
uid_taken_head()
{
	atf_set "descr" "A base user whose uid a local user uses is refused"
}
uid_taken_body()
{
	make_reference
	make_root
	echo 'local:*:830:1001::0:0:Local:/home/local:/bin/sh' >> \
	    root/etc/master.passwd
	pwd_mkdb -p -d root/etc root/etc/master.passwd
	cp root/etc/master.passwd master.passwd.orig
	atf_check -s exit:2 -o match:"created group _svc" \
	    -e match:"REFUSED user _svc \(uid 830\): uid 830 belongs to local user local" \
	    $BA -R $PWD/root -r $PWD/ref
	atf_check -s exit:1 grep '^_svc:' root/etc/master.passwd
	check_preserved master.passwd
}

atf_test_case name_kept
name_kept_head()
{
	atf_set "descr" "A local entry with a base name but another id is kept"
}
name_kept_body()
{
	make_reference
	make_root
	echo 'audio:*:4300:kory' >> root/etc/group
	cp root/etc/group group.orig
	atf_check -o not-match:"created group audio" \
	    -o match:"keeping local group audio \(gid 4300; the base system uses gid 43\)" \
	    $BA -R $PWD/root -r $PWD/ref -v
	atf_check -o inline:"audio:*:4300:kory\n" grep '^audio:' root/etc/group
	check_preserved group
}

atf_test_case removed_locally
removed_locally_head()
{
	atf_set "descr" "An entry removed after a reconcile is not recreated" \
	    "unless -a is given"
}
removed_locally_body()
{
	make_reference
	make_root
	atf_check -o ignore $BA -R $PWD/root -r $PWD/ref
	atf_check -o ignore pw -R "$PWD/root" groupdel audio
	atf_check -o empty $BA -R $PWD/root -r $PWD/ref
	atf_check -s exit:1 grep '^audio:' root/etc/group
	atf_check -o match:"created group audio" $BA -R $PWD/root -r $PWD/ref -a
	atf_check -o match:"^audio:" grep '^audio:' root/etc/group
}

atf_test_case privileged_never_created
privileged_never_created_head()
{
	atf_set "descr" "uid 0 aliases and accounts without a password field" \
	    "are never created"
}
privileged_never_created_body()
{
	make_reference
	make_root
	sed -i '' '/^toor:/d' root/etc/master.passwd
	pwd_mkdb -p -d root/etc root/etc/master.passwd
	atf_check -o match:"not creating privileged account toor" $BA -R $PWD/root -r $PWD/ref -v
	atf_check -s exit:1 grep '^toor:' root/etc/master.passwd
}

atf_test_case member_must_exist
member_must_exist_head()
{
	atf_set "descr" "A new group lists only members that exist"
}
member_must_exist_body()
{
	make_reference
	make_root
	sed -i '' 's/^audio:\*:43:root$/audio:*:43:root,ghost/' ref/group
	atf_check -o match:"member ghost does not exist" $BA -R $PWD/root -r $PWD/ref -v
	atf_check -o inline:"audio:*:43:root\n" grep '^audio:' root/etc/group
}

atf_test_case missing_reference
missing_reference_head()
{
	atf_set "descr" "A missing reference file is an error, not a no-op"
}
missing_reference_body()
{
	make_root
	mkdir ref
	atf_check -s exit:66 -e match:"cannot read reference file" $BA -R $PWD/root -r $PWD/ref
	atf_check cmp group.orig root/etc/group
}

atf_test_case shipped_reference
shipped_reference_head()
{
	atf_set "descr" "The installed reference parses and every base user's" \
	    "primary group is a base group"
}
shipped_reference_body()
{
	ref=/usr/share/base-accounts
	[ -r $ref/group ] || atf_skip "no installed reference"
	awk -F: '!/^#/ && NF { print $3 }' $ref/group | sort -n > gids
	awk -F: '!/^#/ && NF { print $4 }' $ref/master.passwd | sort -un | \
	    while read -r g; do
		grep -qx "$g" gids || atf_fail "primary gid $g is not a base group"
	done
	atf_check -o inline:"audio:*:43:\n" grep '^audio:' $ref/group
}

atf_init_test_cases()
{
	atf_add_test_case creates_missing
	atf_add_test_case idempotent
	atf_add_test_case dry_run
	atf_add_test_case gid_taken
	atf_add_test_case uid_taken
	atf_add_test_case name_kept
	atf_add_test_case removed_locally
	atf_add_test_case privileged_never_created
	atf_add_test_case member_must_exist
	atf_add_test_case missing_reference
	atf_add_test_case shipped_reference
}
