#!/usr/bin/env atf-sh

# Source-only fixtures (the manual page source and the release tooling) are
# installed beneath srctree/ next to this program; the installer scripts are
# checked where bsdinstall installs them.
srctree()
{
	printf '%s' "$(atf_get_srcdir)/srctree"
}

atf_test_case installer_places_zfs_requirement_at_partitioning
installer_places_zfs_requirement_at_partitioning_body()
{
	start="/usr/libexec/bsdinstall/startbsdinstall"
	auto="/usr/libexec/bsdinstall/auto"
	manual="$(srctree)/usr.sbin/bsdinstall/bsdinstall.8"

	atf_check -s exit:1 -o empty -e empty grep \
	    -E 'OpenZFS|bsdfilesystem' "$start"
	atf_check -s exit:0 -o ignore grep \
	    'Guided Root-on-ZFS (required)' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required 5BSD system filesystem; bsdfilesystem' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required system filesystem for a fully functional 5BSD' "$manual"
}

atf_test_case third_party_software_has_separate_dataset
third_party_software_has_separate_dataset_body()
{
	zfsboot="/usr/libexec/bsdinstall/zfsboot"
	manual="$(srctree)/usr.sbin/bsdinstall/bsdinstall.8"
	vmimage="$(srctree)/release/tools/vmimage.subr"

	atf_check -s exit:0 -o ignore grep -Eq \
	    '^[[:space:]]*/usr/local[[:space:]]+mountpoint=/usr/local$' \
	    "$zfsboot"
	atf_check -s exit:0 -o ignore grep -F \
	    'fs=zroot/usr/local\;mountpoint=/usr/local' "$vmimage"
	atf_check -s exit:0 -o ignore grep -F \
	    "Third-party and locally built software is outside the base generation" \
	    "$zfsboot"
	atf_check -s exit:0 -o ignore grep -Eq \
	    '^/usr/local[[:space:]]+mountpoint=/usr/local$' \
	    "$manual"
}


atf_test_case capability_runtime_is_ephemeral
capability_runtime_is_ephemeral_body()
{
	zfsboot="/usr/libexec/bsdinstall/zfsboot"

	atf_check -s exit:0 -o ignore grep -F \
	    'tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0' "$zfsboot"
}

# A pkg(8) INSTALL_AS_USER METALOG never describes ".", and makefs(8) makes
# an undescribed root directory mode 000: every unprivileged process (the
# capability services run as "capability") then fails its first lookup from
# "/" and dies loading /libexec/ld-elf.so.1.  The VM image METALOG must give
# the root a traversable root:wheel 0755 record, keep one that is given, and
# still sort and deduplicate.
atf_test_case image_root_is_traversable
image_root_is_traversable_head()
{
	atf_set "require.progs" "makefs fsdb"
}
image_root_is_traversable_body()
{
	vmimage="$(srctree)/release/tools/vmimage.subr"

	sed -n '/^metalog_normalize() {$/,/^}$/p' "$vmimage" > normalize.sh
	atf_check -s exit:0 -o ignore grep -q '^metalog_normalize' normalize.sh

	mkdir -p root/bin
	printf 'x\n' > root/bin/f
	cat > root/METALOG <<'EOF'
./bin/f type=file uname=root gname=wheel mode=0555
./bin type=dir uname=root gname=wheel mode=0755
./bin type=dir uname=root gname=wheel mode=0755 tags=package=x
EOF
	atf_check -s exit:0 -o save:sorted sh -c \
	    '. ./normalize.sh; metalog_normalize root/METALOG'
	atf_check -s exit:0 -o inline:". type=dir uname=root gname=wheel mode=0755\n" \
	    head -1 sorted
	atf_check -s exit:0 -o inline:"3\n" sh -c 'wc -l < sorted | tr -d " "'

	# makefs must build a root that "capability" (or anyone) can search.
	cp sorted root/METALOG.sorted
	atf_check -s exit:0 -o ignore -e ignore sh -c \
	    'cd root && makefs -t ffs -s 4m ../image METALOG.sorted'
	atf_check -s exit:0 -o match:'I=2 MODE=40755 ' -e ignore sh -c \
	    'echo "inode 2" | fsdb -r image'

	# An explicit root record wins, in either spelling.
	printf './ type=dir uname=root gname=wheel mode=0711\n' >> root/METALOG
	atf_check -s exit:0 -o inline:". type=dir uname=root gname=wheel mode=0711\n" \
	    sh -c '. ./normalize.sh; metalog_normalize root/METALOG | head -1'

	# Duplicate non-directories are still refused.
	printf './bin/f type=file uname=root gname=wheel mode=0444\n' >> root/METALOG
	atf_check -s exit:1 -o ignore -e match:'duplicate non-directory' \
	    sh -c '. ./normalize.sh; metalog_normalize root/METALOG'
}

atf_init_test_cases()
{
	atf_add_test_case image_root_is_traversable
	atf_add_test_case installer_places_zfs_requirement_at_partitioning
	atf_add_test_case third_party_software_has_separate_dataset
	atf_add_test_case capability_runtime_is_ephemeral
}
