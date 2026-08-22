#!/usr/libexec/atf-sh

setup_tools()
{
	mkdir mock root
	tool="@SRCTOP@/usr.sbin/tzfsd/tzfs-mkflavor.sh"
	log="${PWD}/zfs.log"
	export MOCK_ZFS_LOG="$log"
	export PATH="${PWD}/mock:/bin:/usr/bin"

	cat >mock/zfs <<'EOF'
#!/bin/sh
echo "$*" >>"$MOCK_ZFS_LOG"
case "$1" in
list) exit 1 ;;
send)
	printf 'mock-zfs-stream'
	[ "${MOCK_SEND_FAIL:-0}" -eq 0 ]
	;;
*) exit 0 ;;
esac
EOF
	cat >mock/zstd <<'EOF'
#!/bin/sh
out=
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift 2 ;;
	*) shift ;;
	esac
done
if [ "${MOCK_ZSTD_FAIL:-0}" -ne 0 ]; then
	exit 9
fi
cat >"$out"
EOF
	chmod +x mock/zfs mock/zstd
	printf 'rootfs-data' >root/file
}

atf_test_case success_and_owned_cleanup cleanup
success_and_owned_cleanup_head()
{
	atf_set "descr" "flavor builds publish atomically from unique owned scratch state"
}
success_and_owned_cleanup_body()
{
	setup_tools
	printf 'old' >artifact.zst
	atf_check -s exit:0 -e match:'wrote artifact.zst' \
	    sh "$tool" -p tank -c 3 -o artifact.zst test-flavor root
	atf_check -s exit:0 -o inline:'mock-zfs-stream' cat artifact.zst
	atf_check -s exit:0 -o match:'^create -o mountpoint=.* -p tank/.tzfs-build/test-flavor-tzfs-mkflavor\.' \
	    grep '^create ' "$log"
	atf_check -s exit:0 -o match:'^destroy -r tank/.tzfs-build/test-flavor-tzfs-mkflavor\.' \
	    grep '^destroy ' "$log"
	first=$(sed -n '1p' "$log")
	case "$first" in
	list*) ;;
	*) atf_fail "first ZFS operation was destructive: $first" ;;
	esac
}
success_and_owned_cleanup_cleanup()
{
	chmod -R u+w mock root 2>/dev/null || true
	rm -rf mock root artifact.zst zfs.log
}

atf_test_case validation_matrix cleanup
validation_matrix_body()
{
	setup_tools
	for args in \
	    '-p bad/pool -o out.zst good root' \
	    '-p .. -o out.zst good root' \
	    '-p tank -o out.zst bad/name root' \
	    '-p tank -o out.zst .. root' \
	    '-p tank -c 0 -o out.zst good root' \
	    '-p tank -c twenty -o out.zst good root'
	do
		atf_check -s not-exit:0 -e match:'invalid|compression' \
		    sh -c "sh \"$tool\" $args"
	done
	atf_check -s exit:0 test ! -s "$log"
}
validation_matrix_cleanup()
{
	chmod -R u+w mock root 2>/dev/null || true
	rm -rf mock root out.zst zfs.log
}

atf_test_case failures_do_not_publish cleanup
failures_do_not_publish_body()
{
	setup_tools
	printf 'known-good' >artifact.zst
	export MOCK_ZSTD_FAIL=1
	atf_check -s not-exit:0 -e match:'failed to compress' \
	    sh "$tool" -p tank -o artifact.zst test root
	atf_check -s exit:0 -o inline:'known-good' cat artifact.zst
	unset MOCK_ZSTD_FAIL
	export MOCK_SEND_FAIL=1
	atf_check -s not-exit:0 -e match:'failed to produce send stream' \
	    sh "$tool" -p tank -o artifact.zst test root
	atf_check -s exit:0 -o inline:'known-good' cat artifact.zst
}
failures_do_not_publish_cleanup()
{
	chmod -R u+w mock root 2>/dev/null || true
	rm -rf mock root artifact.zst artifact.zst.tmp.* zfs.log
}

atf_test_case linux_requires_pinned_content cleanup
linux_requires_pinned_content_body()
{
	script="@SRCTOP@/usr.sbin/tzfs-flavors/tzfs-flavor-linux.sh"
	mkdir -p layer oci/blobs/sha256 mock
	printf 'rocky-root' >layer/release
	tar -cf layer.tar -C layer .
	layer_sha=$(sha256 -q layer.tar)
	cp layer.tar "oci/blobs/sha256/$layer_sha"
	tar -cJf archive.tar.xz -C oci .
	archive_sha=$(sha256 -q archive.tar.xz)
	cat >mock/fetch <<'EOF'
#!/bin/sh
[ "$1" = -o ] || exit 2
cp "$MOCK_ARCHIVE" "$2"
EOF
	cat >mock/mkflavor <<'EOF'
#!/bin/sh
eval "root=\${$#}"
[ "$(cat "$root/release")" = rocky-root ] || exit 3
printf '%s\n' "$*" >"$MOCK_MKFLAVOR_LOG"
EOF
	chmod +x mock/fetch mock/mkflavor
	export MOCK_ARCHIVE="${PWD}/archive.tar.xz"
	export MOCK_MKFLAVOR_LOG="${PWD}/mkflavor.log"
	export TZFS_FETCH="${PWD}/mock/fetch"
	export TZFS_MKFLAVOR="${PWD}/mock/mkflavor"
	atf_check -s not-exit:0 -e match:'usage:' sh "$script"
	atf_check -s not-exit:0 -e match:'SHA-256 mismatch' sh "$script" \
	    -s 0000000000000000000000000000000000000000000000000000000000000000 \
	    -l "$layer_sha" -m https://example.invalid
	atf_check -s exit:0 -e match:'wrote output.zst' sh "$script" \
	    -s "$archive_sha" -l "$layer_sha" -m https://example.invalid \
	    -o output.zst
	atf_check -s exit:0 -o match:'-o output.zst linux ' cat mkflavor.log
}
linux_requires_pinned_content_cleanup()
{
	chmod -R u+w layer oci mock 2>/dev/null || true
	rm -rf layer oci mock layer.tar archive.tar.xz mkflavor.log output.zst
}

atf_init_test_cases()
{
	atf_add_test_case success_and_owned_cleanup
	atf_add_test_case validation_matrix
	atf_add_test_case failures_do_not_publish
	atf_add_test_case linux_requires_pinned_content
}
