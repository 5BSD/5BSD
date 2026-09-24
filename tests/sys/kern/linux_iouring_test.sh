# SPDX-License-Identifier: BSD-2-Clause
atf_test_case iouring cleanup
iouring_head()
{
	atf_set "descr" "io_uring: operations, completion waits, deadlines, signal masks, and feature negotiation"
	atf_set "require.arch" "amd64 aarch64"
	atf_set "require.progs" "clang ld.lld brandelf timeout mount umount"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
iouring_body()
{
	case "$(uname -p)" in
	amd64) target=x86_64-linux-gnu ;;
	aarch64) target=aarch64-linux-gnu ;;
	*) atf_fail "unsupported architecture" ;;
	esac
	atf_check -s exit:0 -o empty -e empty clang --target="$target" \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o iouring "$(atf_get_srcdir)/linux_iouring.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux iouring
	atf_check -s exit:0 mkdir allocation-tmpfs
	atf_check -s exit:0 mount -t tmpfs tmpfs allocation-tmpfs
	iouring_binary="$(pwd)/iouring"
	atf_check -s exit:0 -o save:cases.txt -e empty ./iouring -l
	while read -r name; do
		case "$name" in
		fallocate|fallocate_mode|fallocate_modes_invalid)
			(cd allocation-tmpfs && timeout 15 "$iouring_binary" "$name") 2>stderr.txt
			;;
		*)
			timeout 15 ./iouring "$name" 2>stderr.txt
			;;
		esac
		rc=$?
		cat stderr.txt >&2
		[ $rc -eq 0 ] || atf_fail "$name: exit status $rc"
	done <cases.txt
}
iouring_cleanup()
{
	[ ! -d allocation-tmpfs ] || umount allocation-tmpfs
}
atf_test_case iouring_resize
iouring_resize_head()
{
	atf_set "descr" "io_uring ring resize: size validation, grow/shrink, and pending-ring rollback"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
iouring_resize_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o iouring_resize \
	    "$(atf_get_srcdir)/linux_iouring_resize.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux iouring_resize
	atf_check -s exit:0 -o save:resize-cases.txt -e empty ./iouring_resize -l
	while read -r name; do
		timeout 15 ./iouring_resize "$name" 2>stderr.txt
		rc=$?
		cat stderr.txt >&2
		[ $rc -eq 0 ] || atf_fail "$name: exit status $rc"
	done <resize-cases.txt
}
atf_test_case iouring_query
iouring_query_head()
{
	atf_set "descr" "io_uring register query: feature discovery, linked entries and negative contracts"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
iouring_query_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o iouring_query \
	    "$(atf_get_srcdir)/linux_iouring_query.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux iouring_query
	atf_check -s exit:0 -o save:query-cases.txt -e empty ./iouring_query -l
	while read -r name; do
		timeout 15 ./iouring_query "$name" 2>stderr.txt
		rc=$?
		cat stderr.txt >&2
		[ $rc -eq 0 ] || atf_fail "$name: exit status $rc"
	done <query-cases.txt
}
atf_test_case iouring_mem_region
iouring_mem_region_head()
{
	atf_set "descr" "io_uring memory region: mapping, registered waits, user pins, rollback and faults"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
iouring_mem_region_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o iouring_mem_region \
	    "$(atf_get_srcdir)/linux_iouring_mem_region.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux iouring_mem_region
	atf_check -s exit:0 -o save:mem-region-cases.txt -e empty ./iouring_mem_region -l
	while read -r name; do
		timeout 15 ./iouring_mem_region "$name" 2>stderr.txt
		rc=$?
		cat stderr.txt >&2
		[ $rc -eq 0 ] || atf_fail "$name: exit status $rc"
	done <mem-region-cases.txt
}
atf_test_case iouring_nommap
iouring_nommap_head()
{
	atf_set "descr" "io_uring caller-owned ring pages and registered-fd-only lifecycle"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
iouring_nommap_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o iouring_nommap \
	    "$(atf_get_srcdir)/linux_iouring_nommap.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux iouring_nommap
	atf_check -s exit:0 -o save:nommap-cases.txt -e empty ./iouring_nommap -l
	[ "$(wc -l <nommap-cases.txt | tr -d ' ')" -eq 11 ] || atf_fail "missing cases"
	while read -r name; do
		timeout 30 ./iouring_nommap "$name" 2>stderr.txt
		rc=$?
		cat stderr.txt >&2
		[ $rc -eq 0 ] || atf_fail "$name: exit status $rc"
	done <nommap-cases.txt
}
atf_init_test_cases()
{
	atf_add_test_case iouring
	atf_add_test_case iouring_resize
	atf_add_test_case iouring_query
	atf_add_test_case iouring_mem_region
	atf_add_test_case iouring_nommap
}
