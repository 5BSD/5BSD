# SPDX-License-Identifier: BSD-2-Clause
atf_test_case fileflags
fileflags_head()
{
	atf_set "descr" "Linux renameat2 flags, fcntl commands (OFD locks, seals, pipe size, owner_ex, F_SETSIG), faccessat2, fchownat, copy_file_range and inotify flags"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
fileflags_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o fileflags \
	    "$(atf_get_srcdir)/linux_fileflags.c"
	atf_check -s exit:0 -o empty -e empty ./fileflags
}
atf_init_test_cases()
{
	atf_add_test_case fileflags
}
