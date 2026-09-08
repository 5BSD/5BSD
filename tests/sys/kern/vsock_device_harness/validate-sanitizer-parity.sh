#!/bin/sh
# Ensure every non-VirtIO host model claimed by the coverage ledger is also
# compiled and executed by the ASan/UBSan harness, not only by Kyua.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ledger=${WASPNEST_NONVIRTIO_LEDGER:-$here/../../../waspnest/waspnest-nonvirtio-coverage.tsv}
run=$here/run.sh
makefile=$here/Makefile

fail()
{
	echo "sanitizer parity: $*" >&2
	exit 1
}

require_wrappers()
{
	test_program=$1
	shift
	compile_block=$(awk -v needle="\$work/$test_program.c" '
	    BEGIN { RS = "" }
	    index($0, needle) { print; exit }
	' "$run")
	[ -n "$compile_block" ] ||
	    fail "$test_program has no sanitizer compile block"
	for symbol; do
		printf '%s\n' "$compile_block" |
		    grep -Fq -- "--wrap=$symbol" ||
		    fail "$test_program sanitizer link omits --wrap=$symbol"
	done
}

require_libraries()
{
	test_program=$1
	shift
	compile_block=$(awk -v needle="\$work/$test_program.c" '
	    BEGIN { RS = "" }
	    index($0, needle) { print; exit }
	' "$run")
	[ -n "$compile_block" ] ||
	    fail "$test_program has no sanitizer compile block"
	for library; do
		printf '%s\n' "$compile_block" | grep -Fq -- "-l$library" ||
		    fail "$test_program sanitizer link omits -l$library"
	done
}


[ -f "$ledger" ] || fail "missing non-VirtIO coverage ledger: $ledger"

tests=$(awk -F '\t' 'NR > 1 && $3 != "-" {
    n = split($3, names, ",")
    for (i = 1; i <= n; i++) if (!seen[names[i]]++) print names[i]
}' "$ledger")
tests="$tests
mevent_lifecycle_test"

for test_program in $tests; do
	grep -Eq "ATF_TESTS_C\\+=[[:space:]]*$test_program([[:space:]]|$)" \
	    "$makefile" || fail "$test_program is not built by Kyua"
	grep -Fq '"$here/'"$test_program"'.c"' "$run" ||
	    fail "$test_program source is absent from sanitizer staging"
	grep -Fq '"$work/'"$test_program"'.c"' "$run" ||
	    fail "$test_program is not compiled by the sanitizer harness"
done

require_wrappers vsock_device_test socket connectat send recv sendmsg shutdown \
    poll close accept socketpair fcntl setsockopt getsockopt recvmsg ioctl \
    realloc writev
require_wrappers virtio_input_test malloc calloc realloc strdup \
    pthread_mutexattr_init pthread_mutexattr_settype pthread_mutex_init
require_wrappers snapshot_manifest_test close fsync write
require_wrappers virtio_pmem_pci_test calloc
require_wrappers virtio_console_test send realloc calloc malloc
require_wrappers virtio_9p_test calloc strdup
require_wrappers virtio_block_test calloc
require_wrappers block_if_test pwrite pwritev
require_wrappers audio_test read write close
require_wrappers virtio_scsi_test pthread_mutex_init pthread_cond_init
require_wrappers virtio_gpu_2d_pci_test malloc calloc
require_wrappers virtio_iommu_pci_test calloc malloc pthread_mutex_init
require_wrappers virtio_mem_test calloc malloc pthread_mutex_init

require_libraries checkpoint_compat_test z
require_libraries checkpoint_machine_test md
require_libraries snapshot_manifest_test md
require_libraries lib9p_fs_path_test 9p sbuf
require_libraries virtio_block_test md
require_libraries virtio_scsi_test sbuf

grep -Fq '#define atf_tc_skip' "$run" ||
    fail "sanitizer ATF shim omits atf_tc_skip"

echo "PASS sanitizer model parity"
