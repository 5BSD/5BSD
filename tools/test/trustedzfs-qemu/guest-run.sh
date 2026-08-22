#!/bin/sh
# Run every ATF case in the TrustedZFS payload without relying on an installed
# Kyuafile.  Intended for the root shell of a disposable test VM.

set -u

payload=${1:-/mnt}
result_dir=/tmp/trustedzfs-atf
passed=0
failed=0
skipped=0

mkdir -p "${result_dir}"
export LD_LIBRARY_PATH=/lib:/usr/lib

run_program()
{
	program=$1
	for test_case in $("${payload}/${program}" -l |
	    awk '/^ident: / { print $2 }'); do
		result="${result_dir}/${program}.${test_case}"
		work="${result_dir}/work.${program}.${test_case}"
		mkdir -p "${work}"
		printf '%s:%s ... ' "${program}" "${test_case}"
		if output=$(cd "${work}" && "${payload}/${program}" \
		    -r "${result}" "${test_case}" 2>&1); then
			case "${output}" in
			*skipped*)
				echo "SKIP ${output}"
				skipped=$((skipped + 1))
				;;
			*)
				echo PASS
				passed=$((passed + 1))
				;;
			esac
		else
			echo "FAIL"
			echo "${output}"
			test ! -f "${result}" || cat "${result}"
			failed=$((failed + 1))
		fi
		cleanup_result="${result}.cleanup"
		if ! (cd "${work}" && "${payload}/${program}" \
		    -r "${cleanup_result}" "${test_case}:cleanup" \
		    >/dev/null 2>&1); then
			echo "${program}:${test_case}:cleanup ... FAIL"
			test ! -f "${cleanup_result}" || cat "${cleanup_result}"
			failed=$((failed + 1))
		fi
	done
}

for program in \
    trustedzfs_capsicum_test \
    libtzfsd_protocol_test \
    zfshandle_rights_test \
    zfshandle_derive_test \
    zfshandle_pin_test \
    zfshandle_phase2_test \
    zfshandle_mount_test \
    zfshandle_pool_test \
    zfshandle_security_test \
    zfshandle_verbs_test \
    zfshandle_negative_test \
    zfshandle_hardening_test \
    tzfsd_test
do
	run_program "${program}"
done

echo "TrustedZFS VM summary: ${passed} passed, ${failed} failed, ${skipped} skipped"
test "${failed}" -eq 0
