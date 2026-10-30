#!/bin/sh
# Run every ATF case in the TrustedZFS payload without relying on an installed
# Kyuafile.  Intended for the root shell of a disposable test VM.

set -u

payload=${1:-/mnt}
result_dir=$(mktemp -d /tmp/trustedzfs-atf.XXXXXX) || exit 1
passed=0
failed=0
skipped=0

export LD_LIBRARY_PATH=/lib:/usr/lib

run_program()
{
	program=$1
	listing="${result_dir}/${program}.listing"
	if ! "${payload}/${program}" -l > "${listing}" 2>&1; then
		echo "${program}: discovery failed"
		cat "${listing}"
		failed=$((failed + 1))
		return
	fi
	# The manifest carries cleanup metadata; do not invoke nonexistent cleanup.
	cases="${result_dir}/${program}.cases"
	if ! awk '
	    BEGIN { RS=""; FS="\n" }
	    NR == 1 {
	        if ($0 != "Content-Type: application/X-atf-tp; version=\"1\"")
	            bad=1
	        next
	    }
	    {
	        name=""; cleanup="false"
	        for (i=1; i<=NF; i++) {
	            if ($i ~ /^ident: /) name=substr($i, 8)
	            if ($i ~ /^has.cleanup: /) cleanup=substr($i, 14)
	        }
	        if (name !~ /^[a-zA-Z0-9_]+$/ || seen[name]++ ||
	            (cleanup != "true" && cleanup != "false")) bad=1
	        else { print name, cleanup; count++ }
	    }
	    END { if (bad || count == 0) exit 1 }
	' "${listing}" > "${cases}"; then
		echo "${program}: invalid or empty test manifest"
		failed=$((failed + 1))
		return
	fi
	while read -r test_case cleanup; do
		result="${result_dir}/${program}.${test_case}"
		work="${result_dir}/work.${program}.${test_case}"
		mkdir -p "${work}" || return 1
		printf '%s:%s ... ' "${program}" "${test_case}"
		status=0
		(cd "${work}" && "${payload}/${program}" \
		    -r "${result}" "${test_case}") > "${result}.output" 2>&1 || status=$?
		outcome=$(cat "${result}" 2>/dev/null) || outcome="missing result"
		case "${status}:${outcome}" in
		0:passed)
			echo PASS
			passed=$((passed + 1))
			;;
		0:skipped:*)
			echo "SKIP ${outcome}"
			skipped=$((skipped + 1))
			;;
		*)
			echo "FAIL (status ${status}, ${outcome})"
			cat "${result}.output"
			failed=$((failed + 1))
			;;
		esac
		if [ "${cleanup}" = true ]; then
			cleanup_result="${result}.cleanup"
			if ! (cd "${work}" && "${payload}/${program}" \
			    -r "${cleanup_result}" "${test_case}:cleanup" \
			    > "${cleanup_result}.output" 2>&1); then
				echo "${program}:${test_case}:cleanup ... FAIL"
				cat "${cleanup_result}.output"
				failed=$((failed + 1))
			fi
		fi
	done < "${cases}"
}

for program in \
    trustedzfs_capsicum_test \
    trustedzfs_limit_test \
    libbsdfilesystem_protocol_test \
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
    bsdfilesystem_test
do
	run_program "${program}" || exit 1
done

echo "TrustedZFS VM summary: ${passed} passed, ${failed} failed, ${skipped} skipped"
echo "TrustedZFS result directory: ${result_dir}"
test "${failed}" -eq 0 && test "${skipped}" -eq 0 && test "${passed}" -gt 0
