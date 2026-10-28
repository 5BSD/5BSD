# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	# Exercise the maintained script; redirect only external effects to fixtures.
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d; s,/usr/bin/ssh-keygen,./keygen,g; s,/etc/ssh/,./keys/,g' \
	    "$(atf_config_get rc_script "${rc_source}/rc.d/sshd")" > sshd.sh
	mkdir keys
	cat > keygen <<-'EOF'
	#!/bin/sh
	echo "$*" >> keygen.calls
	if [ "$1" = -q ]; then
		[ "$3" = "${FAIL_ALG}" ] && exit 1
		: > "$5"
	fi
	exit 0
	EOF
	chmod +x keygen
	cat > seams.sh <<-'EOF'
	checkyesno() { eval '[ "${'"$1"'}" = yes ]'; }
	info() { :; }
	warn() { echo "$*" >&2; }
	EOF
}

atf_test_case key_failure
key_failure_body()
{
	setup
	for alg in rsa ecdsa ed25519; do
		rm -f keys/* keygen.calls
		atf_check -s exit:1 -o ignore -e empty env FAIL_ALG="$alg" sh -c \
		    '. ./seams.sh; . ./sshd.sh; sshd_keygen'
		# Do not fingerprint a failed generation and mask its exit status.
		if grep -q -- "-l -f ./keys/ssh_host_${alg}_key.pub" keygen.calls; then
			atf_fail 'fingerprinted a key after generation failed'
		fi
	done
}

atf_test_case success_and_disabled
success_and_disabled_body()
{
	setup
	atf_check -s exit:0 -o ignore -e empty sh -c \
	    '. ./seams.sh; . ./sshd.sh; sshd_keygen'
	for alg in rsa ecdsa ed25519; do
		[ -f "keys/ssh_host_${alg}_key" ] || atf_fail 'missing generated key'
	done
	rm -f keygen.calls
	atf_check -s exit:0 -o empty -e empty sh -c \
	    '. ./seams.sh; . ./sshd.sh; sshd_keygen'
	[ ! -e keygen.calls ] || atf_fail 'regenerated existing keys'
	rm -f keys/*
	atf_check -s exit:0 -o empty -e empty sh -c \
	    '. ./seams.sh; . ./sshd.sh; sshd_rsa_enable=no; sshd_ecdsa_enable=no; sshd_ed25519_enable=no; sshd_keygen'
	[ ! -e keygen.calls ] || atf_fail 'generated disabled key types'
}

atf_test_case precheck
precheck_body()
{
	setup
	cat > precheck.sh <<-'EOF'
	. ./seams.sh
	. ./sshd.sh
	run_rc_command() {
		echo "$1" >> precmd.calls
		[ "$1" != "${FAIL_STAGE}" ]
	}
	sshd_precmd
	EOF
	for stage in keygen configtest none; do
		rm -f precmd.calls
		status=1
		[ "$stage" != none ] || status=0
		atf_check -s exit:$status -o empty -e empty env FAIL_STAGE="$stage" sh precheck.sh
		printf 'keygen\n' > expected
		[ "$stage" = keygen ] || printf 'configtest\n' >> expected
		atf_check cmp expected precmd.calls
	done
}

atf_init_test_cases()
{
	atf_add_test_case key_failure
	atf_add_test_case success_and_disabled
	atf_add_test_case precheck
}
