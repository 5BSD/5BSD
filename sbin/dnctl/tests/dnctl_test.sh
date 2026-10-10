# SPDX-License-Identifier: BSD-2-Clause
# Syntax tests never open a control socket or change firewall/shaper state.

atf_test_case syntax
syntax_head()
{
	atf_set descr "Standalone Dummynet pipe, queue and scheduler syntax"
	atf_set require.progs dnctl
}
syntax_body()
{
	atf_check -s exit:0 dnctl -n pipe 1 config bw 10Mbit/s delay 20ms
	atf_check -s exit:0 dnctl -n queue 2 config pipe 1 weight 20
	atf_check -s exit:0 dnctl -n sched 1 config type fq_codel
	atf_check -s exit:0 dnctl -n pipe delete 1 2
}

atf_test_case rejects
rejects_head()
{
	atf_set descr "Reject firewall commands and malformed shaper requests"
	atf_set require.progs dnctl
}
rejects_body()
{
	atf_check -s exit:64 -e match:"expected pipe" dnctl -n add allow all
	atf_check -s exit:64 -e match:"expected pipe" dnctl -n nat 1 config
	atf_check -s exit:65 -e match:"invalid object number" dnctl -n pipe delete 1 bogus
	atf_check -s exit:65 -e match:"delay must" dnctl -n pipe 1 config delay 10001
	atf_check -s exit:64 -e match:"unexpected flush" dnctl -n pipe flush unexpected
}

atf_test_case config_file
config_file_head()
{
	atf_set descr "File-level dry run preserves command state and skips comments"
	atf_set require.progs dnctl
}
config_file_body()
{
	cat > config <<EOF
# Configuration applies no live changes in dry-run mode.
pipe 1 config bw 10Mbit/s

queue 2 config pipe 1 weight 20
sched 1 config type fq_codel
EOF
	atf_check -s exit:0 dnctl -n "$(pwd)/config"
}

atf_init_test_cases()
{
	atf_add_test_case syntax
	atf_add_test_case rejects
	atf_add_test_case config_file
}
