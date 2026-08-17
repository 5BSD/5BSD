#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# CLI tests for hwtlm.  Everything here must work without root,
# without RAPL, and without coretemp — the tool's graceful
# degradation is part of what's under test.
#

atf_test_case list_text
list_text_head()
{
	atf_set descr "list reports CPU count and degrades without RAPL"
}
list_text_body()
{
	atf_check -o save:out.txt hwtlm list
	atf_check -o match:'Logical CPUs:  [1-9]' cat out.txt
}

atf_test_case list_json_valid
list_json_valid_head()
{
	atf_set descr "list --format json emits one valid JSON object"
}
list_json_valid_body()
{
	atf_check -o save:out.json hwtlm list --format json
	atf_check -o match:'"logical_cpus":[1-9]' cat out.json
	# Balanced braces on a single line ending in }.
	atf_check -o match:'^\{.*\}$' cat out.json
}

atf_test_case list_percore
list_percore_head()
{
	atf_set descr "list --per-core runs and emits the per-core sections"
}
list_percore_body()
{
	atf_check -o ignore hwtlm list --per-core
}

atf_test_case list_rejects_otel
list_rejects_otel_head()
{
	atf_set descr "list --format otel is rejected"
}
list_rejects_otel_body()
{
	atf_check -s exit:2 -e match:"only supported by" \
	    hwtlm list --format otel
}

atf_test_case watch_duration_terminates
watch_duration_terminates_head()
{
	atf_set descr "watch --duration stops on its own"
	atf_set timeout 30
}
watch_duration_terminates_body()
{
	atf_check -s exit:0 -o ignore -e ignore \
	    hwtlm watch --interval 0.2 --duration 1
}

atf_test_case watch_json_lines
watch_json_lines_head()
{
	atf_set descr "watch --format json emits one JSON object per sample"
	atf_set timeout 30
}
watch_json_lines_body()
{
	atf_check -s exit:0 -o save:out.json -e ignore \
	    hwtlm watch --interval 0.2 --duration 1 --format json
	atf_check -o match:'"time":"' head -1 out.json
	# Every line is a self-contained {...} object.
	while read -r line; do
		case "$line" in
		{*}) ;;
		*) atf_fail "malformed JSONL line: $line" ;;
		esac
	done < out.json
}

atf_test_case watch_validates_args
watch_validates_args_head()
{
	atf_set descr "watch rejects non-positive interval and duration"
}
watch_validates_args_body()
{
	atf_check -s exit:2 -e match:"interval must be" \
	    hwtlm watch --interval 0
	atf_check -s exit:2 -e match:"duration must be" \
	    hwtlm watch --duration -1
	atf_check -s exit:2 -e match:"interval must be" \
	    hwtlm watch --interval nan
	atf_check -s exit:2 -e match:"interval must be" \
	    hwtlm watch --interval 2.5x
}

atf_test_case exec_propagates_exit
exec_propagates_exit_head()
{
	atf_set descr "exec runs the child and propagates its exit code"
	atf_set timeout 30
}
exec_propagates_exit_body()
{
	atf_check -s exit:0 -o ignore -e ignore hwtlm exec -- true
	atf_check -s exit:1 -o ignore -e ignore hwtlm exec -- false
	atf_check -s exit:127 -o ignore -e ignore \
	    hwtlm exec -- /nonexistent/tool
}

atf_test_case exec_json_fields
exec_json_fields_head()
{
	atf_set descr "exec --format json reports command/elapsed/exit_code"
	atf_set timeout 30
}
exec_json_fields_body()
{
	atf_check -s exit:0 -o save:out.json -e ignore \
	    hwtlm exec --format json -- sleep 0.1
	atf_check -o match:'"command":"sleep 0.1"' cat out.json
	atf_check -o match:'"elapsed_seconds":0\.[0-9]*' cat out.json
	atf_check -o match:'"exit_code":0' cat out.json
}

atf_test_case exec_requires_command
exec_requires_command_head()
{
	atf_set descr "exec without a command is a usage error"
}
exec_requires_command_body()
{
	atf_check -s exit:2 -e match:"usage" hwtlm exec
}

atf_init_test_cases()
{
	atf_add_test_case list_text
	atf_add_test_case list_json_valid
	atf_add_test_case list_percore
	atf_add_test_case list_rejects_otel
	atf_add_test_case watch_duration_terminates
	atf_add_test_case watch_json_lines
	atf_add_test_case watch_validates_args
	atf_add_test_case exec_propagates_exit
	atf_add_test_case exec_json_fields
	atf_add_test_case exec_requires_command
}
