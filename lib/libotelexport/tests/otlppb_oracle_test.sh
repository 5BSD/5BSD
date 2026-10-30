#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The OTLP protobuf encoder (otlppb_encode, the library's upb transcoder)
# against independent decoders: the C++ protobuf runtime (otlp_pb_oracle)
# for every golden OTLP JSON request, and protoc(1) --decode_raw, which
# knows no schema at all.

oracle_compare()
{
	n=0
	for f in "$(atf_get_srcdir)"/golden/*.jsonl; do
		while IFS= read -r line; do
			n=$((n + 1))
			printf '%s\n' "$line" > r$n.json
			atf_check -o save:r$n.pb "$(atf_get_srcdir)/otlppb_encode" \
			    < r$n.json
			atf_check "$(atf_get_srcdir)/otlp_pb_oracle" compare \
			    r$n.json r$n.pb
		done < "$f"
	done
	[ "$n" -ge 6 ] || atf_fail "only $n golden requests"
}

atf_test_case golden_oracle
golden_oracle_head()
{
	atf_set "descr" "every golden OTLP JSON request transcodes to the" \
	    "protobuf the C++ runtime parses from the same JSON"
}
golden_oracle_body()
{
	oracle_compare
}

atf_test_case decode_raw
decode_raw_head()
{
	atf_set "descr" "protoc --decode_raw sees the request structure"
	atf_set "require.progs" "${PROTOC:-/usr/libexec/protoc}"
}
decode_raw_body()
{
	printf '%s\n' '{"resourceLogs":[{"scopeLogs":[{"scope":{"name":"sc"},"logRecords":[{"timeUnixNano":"1700000000000000005","severityNumber":17,"body":{"stringValue":"raw body"},"traceId":"0102030405060708090a0b0c0d0e0f10"}]}]}]}' \
	    > r.json
	atf_check -o save:r.pb "$(atf_get_srcdir)/otlppb_encode" < r.json
	# ExportLogsServiceRequest.resource_logs(1).scope_logs(2):
	# scope(1).name(1), log_records(2): time_unix_nano(1, fixed64),
	# severity_number(2), body(5).string_value(1), trace_id(9).
	"${PROTOC:-/usr/libexec/protoc}" --decode_raw < r.pb > raw.txt ||
	    atf_fail "decode_raw"
	atf_check -o match:'^  2 \{' cat raw.txt
	atf_check -o match:'^      1: "sc"' cat raw.txt
	atf_check -o match:'1: 0x17979cfe362a0005' cat raw.txt
	atf_check -o match:'^      2: 17$' cat raw.txt
	atf_check -o match:'1: "raw body"' cat raw.txt
	atf_check -o match:'9: "\\001\\002\\003\\004\\005\\006\\007\\010\\t\\n\\013\\014\\r\\016\\017\\020"' \
	    cat raw.txt
}

atf_test_case encode_errors
encode_errors_head()
{
	atf_set "descr" "otlppb_encode reports what it cannot transcode"
}
encode_errors_body()
{
	echo '{"resourceLogs":[{"nope":1}]}' > bad.json
	atf_check -s exit:1 -e match:'unknown field "nope"' \
	    "$(atf_get_srcdir)/otlppb_encode" < bad.json
	echo '{"x":1}' > bad.json
	atf_check -s exit:1 -e match:'not an OTLP request' \
	    "$(atf_get_srcdir)/otlppb_encode" < bad.json
	atf_check -s exit:2 -e match:'unknown signal' \
	    "$(atf_get_srcdir)/otlppb_encode" -s bogus < /dev/null
	# Forced signal and length-framed output for several requests.
	printf '%s\n%s\n' '{}' '{"resourceSpans":[]}' > two.json
	atf_check -o save:two.pb "$(atf_get_srcdir)/otlppb_encode" -f \
	    -s traces < two.json
	# Two empty messages, each behind a zero length.
	atf_check -o match:'^ *8$' sh -c 'wc -c < two.pb'
	atf_check -o match:'^ *0$' sh -c "tr -d '\\000' < two.pb | wc -c"
}

atf_init_test_cases()
{
	atf_add_test_case golden_oracle
	atf_add_test_case decode_raw
	atf_add_test_case encode_errors
}
