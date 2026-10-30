/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_pb_oracle - the independent OTLP protobuf oracle of the
 * libotelexport tests.  It uses the C++ protobuf runtime and C++ code
 * generated from opentelemetry-proto, so it shares no code with the
 * library's upb-based encoder.
 *
 *   otlp_pb_oracle compare request.json request.pb
 *	Parse the OTLP JSON request (hex trace and span ids are turned
 *	into the base64 of proto3 JSON first; unknown fields are an
 *	error) and the binary request, and compare the two messages.
 *	Exit 0 when equal, 1 with the differences on stderr.
 *   otlp_pb_oracle decode logs|metrics|traces request.pb
 *	Print the binary Export*ServiceRequest as proto3 JSON.
 *   otlp_pb_oracle response logs|metrics|traces rejected [message]
 *	Write an Export*ServiceResponse with a partial_success to stdout.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>

#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/message.h"
#include "google/protobuf/util/field_comparator.h"
#include "google/protobuf/util/json_util.h"
#include "google/protobuf/util/message_differencer.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"

namespace gpb = google::protobuf;
namespace collogs = opentelemetry::proto::collector::logs::v1;
namespace colmetrics = opentelemetry::proto::collector::metrics::v1;
namespace coltrace = opentelemetry::proto::collector::trace::v1;

static std::string
slurp(const char *path)
{
	std::ifstream in(path, std::ios::binary);
	std::ostringstream ss;

	if (!in) {
		std::cerr << "otlp_pb_oracle: cannot read " << path << "\n";
		std::exit(2);
	}
	ss << in.rdbuf();
	return (ss.str());
}

static std::unique_ptr<gpb::Message>
request_for(const std::string &signal)
{

	if (signal == "logs")
		return (std::make_unique<collogs::ExportLogsServiceRequest>());
	if (signal == "metrics")
		return (std::make_unique<
		    colmetrics::ExportMetricsServiceRequest>());
	if (signal == "traces")
		return (std::make_unique<
		    coltrace::ExportTraceServiceRequest>());
	std::cerr << "otlp_pb_oracle: unknown signal " << signal << "\n";
	std::exit(2);
}

/* The signal of an OTLP JSON request, from its top-level key. */
static std::string
json_signal(const std::string &json)
{

	if (json.find("\"resourceLogs\"") != std::string::npos ||
	    json.find("\"resource_logs\"") != std::string::npos)
		return ("logs");
	if (json.find("\"resourceMetrics\"") != std::string::npos ||
	    json.find("\"resource_metrics\"") != std::string::npos)
		return ("metrics");
	return ("traces");
}

static std::string
hex_to_base64(const std::string &hex)
{
	static const char tab[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string bytes, out;
	size_t i;
	unsigned v;

	for (i = 0; i + 1 < hex.size(); i += 2)
		bytes.push_back((char)std::stoul(hex.substr(i, 2), nullptr,
		    16));
	for (i = 0; i < bytes.size(); i += 3) {
		v = (unsigned char)bytes[i] << 16;
		if (i + 1 < bytes.size())
			v |= (unsigned char)bytes[i + 1] << 8;
		if (i + 2 < bytes.size())
			v |= (unsigned char)bytes[i + 2];
		out.push_back(tab[v >> 18 & 63]);
		out.push_back(tab[v >> 12 & 63]);
		out.push_back(i + 1 < bytes.size() ? tab[v >> 6 & 63] : '=');
		out.push_back(i + 2 < bytes.size() ? tab[v & 63] : '=');
	}
	return (out);
}

/*
 * OTLP JSON spells trace and span ids in hex; proto3 JSON expects
 * base64.  This is the only difference between the two encodings.
 */
static std::string
otlp_to_proto3_json(const std::string &json)
{
	static const std::regex id(
	    "(\"(traceId|spanId|parentSpanId|trace_id|span_id|"
	    "parent_span_id)\"\\s*:\\s*\")([0-9a-fA-F]*)\"");
	std::string out;
	std::sregex_iterator it(json.begin(), json.end(), id), end;
	size_t last = 0;

	for (; it != end; ++it) {
		const std::smatch &m = *it;
		out.append(json, last, (size_t)m.position(0) - last);
		out.append(m[1].str());
		out.append(hex_to_base64(m[3].str()));
		out.push_back('"');
		last = (size_t)(m.position(0) + m.length(0));
	}
	out.append(json, last, std::string::npos);
	return (out);
}

static int
compare(const char *jsonpath, const char *pbpath)
{
	std::string json = slurp(jsonpath), bin = slurp(pbpath), diff;
	std::string signal = json_signal(json);
	std::unique_ptr<gpb::Message> want = request_for(signal);
	std::unique_ptr<gpb::Message> got = request_for(signal);
	gpb::util::JsonParseOptions opts;
	gpb::util::DefaultFieldComparator cmp;
	gpb::util::MessageDifferencer d;

	opts.ignore_unknown_fields = false;
	auto st = gpb::util::JsonStringToMessage(otlp_to_proto3_json(json),
	    want.get(), opts);
	if (!st.ok()) {
		std::cerr << "otlp_pb_oracle: JSON does not parse: " <<
		    st.ToString() << "\n";
		return (1);
	}
	if (!got->ParseFromString(bin)) {
		std::cerr << "otlp_pb_oracle: protobuf does not parse\n";
		return (1);
	}
	cmp.set_treat_nan_as_equal(true);
	d.set_field_comparator(&cmp);
	d.ReportDifferencesToString(&diff);
	if (!d.Compare(*want, *got)) {
		std::cerr << "otlp_pb_oracle: messages differ:\n" << diff;
		return (1);
	}
	return (0);
}

static int
decode(const char *signal, const char *pbpath)
{
	std::unique_ptr<gpb::Message> m = request_for(signal);
	std::string out;
	gpb::util::JsonPrintOptions opts;

	if (!m->ParseFromString(slurp(pbpath))) {
		std::cerr << "otlp_pb_oracle: protobuf does not parse\n";
		return (1);
	}
	opts.preserve_proto_field_names = false;
	(void)gpb::util::MessageToJsonString(*m, &out, opts);
	std::cout << out << "\n";
	return (0);
}

static int
response(const std::string &signal, long long rejected, const char *msg)
{
	std::string out;

	if (signal == "logs") {
		collogs::ExportLogsServiceResponse r;
		r.mutable_partial_success()->set_rejected_log_records(rejected);
		r.mutable_partial_success()->set_error_message(msg);
		r.SerializeToString(&out);
	} else if (signal == "metrics") {
		colmetrics::ExportMetricsServiceResponse r;
		r.mutable_partial_success()->set_rejected_data_points(
		    rejected);
		r.mutable_partial_success()->set_error_message(msg);
		r.SerializeToString(&out);
	} else {
		coltrace::ExportTraceServiceResponse r;
		r.mutable_partial_success()->set_rejected_spans(rejected);
		r.mutable_partial_success()->set_error_message(msg);
		r.SerializeToString(&out);
	}
	std::fwrite(out.data(), 1, out.size(), stdout);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc == 4 && std::strcmp(argv[1], "compare") == 0)
		return (compare(argv[2], argv[3]));
	if (argc == 4 && std::strcmp(argv[1], "decode") == 0)
		return (decode(argv[2], argv[3]));
	if ((argc == 4 || argc == 5) && std::strcmp(argv[1], "response") == 0)
		return (response(argv[2], std::atoll(argv[3]),
		    argc == 5 ? argv[4] : ""));
	std::cerr << "usage: otlp_pb_oracle compare request.json request.pb\n"
	    "       otlp_pb_oracle decode signal request.pb\n"
	    "       otlp_pb_oracle response signal rejected [message]\n";
	return (2);
}
