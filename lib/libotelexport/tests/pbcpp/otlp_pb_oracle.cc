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
 *   otlp_pb_oracle decode logs|metrics|traces|profiles request.pb
 *	Print the binary Export*ServiceRequest as proto3 JSON.
 *   otlp_pb_oracle response logs|metrics|traces|profiles rejected [message]
 *	Write an Export*ServiceResponse with a partial_success to stdout.
 *   otlp_pb_oracle profile request.pb
 *	Check an ExportProfilesServiceRequest (experimental profiles,
 *	opentelemetry-proto 1.10) against the dictionary rules of
 *	profiles.proto (every table present with its zero value first,
 *	no duplicate entries, every index in range, unique attribute keys
 *	per sample, values or timestamps in every sample, equal counts
 *	when both) and print its samples resolved through the dictionary,
 *	one per line, sorted:
 *	    <service.name>|<sample type>/<unit>|<k=v,...>|<frames>|<total>
 *	frames leaf first as module`function, module`0xaddress or
 *	0xaddress joined by ';', total the sum of the values (or the
 *	number of timestamps), and a "link=<trace>/<span>" attribute for a
 *	linked sample.  Exit 1 with the violations on stderr.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <algorithm>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/message.h"
#include "google/protobuf/util/field_comparator.h"
#include "google/protobuf/util/json_util.h"
#include "google/protobuf/util/message_differencer.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
#include "opentelemetry/proto/collector/profiles/v1development/profiles_service.pb.h"

namespace gpb = google::protobuf;
namespace collogs = opentelemetry::proto::collector::logs::v1;
namespace colmetrics = opentelemetry::proto::collector::metrics::v1;
namespace coltrace = opentelemetry::proto::collector::trace::v1;
namespace colprof = opentelemetry::proto::collector::profiles::v1development;
namespace prof = opentelemetry::proto::profiles::v1development;

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
	if (signal == "profiles")
		return (std::make_unique<
		    colprof::ExportProfilesServiceRequest>());
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
	if (json.find("\"resourceProfiles\"") != std::string::npos ||
	    json.find("\"resource_profiles\"") != std::string::npos)
		return ("profiles");
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
	} else if (signal == "profiles") {
		colprof::ExportProfilesServiceResponse r;
		r.mutable_partial_success()->set_rejected_profiles(rejected);
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

static std::string
hexstr(const std::string &bytes)
{
	static const char digits[] = "0123456789abcdef";
	std::string out;

	for (unsigned char c : bytes) {
		out.push_back(digits[c >> 4]);
		out.push_back(digits[c & 15]);
	}
	return (out);
}

static std::string
anyvalue(const opentelemetry::proto::common::v1::AnyValue &v)
{

	switch (v.value_case()) {
	case opentelemetry::proto::common::v1::AnyValue::kStringValue:
		return (v.string_value());
	case opentelemetry::proto::common::v1::AnyValue::kIntValue:
		return (std::to_string(v.int_value()));
	case opentelemetry::proto::common::v1::AnyValue::kBoolValue:
		return (v.bool_value() ? "true" : "false");
	case opentelemetry::proto::common::v1::AnyValue::kDoubleValue:
		return (std::to_string(v.double_value()));
	default:
		return ("?");
	}
}

/* Duplicate entries of a table, by serialized value. */
template <typename T>
static int
check_table(const char *name, const T &table, int &bad)
{
	std::set<std::string> seen;
	std::string zero;

	if (table.size() == 0) {
		std::cerr << name << ": missing (needs its zero value)\n";
		bad++;
		return (0);
	}
	if (table.Get(0).ByteSizeLong() != 0) {
		std::cerr << name << "[0]: not the zero value\n";
		bad++;
	}
	for (int i = 0; i < table.size(); i++) {
		std::string s;

		table.Get(i).SerializeToString(&s);
		if (!seen.insert(s).second) {
			std::cerr << name << "[" << i << "]: duplicate\n";
			bad++;
		}
	}
	return (table.size());
}

static int
profile_check(const char *pbpath)
{
	colprof::ExportProfilesServiceRequest req;
	std::vector<std::string> lines;
	int bad = 0;

	if (!req.ParseFromString(slurp(pbpath))) {
		std::cerr << "otlp_pb_oracle: protobuf does not parse\n";
		return (1);
	}
	const prof::ProfilesDictionary &d = req.dictionary();
	int nmap = check_table("mapping_table", d.mapping_table(), bad);
	int nloc = check_table("location_table", d.location_table(), bad);
	int nfun = check_table("function_table", d.function_table(), bad);
	int nlink = check_table("link_table", d.link_table(), bad);
	int nattr = check_table("attribute_table", d.attribute_table(), bad);
	int nstack = check_table("stack_table", d.stack_table(), bad);
	int nstr = d.string_table_size();
	std::set<std::string> strs;

	if (nstr == 0 || d.string_table(0) != "") {
		std::cerr << "string_table[0]: must be \"\"\n";
		bad++;
	}
	for (int i = 0; i < nstr; i++)
		if (!strs.insert(d.string_table(i)).second) {
			std::cerr << "string_table[" << i << "]: duplicate\n";
			bad++;
		}
	auto str = [&](int i) -> std::string {
		if (i < 0 || i >= nstr) {
			std::cerr << "string index " << i << " out of range\n";
			bad++;
			return ("?");
		}
		return (d.string_table(i));
	};
	auto in = [&](const char *what, int i, int n) -> bool {
		if (i < 0 || i >= n) {
			std::cerr << what << " index " << i <<
			    " out of range\n";
			bad++;
			return (false);
		}
		return (true);
	};
	for (int i = 1; i < nmap; i++)
		(void)str(d.mapping_table(i).filename_strindex());
	for (int i = 1; i < nfun; i++) {
		(void)str(d.function_table(i).name_strindex());
		(void)str(d.function_table(i).system_name_strindex());
	}
	for (int i = 1; i < nattr; i++)
		(void)str(d.attribute_table(i).key_strindex());
	for (const auto &rp : req.resource_profiles()) {
		std::string service = "?";

		for (const auto &kv : rp.resource().attributes())
			if (kv.key() == "service.name")
				service = kv.value().string_value();
		for (const auto &sp : rp.scope_profiles())
		for (const auto &p : sp.profiles()) {
			std::string type = str(p.sample_type().type_strindex()) +
			    "/" + str(p.sample_type().unit_strindex());

			for (int a : p.attribute_indices())
				(void)in("profile attribute", a, nattr);
			for (const auto &s : p.samples()) {
				std::vector<std::string> attrs;
				std::set<std::string> keys;
				std::string frames;
				long long total = 0;

				if (s.values_size() == 0 &&
				    s.timestamps_unix_nano_size() == 0) {
					std::cerr << "sample without values or "
					    "timestamps\n";
					bad++;
				}
				if (s.values_size() > 0 &&
				    s.timestamps_unix_nano_size() > 0 &&
				    s.values_size() !=
				    s.timestamps_unix_nano_size()) {
					std::cerr << "sample with unequal value "
					    "and timestamp counts\n";
					bad++;
				}
				for (long long v : s.values())
					total += v;
				if (s.values_size() == 0)
					total = s.timestamps_unix_nano_size();
				for (int a : s.attribute_indices()) {
					if (!in("sample attribute", a, nattr))
						continue;
					const auto &kv = d.attribute_table(a);
					std::string k = str(kv.key_strindex());

					if (!keys.insert(k).second) {
						std::cerr << "sample attribute "
						    "key " << k << " twice\n";
						bad++;
					}
					attrs.push_back(k + "=" +
					    anyvalue(kv.value()));
				}
				if (s.link_index() != 0 &&
				    in("link", s.link_index(), nlink))
					attrs.push_back("link=" + hexstr(
					    d.link_table(s.link_index()).
					    trace_id()) + "/" + hexstr(
					    d.link_table(s.link_index()).
					    span_id()));
				std::sort(attrs.begin(), attrs.end());
				if (s.stack_index() != 0 &&
				    in("stack", s.stack_index(), nstack))
				for (int li : d.stack_table(s.stack_index()).
				    location_indices()) {
					if (!in("location", li, nloc))
						continue;
					const auto &l = d.location_table(li);
					std::string mod, f;
					char addr[32];

					if (l.mapping_index() != 0 &&
					    in("mapping", l.mapping_index(),
					    nmap))
						mod = str(d.mapping_table(
						    l.mapping_index()).
						    filename_strindex());
					if (l.lines_size() > 0 &&
					    in("function", l.lines(0).
					    function_index(), nfun))
						f = str(d.function_table(
						    l.lines(0).function_index()).
						    name_strindex());
					else {
						std::snprintf(addr,
						    sizeof(addr), "0x%llx",
						    (unsigned long long)
						    l.address());
						f = addr;
					}
					if (!frames.empty())
						frames += ";";
					frames += mod.empty() ? f :
					    mod + "`" + f;
				}
				std::string a;
				for (const auto &x : attrs)
					a += (a.empty() ? "" : ",") + x;
				lines.push_back(service + "|" + type + "|" + a +
				    "|" + frames + "|" + std::to_string(total));
			}
		}
	}
	std::sort(lines.begin(), lines.end());
	for (const auto &l : lines)
		std::cout << l << "\n";
	return (bad > 0 ? 1 : 0);
}

int
main(int argc, char **argv)
{

	if (argc == 3 && std::strcmp(argv[1], "profile") == 0)
		return (profile_check(argv[2]));

	if (argc == 4 && std::strcmp(argv[1], "compare") == 0)
		return (compare(argv[2], argv[3]));
	if (argc == 4 && std::strcmp(argv[1], "decode") == 0)
		return (decode(argv[2], argv[3]));
	if ((argc == 4 || argc == 5) && std::strcmp(argv[1], "response") == 0)
		return (response(argv[2], std::atoll(argv[3]),
		    argc == 5 ? argv[4] : ""));
	std::cerr << "usage: otlp_pb_oracle compare request.json request.pb\n"
	    "       otlp_pb_oracle decode signal request.pb\n"
	    "       otlp_pb_oracle response signal rejected [message]\n"
	    "       otlp_pb_oracle profile request.pb\n";
	return (2);
}
