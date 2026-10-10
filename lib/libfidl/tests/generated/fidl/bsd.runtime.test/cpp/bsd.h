// Generated BSD adapters; do not edit.
#pragma once
#include <fidl/bsd/runtime.h>
#include <fidl/bsd.runtime.test/cpp/natural_types.h>
namespace bsd_runtime_test::bsd {
inline void fidl_bsd_discard_events_AjarSurface(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class AjarSurfaceClient {
 public:
  explicit AjarSurfaceClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_AjarSurface(connection,std::move(message)); }); }
 private:
  ::fidl::bsd::Connection& connection_;
};
class AjarSurfaceServer {
 public:
  virtual ~AjarSurfaceServer() = default;
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Ajar);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class AjarSurfaceEvents {
 public:
  virtual ~AjarSurfaceEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Ajar);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_AjarSurface(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { AjarSurfaceEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_ClosedSurface(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class ClosedSurfaceClient {
 public:
  explicit ClosedSurfaceClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_ClosedSurface(connection,std::move(message)); }); }
 private:
  ::fidl::bsd::Connection& connection_;
};
class ClosedSurfaceServer {
 public:
  virtual ~ClosedSurfaceServer() = default;
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class ClosedSurfaceEvents {
 public:
  virtual ~ClosedSurfaceEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_ClosedSurface(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { ClosedSurfaceEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_Collections(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class CollectionsClient {
 public:
  explicit CollectionsClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Collections(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> Echo(::bsd_runtime_test::Collection request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::Collection>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::Collection, ::bsd_runtime_test::Collection>(1804284354618396233ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Configure(::bsd_runtime_test::Configuration request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::Configuration>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::Configuration, ::bsd_runtime_test::Configuration>(6401817887093618988ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Check(::bsd_runtime_test::Request request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::CollectionsCheckResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::Request, ::bsd_runtime_test::CollectionsCheckResult>(7644560012736951822ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class CollectionsServer {
 public:
  virtual ~CollectionsServer() = default;
  virtual void Echo(::bsd_runtime_test::Collection request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyEcho(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::Collection response) {
    if (context.Validate(1804284354618396233ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Configure(::bsd_runtime_test::Configuration request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyConfigure(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::Configuration response) {
    if (context.Validate(6401817887093618988ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Check(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyCheck(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::CollectionsCheckResult response) {
    if (context.Validate(7644560012736951822ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 1804284354618396233ULL: {
      if (!(message->header().txid != 0) || message->Validate(1804284354618396233ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Collection>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Echo(std::move(decoded.value()), std::move(message)); return;
    }
    case 6401817887093618988ULL: {
      if (!(message->header().txid != 0) || message->Validate(6401817887093618988ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Configuration>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Configure(std::move(decoded.value()), std::move(message)); return;
    }
    case 7644560012736951822ULL: {
      if (!(message->header().txid != 0) || message->Validate(7644560012736951822ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Check(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class CollectionsEvents {
 public:
  virtual ~CollectionsEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_Collections(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { CollectionsEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_EndpointExchange(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class EndpointExchangeClient {
 public:
  explicit EndpointExchangeClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_EndpointExchange(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> RoundTrip(::bsd_runtime_test::EndpointRequest request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::EndpointRequest>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::EndpointRequest, ::bsd_runtime_test::EndpointRequest>(8128056957808125708ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class EndpointExchangeServer {
 public:
  virtual ~EndpointExchangeServer() = default;
  virtual void RoundTrip(::bsd_runtime_test::EndpointRequest request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyRoundTrip(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::EndpointRequest response) {
    if (context.Validate(8128056957808125708ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 8128056957808125708ULL: {
      if (!(message->header().txid != 0) || message->Validate(8128056957808125708ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::EndpointRequest>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      RoundTrip(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class EndpointExchangeEvents {
 public:
  virtual ~EndpointExchangeEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_EndpointExchange(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { EndpointExchangeEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_Flexible(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class FlexibleClient {
 public:
  explicit FlexibleClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Flexible(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> Ping(::fidl::bsd::Empty request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::FlexiblePingResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = [callback=std::move(callback)](auto result) mutable {
      if (result.is_ok() && result->framework_err()) { callback(fit::error(EOPNOTSUPP)); return; }
      callback(std::move(result));
    };
    return connection_.Call<::fidl::bsd::Empty, ::bsd_runtime_test::FlexiblePingResult>(3602317343050944474ULL, std::move(request), std::move(completion), true);
  }
  ::fidl::bsd::Result<uint32_t> Echo(::bsd_runtime_test::Request request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::FlexibleEchoResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = [callback=std::move(callback)](auto result) mutable {
      if (result.is_ok() && result->framework_err()) { callback(fit::error(EOPNOTSUPP)); return; }
      callback(std::move(result));
    };
    return connection_.Call<::bsd_runtime_test::Request, ::bsd_runtime_test::FlexibleEchoResult>(8944178104972771519ULL, std::move(request), std::move(completion), true);
  }
  ::fidl::bsd::Result<uint32_t> Check(::bsd_runtime_test::Request request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::FlexibleCheckResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = [callback=std::move(callback)](auto result) mutable {
      if (result.is_ok() && result->framework_err()) { callback(fit::error(EOPNOTSUPP)); return; }
      callback(std::move(result));
    };
    return connection_.Call<::bsd_runtime_test::Request, ::bsd_runtime_test::FlexibleCheckResult>(7584068723023633537ULL, std::move(request), std::move(completion), true);
  }
  int Note(::bsd_runtime_test::Request request) { return connection_.Send(2537489178001731479ULL, std::move(request), true); }
  ::fidl::bsd::Result<uint32_t> StrictPing(::fidl::bsd::Empty request, std::function<void(::fidl::bsd::Result<::fidl::bsd::Empty>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::fidl::bsd::Empty, ::fidl::bsd::Empty>(8183355633474720249ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class FlexibleServer {
 public:
  virtual ~FlexibleServer() = default;
  virtual void Ping(::fidl::bsd::Empty request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyPing(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::FlexiblePingResult response) {
    if (context.Validate(3602317343050944474ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), true);
  }
  virtual void Echo(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyEcho(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::FlexibleEchoResult response) {
    if (context.Validate(8944178104972771519ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), true);
  }
  virtual void Check(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyCheck(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::FlexibleCheckResult response) {
    if (context.Validate(7584068723023633537ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), true);
  }
  virtual void Note(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int Changed(::fidl::bsd::Connection& connection, ::bsd_runtime_test::Response event) { return connection.Send(2962546122912921191ULL, std::move(event), true); }
  virtual void StrictPing(::fidl::bsd::Empty request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyStrictPing(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::fidl::bsd::Empty response) {
    if (context.Validate(8183355633474720249ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 3602317343050944474ULL: {
      if (!(message->header().txid != 0) || message->Validate(3602317343050944474ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::fidl::bsd::Empty>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Ping(std::move(decoded.value()), std::move(message)); return;
    }
    case 8944178104972771519ULL: {
      if (!(message->header().txid != 0) || message->Validate(8944178104972771519ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Echo(std::move(decoded.value()), std::move(message)); return;
    }
    case 7584068723023633537ULL: {
      if (!(message->header().txid != 0) || message->Validate(7584068723023633537ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Check(std::move(decoded.value()), std::move(message)); return;
    }
    case 2537489178001731479ULL: {
      if (!(message->header().txid == 0) || message->Validate(2537489178001731479ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Note(std::move(decoded.value()), std::move(message)); return;
    }
    case 8183355633474720249ULL: {
      if (!(message->header().txid != 0) || message->Validate(8183355633474720249ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::fidl::bsd::Empty>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      StrictPing(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Open);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class FlexibleEvents {
 public:
  virtual ~FlexibleEvents() = default;
  virtual void Changed(::bsd_runtime_test::Response value, const ::fidl::bsd::Incoming& context) {};
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 2962546122912921191ULL: {
      if (message->Validate(2962546122912921191ULL, 0)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Response>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Changed(std::move(decoded.value()), *message); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Open);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_Flexible(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { FlexibleEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_Naming(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class NamingClient {
 public:
  explicit NamingClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Naming(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> RoundTrip(::bsd_runtime_test::EscapedNames request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::EscapedNames>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::EscapedNames, ::bsd_runtime_test::EscapedNames>(5794936637052860447ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class NamingServer {
 public:
  virtual ~NamingServer() = default;
  virtual void RoundTrip(::bsd_runtime_test::EscapedNames request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyRoundTrip(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::EscapedNames response) {
    if (context.Validate(5794936637052860447ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 5794936637052860447ULL: {
      if (!(message->header().txid != 0) || message->Validate(5794936637052860447ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::EscapedNames>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      RoundTrip(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class NamingEvents {
 public:
  virtual ~NamingEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_Naming(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { NamingEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_OpenSurface(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class OpenSurfaceClient {
 public:
  explicit OpenSurfaceClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_OpenSurface(connection,std::move(message)); }); }
 private:
  ::fidl::bsd::Connection& connection_;
};
class OpenSurfaceServer {
 public:
  virtual ~OpenSurfaceServer() = default;
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Open);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class OpenSurfaceEvents {
 public:
  virtual ~OpenSurfaceEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Open);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_OpenSurface(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { OpenSurfaceEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_Service(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class ServiceClient {
 public:
  explicit ServiceClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Service(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> RoundTrip(::bsd_runtime_test::Request request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::Response>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::Request, ::bsd_runtime_test::Response>(8323773374816640790ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Take(::bsd_runtime_test::ReadOnly request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::Response>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::ReadOnly, ::bsd_runtime_test::Response>(2183023553111572035ULL, std::move(request), std::move(completion), false);
  }
  int Notify(::bsd_runtime_test::Request request) { return connection_.Send(8022716801381730719ULL, std::move(request), false); }
 private:
  ::fidl::bsd::Connection& connection_;
};
class ServiceServer {
 public:
  virtual ~ServiceServer() = default;
  virtual void RoundTrip(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyRoundTrip(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::Response response) {
    if (context.Validate(8323773374816640790ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Take(::bsd_runtime_test::ReadOnly request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyTake(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::Response response) {
    if (context.Validate(2183023553111572035ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Notify(::bsd_runtime_test::Request request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int Changed(::fidl::bsd::Connection& connection, ::bsd_runtime_test::Response event) { return connection.Send(7764275307639556784ULL, std::move(event), false); }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 8323773374816640790ULL: {
      if (!(message->header().txid != 0) || message->Validate(8323773374816640790ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      RoundTrip(std::move(decoded.value()), std::move(message)); return;
    }
    case 2183023553111572035ULL: {
      if (!(message->header().txid != 0) || message->Validate(2183023553111572035ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::ReadOnly>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Take(std::move(decoded.value()), std::move(message)); return;
    }
    case 8022716801381730719ULL: {
      if (!(message->header().txid == 0) || message->Validate(8022716801381730719ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Request>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Notify(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class ServiceEvents {
 public:
  virtual ~ServiceEvents() = default;
  virtual void Changed(::bsd_runtime_test::Response value, const ::fidl::bsd::Incoming& context) {};
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 7764275307639556784ULL: {
      if (message->Validate(7764275307639556784ULL, 0)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::Response>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Changed(std::move(decoded.value()), *message); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_Service(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { ServiceEvents events; events.Dispatch(connection,std::move(message)); }
inline void fidl_bsd_discard_events_Shapes(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class ShapesClient {
 public:
  explicit ShapesClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Shapes(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> Ping(::fidl::bsd::Empty request, std::function<void(::fidl::bsd::Result<::fidl::bsd::Empty>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::fidl::bsd::Empty, ::fidl::bsd::Empty>(3406269359610544657ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Echo(::bsd_runtime_test::ShapesEchoRequest request, std::function<void(::fidl::bsd::Result<::bsd_runtime_test::ShapesEchoResponse>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_runtime_test::ShapesEchoRequest, ::bsd_runtime_test::ShapesEchoResponse>(2551981170178961328ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class ShapesServer {
 public:
  virtual ~ShapesServer() = default;
  virtual void Ping(::fidl::bsd::Empty request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyPing(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::fidl::bsd::Empty response) {
    if (context.Validate(3406269359610544657ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Echo(::bsd_runtime_test::ShapesEchoRequest request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyEcho(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_runtime_test::ShapesEchoResponse response) {
    if (context.Validate(2551981170178961328ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 3406269359610544657ULL: {
      if (!(message->header().txid != 0) || message->Validate(3406269359610544657ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::fidl::bsd::Empty>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Ping(std::move(decoded.value()), std::move(message)); return;
    }
    case 2551981170178961328ULL: {
      if (!(message->header().txid != 0) || message->Validate(2551981170178961328ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_runtime_test::ShapesEchoRequest>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Echo(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class ShapesEvents {
 public:
  virtual ~ShapesEvents() = default;
  virtual void OnUnknownEvent(uint64_t) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownEvent(message->header().ordinal); return;
    }
    }
  }
};
inline void fidl_bsd_discard_events_Shapes(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { ShapesEvents events; events.Dispatch(connection,std::move(message)); }
}
