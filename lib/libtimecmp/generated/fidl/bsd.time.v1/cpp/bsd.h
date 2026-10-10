// Generated BSD adapters; do not edit.
#pragma once
#include <fidl/bsd/runtime.h>
#include <fidl/bsd.time.v1/cpp/natural_types.h>
namespace bsd_time_v1::bsd {
inline void fidl_bsd_discard_events_Time(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);
class TimeClient {
 public:
  explicit TimeClient(::fidl::bsd::Connection& connection) : connection_(connection) { connection.EnsureEventHandler([&connection](auto message){ fidl_bsd_discard_events_Time(connection,std::move(message)); }); }
  ::fidl::bsd::Result<uint32_t> GetProtocolInfo(::fidl::bsd::Empty request, std::function<void(::fidl::bsd::Result<::bsd_time_v1::ProtocolInfo>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::fidl::bsd::Empty, ::bsd_time_v1::ProtocolInfo>(5276910095708089196ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Get(::fidl::bsd::Empty request, std::function<void(::fidl::bsd::Result<::bsd_time_v1::TimeGetResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::fidl::bsd::Empty, ::bsd_time_v1::TimeGetResult>(3914709581465579447ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Set(::bsd_time_v1::Timestamp request, std::function<void(::fidl::bsd::Result<::bsd_time_v1::TimeSetResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_time_v1::Timestamp, ::bsd_time_v1::TimeSetResult>(2007334572207215047ULL, std::move(request), std::move(completion), false);
  }
  ::fidl::bsd::Result<uint32_t> Adjust(::bsd_time_v1::Delta request, std::function<void(::fidl::bsd::Result<::bsd_time_v1::TimeAdjustResult>)> callback) {
    if (!callback) return fit::error(EINVAL);
    auto completion = std::move(callback);
    return connection_.Call<::bsd_time_v1::Delta, ::bsd_time_v1::TimeAdjustResult>(5749555094228569457ULL, std::move(request), std::move(completion), false);
  }
 private:
  ::fidl::bsd::Connection& connection_;
};
class TimeServer {
 public:
  virtual ~TimeServer() = default;
  virtual void GetProtocolInfo(::fidl::bsd::Empty request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyGetProtocolInfo(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_time_v1::ProtocolInfo response) {
    if (context.Validate(5276910095708089196ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Get(::fidl::bsd::Empty request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyGet(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_time_v1::TimeGetResult response) {
    if (context.Validate(3914709581465579447ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Set(::bsd_time_v1::Timestamp request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplySet(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_time_v1::TimeSetResult response) {
    if (context.Validate(2007334572207215047ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void Adjust(::bsd_time_v1::Delta request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;
  static int ReplyAdjust(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, ::bsd_time_v1::TimeAdjustResult response) {
    if (context.Validate(5749555094228569457ULL, context.header().txid)) return EPROTO;
    return connection.Reply(context, std::move(response), false);
  }
  virtual void OnUnknownMethod(uint64_t, bool) {}
  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {
    switch (message->header().ordinal) {
    case 5276910095708089196ULL: {
      if (!(message->header().txid != 0) || message->Validate(5276910095708089196ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::fidl::bsd::Empty>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      GetProtocolInfo(std::move(decoded.value()), std::move(message)); return;
    }
    case 3914709581465579447ULL: {
      if (!(message->header().txid != 0) || message->Validate(3914709581465579447ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::fidl::bsd::Empty>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Get(std::move(decoded.value()), std::move(message)); return;
    }
    case 2007334572207215047ULL: {
      if (!(message->header().txid != 0) || message->Validate(2007334572207215047ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_time_v1::Timestamp>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Set(std::move(decoded.value()), std::move(message)); return;
    }
    case 5749555094228569457ULL: {
      if (!(message->header().txid != 0) || message->Validate(5749555094228569457ULL, message->header().txid)) { connection.Close(EPROTO); return; }
      auto decoded = message->Decode<::bsd_time_v1::Delta>();
      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }
      Adjust(std::move(decoded.value()), std::move(message)); return;
    }
    default: {
      int error = connection.HandleUnknown(*message, ::fidl::bsd::Openness::Closed);
      if (error) { connection.Close(error); return; }
      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;
    }
    }
  }
};
class TimeEvents {
 public:
  virtual ~TimeEvents() = default;
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
inline void fidl_bsd_discard_events_Time(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) { TimeEvents events; events.Dispatch(connection,std::move(message)); }
}
