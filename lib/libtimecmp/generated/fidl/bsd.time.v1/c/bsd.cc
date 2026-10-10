// Generated C bridge; compile as C++20.
#include <fidl/bsd/c_bridge.h>
#include <fidl/bsd.time.v1/cpp/bsd.h>
#include <fidl/bsd.time.v1/c/bridge.h>
using fidl::bsd::CBoundary;
using namespace fidl::bsd::generated;
namespace { struct Bridge_bsd_time_v1_Time : bsd_time_v1::bsd::TimeServer {
  fidl_bsd_connection* connection;
  bsd_time_v1_Time_server handlers;
  void* context;
  Bridge_bsd_time_v1_Time(fidl_bsd_connection* c, const bsd_time_v1_Time_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void GetProtocolInfo(::fidl::bsd::Empty value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.GetProtocolInfo) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_fidl_bsd_empty view(value);
    handlers.GetProtocolInfo(context,connection,request.get(),&view.data);
  }
  void Get(::fidl::bsd::Empty value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Get) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_fidl_bsd_empty view(value);
    handlers.Get(context,connection,request.get(),&view.data);
  }
  void Set(::bsd_time_v1::Timestamp value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Set) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_time_v1_Timestamp view(value);
    handlers.Set(context,connection,request.get(),&view.data);
  }
  void Adjust(::bsd_time_v1::Delta value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Adjust) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_time_v1_Delta view(value);
    handlers.Adjust(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_time_v1_Time_bind(fidl_bsd_connection* connection,const bsd_time_v1_Time_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_time_v1_Time>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_time_v1_Time_GetProtocolInfo(fidl_bsd_connection* connection,const fidl_bsd_empty* request,bsd_time_v1_Time_GetProtocolInfo_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_time_v1::bsd::TimeClient client(*connection->value);
    auto result=client.GetProtocolInfo(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_time_v1_ProtocolInfo> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_time_v1_Time_GetProtocolInfo_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_time_v1_ProtocolInfo* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_time_v1::bsd::TimeServer::ReplyGetProtocolInfo(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_time_v1_Time_Get(fidl_bsd_connection* connection,const fidl_bsd_empty* request,bsd_time_v1_Time_Get_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_time_v1::bsd::TimeClient client(*connection->value);
    auto result=client.Get(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_time_v1_Time_Get_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_time_v1_Time_Get_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_time_v1_Time_Get_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_time_v1::bsd::TimeServer::ReplyGet(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_time_v1_Time_Set(fidl_bsd_connection* connection,const bsd_time_v1_Timestamp* request,bsd_time_v1_Time_Set_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_time_v1::bsd::TimeClient client(*connection->value);
    auto result=client.Set(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_time_v1_Time_Set_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_time_v1_Time_Set_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_time_v1_Time_Set_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_time_v1::bsd::TimeServer::ReplySet(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_time_v1_Time_Adjust(fidl_bsd_connection* connection,const bsd_time_v1_Delta* request,bsd_time_v1_Time_Adjust_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_time_v1::bsd::TimeClient client(*connection->value);
    auto result=client.Adjust(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_time_v1_Time_Adjust_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_time_v1_Time_Adjust_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_time_v1_Time_Adjust_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_time_v1::bsd::TimeServer::ReplyAdjust(*connection->value,*request->value,FromC(response));
    return error;
  });
}
