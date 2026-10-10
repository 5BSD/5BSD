// Generated C bridge; compile as C++20.
#include <fidl/bsd/c_bridge.h>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
#include <fidl/bsd.runtime.test/c/bridge.h>
using fidl::bsd::CBoundary;
using namespace fidl::bsd::generated;
namespace { struct Bridge_bsd_runtime_test_AjarSurface : bsd_runtime_test::bsd::AjarSurfaceServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_AjarSurface_server handlers;
  void* context;
  Bridge_bsd_runtime_test_AjarSurface(fidl_bsd_connection* c, const bsd_runtime_test_AjarSurface_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void OnUnknownMethod(uint64_t ordinal, bool two_way) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal,two_way); }
}; }
extern "C" int bsd_runtime_test_AjarSurface_bind(fidl_bsd_connection* connection,const bsd_runtime_test_AjarSurface_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_AjarSurface>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
namespace { struct Events_bsd_runtime_test_AjarSurface : bsd_runtime_test::bsd::AjarSurfaceEvents {
  bsd_runtime_test_AjarSurface_events handlers; void* context;
  Events_bsd_runtime_test_AjarSurface(const bsd_runtime_test_AjarSurface_events& h,void* c):handlers(h),context(c){}
  void OnUnknownEvent(uint64_t ordinal) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal); }
}; }
extern "C" int bsd_runtime_test_AjarSurface_bind_events(fidl_bsd_connection* connection,const bsd_runtime_test_AjarSurface_events* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Events_bsd_runtime_test_AjarSurface>(*handlers,context);
    connection->value->SetEventHandler([bridge,connection](auto message){bridge->Dispatch(*connection->value,std::move(message));}); return 0;
  });
}
namespace { struct Bridge_bsd_runtime_test_ClosedSurface : bsd_runtime_test::bsd::ClosedSurfaceServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_ClosedSurface_server handlers;
  void* context;
  Bridge_bsd_runtime_test_ClosedSurface(fidl_bsd_connection* c, const bsd_runtime_test_ClosedSurface_server& h, void* x) : connection(c), handlers(h), context(x) {}
}; }
extern "C" int bsd_runtime_test_ClosedSurface_bind(fidl_bsd_connection* connection,const bsd_runtime_test_ClosedSurface_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_ClosedSurface>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
namespace { struct Bridge_bsd_runtime_test_Collections : bsd_runtime_test::bsd::CollectionsServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_Collections_server handlers;
  void* context;
  Bridge_bsd_runtime_test_Collections(fidl_bsd_connection* c, const bsd_runtime_test_Collections_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void Echo(::bsd_runtime_test::Collection value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Echo) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Collection view(value);
    handlers.Echo(context,connection,request.get(),&view.data);
  }
  void Configure(::bsd_runtime_test::Configuration value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Configure) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Configuration view(value);
    handlers.Configure(context,connection,request.get(),&view.data);
  }
  void Check(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Check) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.Check(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_runtime_test_Collections_bind(fidl_bsd_connection* connection,const bsd_runtime_test_Collections_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_Collections>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_Collections_Echo(fidl_bsd_connection* connection,const bsd_runtime_test_Collection* request,bsd_runtime_test_Collections_Echo_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::CollectionsClient client(*connection->value);
    auto result=client.Echo(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Collection> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Collections_Echo_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Collection* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::CollectionsServer::ReplyEcho(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Collections_Configure(fidl_bsd_connection* connection,const bsd_runtime_test_Configuration* request,bsd_runtime_test_Collections_Configure_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::CollectionsClient client(*connection->value);
    auto result=client.Configure(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Configuration> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Collections_Configure_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Configuration* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::CollectionsServer::ReplyConfigure(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Collections_Check(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request,bsd_runtime_test_Collections_Check_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::CollectionsClient client(*connection->value);
    auto result=client.Check(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Collections_Check_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Collections_Check_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Collections_Check_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::CollectionsServer::ReplyCheck(*connection->value,*request->value,FromC(response));
    return error;
  });
}
namespace { struct Bridge_bsd_runtime_test_EndpointExchange : bsd_runtime_test::bsd::EndpointExchangeServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_EndpointExchange_server handlers;
  void* context;
  Bridge_bsd_runtime_test_EndpointExchange(fidl_bsd_connection* c, const bsd_runtime_test_EndpointExchange_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void RoundTrip(::bsd_runtime_test::EndpointRequest value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.RoundTrip) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_EndpointRequest view(value);
    handlers.RoundTrip(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_runtime_test_EndpointExchange_bind(fidl_bsd_connection* connection,const bsd_runtime_test_EndpointExchange_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_EndpointExchange>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_EndpointExchange_RoundTrip(fidl_bsd_connection* connection,const bsd_runtime_test_EndpointRequest* request,bsd_runtime_test_EndpointExchange_RoundTrip_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::EndpointExchangeClient client(*connection->value);
    auto result=client.RoundTrip(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_EndpointRequest> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_EndpointExchange_RoundTrip_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_EndpointRequest* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::EndpointExchangeServer::ReplyRoundTrip(*connection->value,*request->value,FromC(response));
    return error;
  });
}
namespace { struct Bridge_bsd_runtime_test_Flexible : bsd_runtime_test::bsd::FlexibleServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_Flexible_server handlers;
  void* context;
  Bridge_bsd_runtime_test_Flexible(fidl_bsd_connection* c, const bsd_runtime_test_Flexible_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void Ping(::fidl::bsd::Empty value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Ping) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_fidl_bsd_empty view(value);
    handlers.Ping(context,connection,request.get(),&view.data);
  }
  void Echo(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Echo) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.Echo(context,connection,request.get(),&view.data);
  }
  void Check(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Check) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.Check(context,connection,request.get(),&view.data);
  }
  void Note(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Note) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.Note(context,connection,request.get(),&view.data);
  }
  void StrictPing(::fidl::bsd::Empty value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.StrictPing) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_fidl_bsd_empty view(value);
    handlers.StrictPing(context,connection,request.get(),&view.data);
  }
  void OnUnknownMethod(uint64_t ordinal, bool two_way) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal,two_way); }
}; }
extern "C" int bsd_runtime_test_Flexible_bind(fidl_bsd_connection* connection,const bsd_runtime_test_Flexible_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_Flexible>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_Flexible_Ping(fidl_bsd_connection* connection,const fidl_bsd_empty* request,bsd_runtime_test_Flexible_Ping_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::FlexibleClient client(*connection->value);
    auto result=client.Ping(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Flexible_Ping_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Flexible_Ping_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Flexible_Ping_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::FlexibleServer::ReplyPing(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Flexible_Echo(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request,bsd_runtime_test_Flexible_Echo_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::FlexibleClient client(*connection->value);
    auto result=client.Echo(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Flexible_Echo_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Flexible_Echo_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Flexible_Echo_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::FlexibleServer::ReplyEcho(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Flexible_Check(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request,bsd_runtime_test_Flexible_Check_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::FlexibleClient client(*connection->value);
    auto result=client.Check(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Flexible_Check_Result> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Flexible_Check_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Flexible_Check_Result* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::FlexibleServer::ReplyCheck(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Flexible_Note(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request) {
  if(!connection || !request) return EINVAL;
  return CBoundary([&]() -> int { bsd_runtime_test::bsd::FlexibleClient client(*connection->value); return client.Note(FromC(request)); });
}
extern "C" int bsd_runtime_test_Flexible_Changed(fidl_bsd_connection* connection,const bsd_runtime_test_Response* event) {
  if(!connection || !event) return EINVAL;
  return CBoundary([&]() -> int { return bsd_runtime_test::bsd::FlexibleServer::Changed(*connection->value,FromC(event)); });
}
extern "C" int bsd_runtime_test_Flexible_StrictPing(fidl_bsd_connection* connection,const fidl_bsd_empty* request,bsd_runtime_test_Flexible_StrictPing_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::FlexibleClient client(*connection->value);
    auto result=client.StrictPing(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_fidl_bsd_empty> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Flexible_StrictPing_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const fidl_bsd_empty* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::FlexibleServer::ReplyStrictPing(*connection->value,*request->value,FromC(response));
    return error;
  });
}
namespace { struct Events_bsd_runtime_test_Flexible : bsd_runtime_test::bsd::FlexibleEvents {
  bsd_runtime_test_Flexible_events handlers; void* context;
  Events_bsd_runtime_test_Flexible(const bsd_runtime_test_Flexible_events& h,void* c):handlers(h),context(c){}
  void Changed(::bsd_runtime_test::Response value,const fidl::bsd::Incoming&) override {
    View_bsd_runtime_test_Response view(value); if(handlers.Changed) handlers.Changed(context,&view.data);
  }
  void OnUnknownEvent(uint64_t ordinal) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal); }
}; }
extern "C" int bsd_runtime_test_Flexible_bind_events(fidl_bsd_connection* connection,const bsd_runtime_test_Flexible_events* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Events_bsd_runtime_test_Flexible>(*handlers,context);
    connection->value->SetEventHandler([bridge,connection](auto message){bridge->Dispatch(*connection->value,std::move(message));}); return 0;
  });
}
namespace { struct Bridge_bsd_runtime_test_Naming : bsd_runtime_test::bsd::NamingServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_Naming_server handlers;
  void* context;
  Bridge_bsd_runtime_test_Naming(fidl_bsd_connection* c, const bsd_runtime_test_Naming_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void RoundTrip(::bsd_runtime_test::EscapedNames value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.RoundTrip) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_EscapedNames view(value);
    handlers.RoundTrip(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_runtime_test_Naming_bind(fidl_bsd_connection* connection,const bsd_runtime_test_Naming_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_Naming>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_Naming_RoundTrip(fidl_bsd_connection* connection,const bsd_runtime_test_EscapedNames* request,bsd_runtime_test_Naming_RoundTrip_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::NamingClient client(*connection->value);
    auto result=client.RoundTrip(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_EscapedNames> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Naming_RoundTrip_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_EscapedNames* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::NamingServer::ReplyRoundTrip(*connection->value,*request->value,FromC(response));
    return error;
  });
}
namespace { struct Bridge_bsd_runtime_test_OpenSurface : bsd_runtime_test::bsd::OpenSurfaceServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_OpenSurface_server handlers;
  void* context;
  Bridge_bsd_runtime_test_OpenSurface(fidl_bsd_connection* c, const bsd_runtime_test_OpenSurface_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void OnUnknownMethod(uint64_t ordinal, bool two_way) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal,two_way); }
}; }
extern "C" int bsd_runtime_test_OpenSurface_bind(fidl_bsd_connection* connection,const bsd_runtime_test_OpenSurface_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_OpenSurface>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
namespace { struct Events_bsd_runtime_test_OpenSurface : bsd_runtime_test::bsd::OpenSurfaceEvents {
  bsd_runtime_test_OpenSurface_events handlers; void* context;
  Events_bsd_runtime_test_OpenSurface(const bsd_runtime_test_OpenSurface_events& h,void* c):handlers(h),context(c){}
  void OnUnknownEvent(uint64_t ordinal) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal); }
}; }
extern "C" int bsd_runtime_test_OpenSurface_bind_events(fidl_bsd_connection* connection,const bsd_runtime_test_OpenSurface_events* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Events_bsd_runtime_test_OpenSurface>(*handlers,context);
    connection->value->SetEventHandler([bridge,connection](auto message){bridge->Dispatch(*connection->value,std::move(message));}); return 0;
  });
}
namespace { struct Bridge_bsd_runtime_test_Service : bsd_runtime_test::bsd::ServiceServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_Service_server handlers;
  void* context;
  Bridge_bsd_runtime_test_Service(fidl_bsd_connection* c, const bsd_runtime_test_Service_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void RoundTrip(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.RoundTrip) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.RoundTrip(context,connection,request.get(),&view.data);
  }
  void Take(::bsd_runtime_test::ReadOnly value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Take) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_ReadOnly view(value);
    handlers.Take(context,connection,request.get(),&view.data);
  }
  void Notify(::bsd_runtime_test::Request value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Notify) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_Request view(value);
    handlers.Notify(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_runtime_test_Service_bind(fidl_bsd_connection* connection,const bsd_runtime_test_Service_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_Service>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_Service_RoundTrip(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request,bsd_runtime_test_Service_RoundTrip_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::ServiceClient client(*connection->value);
    auto result=client.RoundTrip(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Response> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Service_RoundTrip_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Response* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::ServiceServer::ReplyRoundTrip(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Service_Take(fidl_bsd_connection* connection,const bsd_runtime_test_ReadOnly* request,bsd_runtime_test_Service_Take_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::ServiceClient client(*connection->value);
    auto result=client.Take(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_Response> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Service_Take_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_Response* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::ServiceServer::ReplyTake(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Service_Notify(fidl_bsd_connection* connection,const bsd_runtime_test_Request* request) {
  if(!connection || !request) return EINVAL;
  return CBoundary([&]() -> int { bsd_runtime_test::bsd::ServiceClient client(*connection->value); return client.Notify(FromC(request)); });
}
extern "C" int bsd_runtime_test_Service_Changed(fidl_bsd_connection* connection,const bsd_runtime_test_Response* event) {
  if(!connection || !event) return EINVAL;
  return CBoundary([&]() -> int { return bsd_runtime_test::bsd::ServiceServer::Changed(*connection->value,FromC(event)); });
}
namespace { struct Events_bsd_runtime_test_Service : bsd_runtime_test::bsd::ServiceEvents {
  bsd_runtime_test_Service_events handlers; void* context;
  Events_bsd_runtime_test_Service(const bsd_runtime_test_Service_events& h,void* c):handlers(h),context(c){}
  void Changed(::bsd_runtime_test::Response value,const fidl::bsd::Incoming&) override {
    View_bsd_runtime_test_Response view(value); if(handlers.Changed) handlers.Changed(context,&view.data);
  }
}; }
extern "C" int bsd_runtime_test_Service_bind_events(fidl_bsd_connection* connection,const bsd_runtime_test_Service_events* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Events_bsd_runtime_test_Service>(*handlers,context);
    connection->value->SetEventHandler([bridge,connection](auto message){bridge->Dispatch(*connection->value,std::move(message));}); return 0;
  });
}
namespace { struct Bridge_bsd_runtime_test_Shapes : bsd_runtime_test::bsd::ShapesServer {
  fidl_bsd_connection* connection;
  bsd_runtime_test_Shapes_server handlers;
  void* context;
  Bridge_bsd_runtime_test_Shapes(fidl_bsd_connection* c, const bsd_runtime_test_Shapes_server& h, void* x) : connection(c), handlers(h), context(x) {}
  void Ping(::fidl::bsd::Empty value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Ping) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_fidl_bsd_empty view(value);
    handlers.Ping(context,connection,request.get(),&view.data);
  }
  void Echo(::bsd_runtime_test::ShapesEchoRequest value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {
    if (!handlers.Echo) { connection->value->Close(ENOSYS); return; }
    fidl::bsd::CRequest request(new fidl_bsd_request);
    request->value=std::move(incoming);
    View_bsd_runtime_test_ShapesEchoRequest view(value);
    handlers.Echo(context,connection,request.get(),&view.data);
  }
}; }
extern "C" int bsd_runtime_test_Shapes_bind(fidl_bsd_connection* connection,const bsd_runtime_test_Shapes_server* handlers,void* context) {
  if(!connection || !handlers) return EINVAL;
  return CBoundary([&]() -> int {
    auto bridge=std::make_shared<Bridge_bsd_runtime_test_Shapes>(connection,*handlers,context);
    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };
    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;
  });
}
extern "C" int bsd_runtime_test_Shapes_Ping(fidl_bsd_connection* connection,const fidl_bsd_empty* request,bsd_runtime_test_Shapes_Ping_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::ShapesClient client(*connection->value);
    auto result=client.Ping(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_fidl_bsd_empty> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Shapes_Ping_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const fidl_bsd_empty* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::ShapesServer::ReplyPing(*connection->value,*request->value,FromC(response));
    return error;
  });
}
extern "C" int bsd_runtime_test_Shapes_Echo(fidl_bsd_connection* connection,const bsd_runtime_test_ShapesEchoRequest* request,bsd_runtime_test_Shapes_Echo_callback callback,void* context,uint32_t* txid) {
  if(!connection || !request || !callback || !txid) return EINVAL;
  *txid=0;
  return CBoundary([&]() -> int {
    bsd_runtime_test::bsd::ShapesClient client(*connection->value);
    auto result=client.Echo(FromC(request),[callback,context](auto result) {
      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }
      std::optional<View_bsd_runtime_test_ShapesEchoResponse> view;
      int error = CBoundary([&]() -> int { view.emplace(result.value()); return 0; });
      if (error) { callback(context,error,nullptr); return; }
      callback(context,0,&view->data);
    });
    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;
  });
}
extern "C" int bsd_runtime_test_Shapes_Echo_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const bsd_runtime_test_ShapesEchoResponse* response) {
  if(!connection || !request || !response) return EINVAL;
  if(request->value->replied()) return EALREADY;
  return CBoundary([&]() -> int {
    int error=bsd_runtime_test::bsd::ShapesServer::ReplyEcho(*connection->value,*request->value,FromC(response));
    return error;
  });
}
