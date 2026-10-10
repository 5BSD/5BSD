# SPDX-License-Identifier: BSD-2-Clause
"""Emit a checked C ABI over the same generated natural types and BSD runtime."""

def generate_c(ir, root, cpp, dependencies=()):
    library=ir['name']; prefix=library.replace('.','_')
    protocols=ir['protocol_declarations']
    used=set()
    for p in protocols:
        for m in p['methods']:
            for direction in ('request','response'):
                if m.get('has_'+direction): used.add(m['maybe_'+direction+'_payload']['identifier'])
    from generate_bsd_c_types import CTypes, cname
    types = CTypes(ir, cpp, used, dependencies)
    h=['/* Generated C bindings; do not edit. */','#pragma once','#include <fidl/bsd/runtime_c.h>','#include <stdbool.h>',
       '#ifdef __cplusplus','extern "C" {','#endif',
       '/* Outgoing buffers and descriptors are borrowed; descriptors are duplicated.',
       ' * Callback buffers last until return. Take a callback descriptor with',
       ' * fidl_bsd_take_fd() to retain it. Retain request contexts for deferred replies. */']
    cc=['// Generated C bridge; compile as C++20.','#include <fidl/bsd/c_bridge.h>',
        '#include <fidl/'+library+'/cpp/bsd.h>','#include <fidl/'+library+'/c/bridge.h>', 'using fidl::bsd::CBoundary;', 'using namespace fidl::bsd::generated;']
    h += types.header()
    bridge = ['// Generated private C++ conversions for the C ABI; do not edit.',
              '#pragma once', '#include <fidl/bsd/c_bridge.h>',
              '#include <fidl/'+library+'/cpp/natural_types.h>',
              '#include <fidl/'+library+'/c/bsd.h>']
    bridge += ['#include <fidl/'+d['name']+'/c/bridge.h>'
               for d in ir['library_dependencies'] if d['name'] != 'zx' or any(x['name'] == 'zx' for x in dependencies)]
    bridge += ['namespace fidl::bsd::generated {', *types.bridge(), '}']
    for p in protocols:
        pn=p['_cpp_name']; pc=prefix+'_'+pn; ns=prefix+'::bsd::'+pn
        h += [f'struct {pc}_server {{']
        for m in p['methods']:
            if m['has_request']:
                req=cname(m['maybe_request_payload']['identifier'])
                h += [f'    void (*{m["name"]})(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct {req} *);']
        if not any(m['has_request'] for m in p['methods']): h+=['    unsigned char unused;']
        if p['openness'] != 'closed': h += ['    void (*unknown_interaction)(void *, uint64_t, bool);']
        h+=['};',f'int {pc}_bind(struct fidl_bsd_connection *, const struct {pc}_server *, void *);']
        cc += [f'namespace {{ struct Bridge_{pc} : {ns}Server {{', '  fidl_bsd_connection* connection;',f'  {pc}_server handlers;', '  void* context;',
               f'  Bridge_{pc}(fidl_bsd_connection* c, const {pc}_server& h, void* x) : connection(c), handlers(h), context(x) {{}}']
        for m in p['methods']:
            mn=m['name']; ordinal=m['ordinal']
            if not m['has_request']:continue
            ident=m['maybe_request_payload']['identifier']; req=cname(ident)
            cc += [f'  void {mn}({cpp(ident)} value, std::unique_ptr<fidl::bsd::Incoming> incoming) override {{',
                   f'    if (!handlers.{mn}) {{ connection->value->Close(ENOSYS); return; }}',
                   '    fidl::bsd::CRequest request(new fidl_bsd_request);', '    request->value=std::move(incoming);',f'    View_{req} view(value);',
                   f'    handlers.{mn}(context,connection,request.get(),&view.data);','  }']
        if p['openness'] != 'closed': cc += ['  void OnUnknownMethod(uint64_t ordinal, bool two_way) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal,two_way); }']
        cc+=['}; }', f'extern "C" int {pc}_bind(fidl_bsd_connection* connection,const {pc}_server* handlers,void* context) {{',
             '  if(!connection || !handlers) return EINVAL;', '  return CBoundary([&]() -> int {', f'    auto bridge=std::make_shared<Bridge_{pc}>(connection,*handlers,context);',
             '    auto dispatch=[bridge](auto message){ bridge->Dispatch(*bridge->connection->value,std::move(message)); };',
             '    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;', '  });','}']
        for m in p['methods']:
            mn=m['name']; func=pc+'_'+mn; ordinal=m['ordinal']
            if m['has_request']:
                reqid=m['maybe_request_payload']['identifier']; req=cname(reqid)
                if m['has_response']:
                    respid=m['maybe_response_payload']['identifier']; resp=cname(respid)
                    h += [f'typedef void (*{func}_callback)(void *, int, struct {resp} *);',
                          f'int {func}(struct fidl_bsd_connection *, const struct {req} *, {func}_callback, void *, uint32_t *);',
                          f'int {func}_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct {resp} *);']
                    cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {req}* request,{func}_callback callback,void* context,uint32_t* txid) {{',
                           '  if(!connection || !request || !callback || !txid) return EINVAL;', '  *txid=0;', '  return CBoundary([&]() -> int {',
                           f'    {ns}Client client(*connection->value);',f'    auto result=client.{mn}(FromC(request),[callback,context](auto result) {{',
                           '      if(result.is_error()) { callback(context,result.error_value(),nullptr); return; }',
                           f'      std::optional<View_{resp}> view;', f'      int error = CBoundary([&]() -> int {{ view.emplace(result.value()); return 0; }});', '      if (error) { callback(context,error,nullptr); return; }', '      callback(context,0,&view->data);', '    });',
                           '    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;', '  });','}',
                           f'extern "C" int {func}_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const {resp}* response) {{',
                           '  if(!connection || !request || !response) return EINVAL;', '  if(request->value->replied()) return EALREADY;', '  return CBoundary([&]() -> int {',
                           f'    int error={ns}Server::Reply{mn}(*connection->value,*request->value,FromC(response));',
                           '    return error;', '  });','}']
                else:
                    h += [f'int {func}(struct fidl_bsd_connection *, const struct {req} *);']
                    cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {req}* request) {{',
                           '  if(!connection || !request) return EINVAL;', f'  return CBoundary([&]() -> int {{ {ns}Client client(*connection->value); return client.{mn}(FromC(request)); }});','}']
            else:
                resp=cname(m['maybe_response_payload']['identifier'])
                h += [f'int {func}(struct fidl_bsd_connection *, const struct {resp} *);']
                cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {resp}* event) {{',
                       '  if(!connection || !event) return EINVAL;',f'  return CBoundary([&]() -> int {{ return {ns}Server::{mn}(*connection->value,FromC(event)); }});','}']
        events=[m for m in p['methods'] if not m['has_request']]
        if events or p['openness'] != 'closed':
            h += [f'struct {pc}_events {{']
            for m in events:
                resp=cname(m['maybe_response_payload']['identifier'])
                h += [f'    void (*{m["name"]})(void *, struct {resp} *);']
            if p['openness'] != 'closed': h += ['    void (*unknown_interaction)(void *, uint64_t);']
            h+=['};',f'int {pc}_bind_events(struct fidl_bsd_connection *, const struct {pc}_events *, void *);']
            cc += [f'namespace {{ struct Events_{pc} : {ns}Events {{',f'  {pc}_events handlers; void* context;',
                   f'  Events_{pc}(const {pc}_events& h,void* c):handlers(h),context(c){{}}']
            for m in events:
                respid=m['maybe_response_payload']['identifier']; resp=cname(respid); mn=m['name']
                cc += [f'  void {mn}({cpp(respid)} value,const fidl::bsd::Incoming&) override {{',f'    View_{resp} view(value); if(handlers.{mn}) handlers.{mn}(context,&view.data);','  }']
            if p['openness'] != 'closed': cc += ['  void OnUnknownEvent(uint64_t ordinal) override { if (handlers.unknown_interaction) handlers.unknown_interaction(context,ordinal); }']
            cc += ['}; }',f'extern "C" int {pc}_bind_events(fidl_bsd_connection* connection,const {pc}_events* handlers,void* context) {{',
                   '  if(!connection || !handlers) return EINVAL;', '  return CBoundary([&]() -> int {', f'    auto bridge=std::make_shared<Events_{pc}>(*handlers,context);',
                   '    connection->value->SetEventHandler([bridge,connection](auto message){bridge->Dispatch(*connection->value,std::move(message));}); return 0;', '  });','}']
    h+=['#ifdef __cplusplus','}','#endif']
    base=root/'fidl'/library/'c'; base.mkdir(parents=True,exist_ok=True)
    (base/'bsd.h').write_text('\n'.join(h)+'\n')
    (base/'bsd.cc').write_text('\n'.join(cc)+'\n')
    (base/'bridge.h').write_text('\n'.join(bridge)+'\n')
