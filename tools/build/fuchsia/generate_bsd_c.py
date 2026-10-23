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
       '/* Outgoing buffers and descriptors are borrowed; descriptors are duplicated',
       ' * unless marked with fidl_bsd_fd_owned(), which the call takes and closes in',
       ' * every outcome. Callback buffers last until return. Take a callback',
       ' * descriptor with fidl_bsd_take_fd() to retain it. Retain request contexts',
       ' * for deferred replies. */']
    cc=['// Generated C bridge; compile as C++20.','#include <fidl/bsd/c_bridge.h>','#include <fidl/bsd/c_wire.h>',
        '#include <fidl/'+library+'/cpp/bsd.h>','#include <fidl/'+library+'/c/bridge.h>', 'using fidl::bsd::CBoundary;', 'using namespace fidl::bsd::generated;']
    h += types.header()
    bridge = ['// Generated private C++ conversions for the C ABI; do not edit.',
              '#pragma once', '#include <fidl/bsd/c_bridge.h>',
              '#include <fidl/'+library+'/cpp/natural_types.h>',
              '#include <fidl/'+library+'/c/bsd.h>']
    bridge += ['#include <fidl/'+d['name']+'/c/bridge.h>'
               for d in ir['library_dependencies'] if d['name'] != 'zx' or any(x['name'] == 'zx' for x in dependencies)]
    from generate_bsd_c_wire import Wire
    wire = Wire(types)
    aggregates = [i for i in sorted(types.owned) if types.decls[i][0] in ('struct', 'table', 'union')]
    bridge.insert(2, '#include <fidl/bsd/c_wire.h>')
    bridge += ['namespace fidl::bsd::generated {', *types.bridge(), *wire.functions(aggregates), '}']
    def payload(ident):
        # (C type, wire inline size); the empty payload has no body.
        if ident == 'fidl.bsd/Empty':
            return 'fidl_bsd_empty', 0
        return cname(ident), types.decls[ident][1]['type_shape_v2']['inline_size']
    def has_handles(ident):
        return ident != 'fidl.bsd/Empty' and wire.aggregate_has_handles(ident)
    def encode_body(ident, value):
        # A payload with descriptors releases the owned ones a failed encode
        # did not attach (the packet closes those it did), so the caller's
        # fidl_bsd_fd_owned() descriptors are consumed in every outcome.
        ctype, size = payload(ident)
        if not size:
            return '[](fidl::bsd::Outgoing&) -> int { return 0; }'
        if not has_handles(ident):
            return (f'[&](fidl::bsd::Outgoing& out) -> int {{ fidl::bsd::cwire::Encoder e(out); '
                    f'size_t at = e.Alloc({size}); CWEnc_{ctype}(e, {value}, at, 0); return e.error(); }}')
        return (f'[&](fidl::bsd::Outgoing& out) -> int {{ fidl::bsd::cwire::Encoder e(out); '
                f'try {{ size_t at = e.Alloc({size}); CWEnc_{ctype}(e, {value}, at, 0); }} '
                f'catch (const std::bad_alloc&) {{ e.Fail(ENOMEM); }} '
                f'if (e.error()) CWRelease_{ctype}(fidl::bsd::cwire::OwnedRelease(e), {value}); return e.error(); }}')
    def argument_check(ident, value, condition):
        # Rejected arguments still consume the owned descriptors of a
        # non-null payload.
        ctype, _ = payload(ident)
        if not has_handles(ident):
            return f'  if({condition}) return EINVAL;'
        return (f'  if(!{value}) return EINVAL;\n'
                f'  if({condition}) {{ CWRelease_{ctype}(fidl::bsd::cwire::OwnedRelease(), {value}); return EINVAL; }}')
    def decode_body(ident, decoder, incoming, out):
        # C++ statement yielding int error (0, EPROTO).
        ctype, size = payload(ident)
        if not size:
            return (f'(channel_message_length(({incoming}).native()) == sizeof(fidl_message_header_t) && '
                    f'channel_message_fd_count(({incoming}).native()) == 0) ? 0 : EPROTO')
        return (f'[&]() -> int {{ int error = {decoder}.Begin({incoming}); if (error) return error; '
                f'size_t at; if (!{decoder}.Claim({size}, &at) || !CWDec_{ctype}({decoder}, at, {out}, 0) || '
                f'!{decoder}.Finish()) return EPROTO; return 0; }}()')
    for p in protocols:
        pn=p['_cpp_name']; pc=prefix+'_'+pn
        openness = 'fidl::bsd::Openness::' + p['openness'].title()
        events=[m for m in p['methods'] if not m['has_request']]
        h += [f'struct {pc}_server {{']
        for m in p['methods']:
            if m['has_request']:
                req=cname(m['maybe_request_payload']['identifier'])
                h += [f'    void (*{m["name"]})(void *, struct fidl_bsd_connection *, struct fidl_bsd_request *, struct {req} *);']
        if not any(m['has_request'] for m in p['methods']): h+=['    unsigned char unused;']
        if p['openness'] != 'closed': h += ['    void (*unknown_interaction)(void *, uint64_t, bool);']
        h+=['};',f'int {pc}_bind(struct fidl_bsd_connection *, const struct {pc}_server *, void *);']
        # Incoming messages decode straight into C views (generated wire
        # decoders, per-message arena); handler descriptors not taken are
        # closed when the decoder goes out of scope.
        cc += ['namespace {',
               f'struct CServer_{pc} {{ fidl_bsd_connection* connection; {pc}_server handlers; void* context; }};',
               f'void CServerDispatch_{pc}(CServer_{pc}& s, std::unique_ptr<fidl::bsd::Incoming> message) {{',
               '  auto& c = *s.connection->value;',
               '  const auto header = message->header();',
               '  switch (header.ordinal) {']
        for m in p['methods']:
            if not m['has_request']: continue
            mn=m['name']; ordinal=m['ordinal']; ident=m['maybe_request_payload']['identifier']; req=cname(ident)
            txcheck='header.txid != 0' if m['has_response'] else 'header.txid == 0'
            cc += [f'  case {ordinal}ULL: {{',
                   f'    if (!({txcheck}) || message->Validate({ordinal}ULL, header.txid)) {{ c.Close(EPROTO); return; }}',
                   '    fidl::bsd::cwire::Arena arena;', f'    {req} data{{}};', '    fidl::bsd::cwire::Decoder decoder(arena);',
                   f'    if (int error = {decode_body(ident, "decoder", "*message", "&data")}) {{ c.Close(error); return; }}',
                   f'    if (!s.handlers.{mn}) {{ c.Close(ENOSYS); return; }}',
                   '    fidl::bsd::CRequest request = fidl::bsd::NewCRequest(s.connection, std::move(message));',
                   f'    s.handlers.{mn}(s.context, s.connection, request.get(), &data);', '    return;', '  }']
        cc += ['  default: {',
               f'    int error = c.HandleUnknown(*message, {openness});',
               '    if (error) { c.Close(error); return; }']
        if p['openness'] != 'closed':
            cc += ['    if (s.handlers.unknown_interaction) s.handlers.unknown_interaction(s.context, header.ordinal, header.txid != 0);']
        cc += ['    return;', '  }', '  }', '}']
        # Events reach a client; with no handlers bound they are validated
        # and dropped (as the C++ client's default event handler does).
        cc += [f'void CEventsDispatch_{pc}(fidl::bsd::Connection& c, const {pc}_events* handlers, void* context, std::unique_ptr<fidl::bsd::Incoming> message) {{'
               if events or p['openness'] != 'closed' else
               f'void CEventsDispatch_{pc}(fidl::bsd::Connection& c, const void* handlers, void* context, std::unique_ptr<fidl::bsd::Incoming> message) {{',
               '  const auto header = message->header();',
               '  switch (header.ordinal) {']
        for m in events:
            mn=m['name']; ordinal=m['ordinal']; ident=m['maybe_response_payload']['identifier']; resp=cname(ident)
            cc += [f'  case {ordinal}ULL: {{',
                   f'    if (message->Validate({ordinal}ULL, 0)) {{ c.Close(EPROTO); return; }}',
                   '    fidl::bsd::cwire::Arena arena;', f'    {resp} data{{}};', '    fidl::bsd::cwire::Decoder decoder(arena);',
                   f'    if (int error = {decode_body(ident, "decoder", "*message", "&data")}) {{ c.Close(error); return; }}',
                   f'    if (handlers && handlers->{mn}) handlers->{mn}(context, &data);', '    return;', '  }']
        cc += ['  default: {',
               f'    int error = c.HandleUnknown(*message, {openness});',
               '    if (error) { c.Close(error); return; }']
        if p['openness'] != 'closed':
            cc += ['    if (handlers && handlers->unknown_interaction) handlers->unknown_interaction(context, header.ordinal);']
        cc += ['    (void)handlers; (void)context;', '    return;', '  }', '  }', '}',
               f'void EnsureEvents_{pc}(fidl_bsd_connection* connection) {{',
               '  if (!connection->value->HasEventHandler())',
               f'    connection->value->EnsureEventHandler([connection](std::unique_ptr<fidl::bsd::Incoming> m) {{ CEventsDispatch_{pc}(*connection->value, nullptr, nullptr, std::move(m)); }});',
               '}', '}']
        cc += [f'extern "C" int {pc}_bind(fidl_bsd_connection* connection,const {pc}_server* handlers,void* context) {{',
               '  if(!connection || !handlers) return EINVAL;', '  return CBoundary([&]() -> int {',
               f'    auto server=std::make_shared<CServer_{pc}>(CServer_{pc}{{connection,*handlers,context}});',
               f'    auto dispatch=[server](std::unique_ptr<fidl::bsd::Incoming> message){{ CServerDispatch_{pc}(*server,std::move(message)); }};',
               '    connection->value->SetRequestHandler(dispatch); connection->value->SetEventHandler(dispatch); return 0;', '  });','}']
        for m in p['methods']:
            mn=m['name']; func=pc+'_'+mn; ordinal=m['ordinal']; flexible=str(not m['strict']).lower()
            if m['has_request']:
                reqid=m['maybe_request_payload']['identifier']; req=cname(reqid)
                if m['has_response']:
                    respid=m['maybe_response_payload']['identifier']; resp=cname(respid)
                    h += [f'typedef void (*{func}_callback)(void *, int, struct {resp} *);',
                          f'int {func}(struct fidl_bsd_connection *, const struct {req} *, {func}_callback, void *, uint32_t *);',
                          f'int {func}_reply(struct fidl_bsd_connection *, struct fidl_bsd_request *, const struct {resp} *);']
                    # A flexible method's framework error reaches C as EOPNOTSUPP.
                    framework = ('      if (data.tag == 3ULL) { callback(context, EOPNOTSUPP, nullptr); return; }'
                                 if not m['strict'] else None)
                    cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {req}* request,{func}_callback callback,void* context,uint32_t* txid) {{',
                           '  if(txid) *txid=0;',
                           argument_check(reqid, 'request', '!connection || !request || !callback || !txid'),
                           '  return CBoundary([&]() -> int {',
                           f'    EnsureEvents_{pc}(connection);',
                           '    fidl::bsd::Connection* c = connection->value.get();',
                           f'    auto result = c->CallRaw({ordinal}ULL, {flexible}, {encode_body(reqid, "request")},',
                           '      [c, callback, context](int error, fidl::bsd::Incoming* incoming) {',
                           '      if (error) { callback(context, error, nullptr); return; }',
                           f'      fidl::bsd::cwire::Arena arena; {resp} data{{}}; fidl::bsd::cwire::Decoder decoder(arena);',
                           '      try {',
                           f'        error = {decode_body(respid, "decoder", "*incoming", "&data")};',
                           '      } catch (const std::bad_alloc&) { error = ENOMEM; }',
                           '      if (error) { c->Close(error); callback(context, error, nullptr); return; }',
                           *([framework] if framework else []),
                           '      callback(context, 0, &data);', '    });',
                           '    if(result.is_error()) return result.error_value(); *txid=result.value(); return 0;', '  });','}',
                           f'extern "C" int {func}_reply(fidl_bsd_connection* connection,fidl_bsd_request* request,const {resp}* response) {{',
                           argument_check(respid, 'response', '!connection || !request || !response'),
                           '  return CBoundary([&]() -> int {',
                           f'    return connection->value->ReplyRaw(*request->value, {flexible}, {encode_body(respid, "response")}, {ordinal}ULL);',
                           '  });','}']
                else:
                    h += [f'int {func}(struct fidl_bsd_connection *, const struct {req} *);']
                    cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {req}* request) {{',
                           argument_check(reqid, 'request', '!connection || !request'),
                           '  return CBoundary([&]() -> int {',
                           f'    EnsureEvents_{pc}(connection);',
                           f'    return connection->value->SendRaw({ordinal}ULL, {flexible}, {encode_body(reqid, "request")});',
                           '  });','}']
            else:
                respid=m['maybe_response_payload']['identifier']; resp=cname(respid)
                h += [f'int {func}(struct fidl_bsd_connection *, const struct {resp} *);']
                cc += [f'extern "C" int {func}(fidl_bsd_connection* connection,const {resp}* event) {{',
                       argument_check(respid, 'event', '!connection || !event'),
                       f'  return CBoundary([&]() -> int {{ return connection->value->SendRaw({ordinal}ULL, {flexible}, {encode_body(respid, "event")}); }});','}']
        if events or p['openness'] != 'closed':
            h += [f'struct {pc}_events {{']
            for m in events:
                resp=cname(m['maybe_response_payload']['identifier'])
                h += [f'    void (*{m["name"]})(void *, struct {resp} *);']
            if p['openness'] != 'closed': h += ['    void (*unknown_interaction)(void *, uint64_t);']
            h+=['};',f'int {pc}_bind_events(struct fidl_bsd_connection *, const struct {pc}_events *, void *);']
            cc += [f'extern "C" int {pc}_bind_events(fidl_bsd_connection* connection,const {pc}_events* handlers,void* context) {{',
                   '  if(!connection || !handlers) return EINVAL;', '  return CBoundary([&]() -> int {',
                   f'    auto bound=std::make_shared<std::pair<{pc}_events, void*>>(*handlers,context);',
                   f'    connection->value->SetEventHandler([bound,connection](std::unique_ptr<fidl::bsd::Incoming> m){{ CEventsDispatch_{pc}(*connection->value,&bound->first,bound->second,std::move(m)); }}); return 0;',
                   '  });','}']
    h+=['#ifdef __cplusplus','}','#endif']
    base=root/'fidl'/library/'c'; base.mkdir(parents=True,exist_ok=True)
    (base/'bsd.h').write_text('\n'.join(h)+'\n')
    (base/'bsd.cc').write_text('\n'.join(cc)+'\n')
    (base/'bridge.h').write_text('\n'.join(bridge)+'\n')
