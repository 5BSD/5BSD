#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Generate BSD adapters around upstream FIDL natural types and codecs.

The upstream compiler IR is unchanged.  fidlgen_natural.py emits the native
natural types by running upstream's fidlgen_cpp templates; this adapter adds
client/server and optional C APIs.  Fuchsia messaging outputs are not part
of this backend.  Unsupported transport features fail at generation time.
"""
import argparse
import sys
sys.dont_write_bytecode = True
import json
import re
import tempfile
from pathlib import Path

EMPTY = 'fidl.bsd/Empty'

def walk(value):
    if isinstance(value, dict):
        yield value
        for v in value.values(): yield from walk(v)
    elif isinstance(value, list):
        for v in value: yield from walk(v)

def dependency_order(main, dependencies):
    """Validate a complete IR set and return dependency-first paths."""
    inputs = {}
    for path in [main, *dependencies]:
        ir = json.loads(path.read_text())
        name = ir['name']
        if name in inputs:
            raise ValueError('duplicate library IR: ' + name)
        if not re.fullmatch(r'[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*', name):
            raise ValueError('unsupported library name: ' + name)
        inputs[name] = (path, ir)
    declarations = {}
    for _, ir in inputs.values():
        for key, values in ir.items():
            if key.endswith('_declarations') and key != 'external_struct_declarations':
                for declaration in values:
                    declarations[declaration['name']] = declaration
    def semantic(value):
        if isinstance(value, list): return [semantic(v) for v in value]
        if isinstance(value, dict):
            return {k:semantic(v) for k,v in value.items()
                    if k not in ('location', 'maybe_attributes', 'deprecated')}
        return value
    for _, ir in inputs.values():
        for dependency in ir['library_dependencies']:
            name = dependency['name']
            # zx.Handle is mapped to native descriptors; it has no generated
            # Zircon runtime dependency. Other schema libraries need their IR.
            if name == 'zx' and name not in inputs: continue
            if name not in inputs:
                raise ValueError('missing dependency IR: ' + name + ' (use --dependency-json)')
            supplied = inputs[name][1]['declarations']
            for ident, info in dependency['declarations'].items():
                if supplied.get(ident) != info['kind'] or ident not in declarations:
                    raise ValueError('incompatible dependency declaration: ' + ident)
                declaration = declarations[ident]
                if info['kind'] in ('enum', 'bits'):
                    primitive = declaration['type']
                    if isinstance(primitive, dict): primitive = primitive['subtype']
                    width = int(primitive.lstrip('uint')) // 8
                    declaration = dict(declaration, type_shape_v2={
                        'inline_size':width, 'alignment':width, 'depth':0,
                        'max_handles':0, 'max_out_of_line':0,
                        'has_padding':False, 'has_flexible_envelope':False})
                for key in ('resource', 'type_shape_v2'):
                    if key in info and info[key] != declaration.get(key):
                        raise ValueError('incompatible dependency layout: ' + ident)
        for declaration in ir.get('external_struct_declarations', []):
            ident = declaration['name']
            if ident not in declarations or semantic(declaration) != semantic(declarations[ident]):
                raise ValueError('incompatible imported struct: ' + ident)
    ordered = []; visiting = set(); done = set()
    def visit(name):
        if name in done: return
        if name in visiting: raise ValueError('cyclic dependency IR: ' + name)
        visiting.add(name)
        for dependency in inputs[name][1]['library_dependencies']:
            if dependency['name'] in inputs: visit(dependency['name'])
        visiting.remove(name); done.add(name); ordered.append(inputs[name][0])
    for name in sorted(inputs): visit(name)
    return ordered

def generate(ir_path, root, templates, dependencies=()):
    import fidlgen_natural
    ir = json.loads(ir_path.read_text())
    natural_ir = json.loads(ir_path.read_text())
    name = ir['name']
    if not re.fullmatch(r'[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*', name):
        raise ValueError('unsupported library name: ' + name)
    for t in walk(ir):
        if t.get('kind_v2') == 'endpoint' and t.get('protocol_transport','Channel') != 'Channel':
            raise ValueError('only native channel protocol endpoints are supported')
        if t.get('kind_v2') == 'handle':
            if t.get('resource_identifier') != 'zx/Handle' or t.get('subtype') not in ('handle','channel','socket'):
                raise ValueError('unsupported native handle type: ' + str(t))
            rights=t.get('rights', 0x80000000)
            if rights != 0x80000000 and rights & ~12:
                raise ValueError('only READ, WRITE, or SAME_RIGHTS have native mappings')
            if t.get('subtype') == 'channel' and rights != 0x80000000:
                raise ValueError('channel descriptors require SAME_RIGHTS; use native attenuation')
    definitions = {d['name']:d for d in ir['struct_declarations'] + ir['table_declarations'] + ir['union_declarations']}
    available = set(definitions)
    for dependency in dependencies:
        available.update(dependency['declarations'])
    for proto in ir['protocol_declarations']:
        if proto['openness'] not in ('closed', 'ajar', 'open'): raise ValueError('unsupported protocol openness')
        for m in proto['methods']:
            if not m['strict'] and (proto['openness'] == 'closed' or
                (proto['openness'] == 'ajar' and m['has_request'] and m['has_response'])):
                raise ValueError('flexible method is incompatible with protocol openness')
            for direction in ('request','response'):
                if m.get('has_'+direction):
                    payload=m.get('maybe_'+direction+'_payload')
                    if payload and payload.get('identifier') not in available:
                        raise ValueError('payload declaration is unavailable')
                    if not payload:
                        m['maybe_'+direction+'_payload']={'identifier':EMPTY}
    root.mkdir(parents=True,exist_ok=True)
    # The five natural-type files come from upstream's fidlgen_cpp templates
    # (markers.h, common_types.{h,cc}, natural_types.{h,cc}).
    try:
        natural, names = fidlgen_natural.generate(natural_ir, templates)
    except fidlgen_natural.GeneratorError as error:
        raise ValueError(str(error)) from error
    base=root/'fidl'/name/'cpp'
    base.mkdir(parents=True,exist_ok=True)
    for path, text in natural.items():
        (root/path).write_text(text)
    def cpp(identifier):
        return '::fidl::bsd::Empty' if identifier == EMPTY else names['types'][identifier]
    for declaration in definitions.values():
        for member in declaration.get('members',[]):
            member['_cpp_name']=names['members'][declaration['name']+'/'+member['name']]
    for proto in ir['protocol_declarations']:
        proto['_cpp_name']=cpp(proto['name']).split('::')[-1]
        for method in proto['methods']:
            method['name']=names['members'][proto['name']+'/'+method['name']]
    out=['// Generated BSD adapters; do not edit.','#pragma once','#include <fidl/bsd/runtime.h>',
         '#include <fidl/'+name+'/cpp/natural_types.h>', 'namespace '+name.replace('.','_')+'::bsd {']
    for proto in ir['protocol_declarations']:
        pname=proto['_cpp_name']
        openness = '::fidl::bsd::Openness::' + proto['openness'].title()
        discard = 'fidl_bsd_discard_events_' + pname
        out += [f'inline void {discard}(::fidl::bsd::Connection&, std::unique_ptr<::fidl::bsd::Incoming>);',
                f'class {pname}Client {{', ' public:',
                f'  explicit {pname}Client(::fidl::bsd::Connection& connection) : connection_(connection) {{ connection.EnsureEventHandler([&connection](auto message){{ {discard}(connection,std::move(message)); }}); }}']
        for m in proto['methods']:
            if not m['has_request']: continue
            req=cpp(m['maybe_request_payload']['identifier']); ordinal=m['ordinal']; method=m['name']; flexible=str(not m['strict']).lower()
            if m['has_response']:
                resp=cpp(m['maybe_response_payload']['identifier'])
                out += [f'  ::fidl::bsd::Result<uint32_t> {method}({req} request, std::function<void(::fidl::bsd::Result<{resp}>)> callback) {{',
                        '    if (!callback) return fit::error(EINVAL);']
                if not m['strict']:
                    out += ['    auto completion = [callback=std::move(callback)](auto result) mutable {',
                            '      if (result.is_ok() && result->framework_err()) { callback(fit::error(EOPNOTSUPP)); return; }',
                            '      callback(std::move(result));', '    };']
                else: out += ['    auto completion = std::move(callback);']
                out += [f'    return connection_.Call<{req}, {resp}>({ordinal}ULL, std::move(request), std::move(completion), {flexible});', '  }']
            else:
                out += [f'  int {method}({req} request) {{ return connection_.Send({ordinal}ULL, std::move(request), {flexible}); }}']
        out += [' private:', '  ::fidl::bsd::Connection& connection_;','};',f'class {pname}Server {{',' public:',f'  virtual ~{pname}Server() = default;']
        for m in proto['methods']:
            method=m['name']; ordinal=m['ordinal']; flexible=str(not m['strict']).lower()
            if m['has_request']:
                req=cpp(m['maybe_request_payload']['identifier'])
                out += [f'  virtual void {method}({req} request, std::unique_ptr<::fidl::bsd::Incoming> context) = 0;']
                if m['has_response']:
                    resp=cpp(m['maybe_response_payload']['identifier'])
                    out += [f'  static int Reply{method}(::fidl::bsd::Connection& connection, ::fidl::bsd::Incoming& context, {resp} response) {{',
                            f'    if (context.Validate({ordinal}ULL, context.header().txid)) return EPROTO;',
                            f'    return connection.Reply(context, std::move(response), {flexible});','  }']
            else:
                resp=cpp(m['maybe_response_payload']['identifier'])
                out += [f'  static int {method}(::fidl::bsd::Connection& connection, {resp} event) {{ return connection.Send({ordinal}ULL, std::move(event), {flexible}); }}']
        out += ['  virtual void OnUnknownMethod(uint64_t, bool) {}', '  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {','    switch (message->header().ordinal) {']
        for m in proto['methods']:
            if not m['has_request']: continue
            req=cpp(m['maybe_request_payload']['identifier']); method=m['name']; ordinal=m['ordinal']
            txcheck='message->header().txid != 0' if m['has_response'] else 'message->header().txid == 0'
            out += [f'    case {ordinal}ULL: {{', f'      if (!({txcheck}) || message->Validate({ordinal}ULL, message->header().txid)) {{ connection.Close(EPROTO); return; }}',
                    f'      auto decoded = message->Decode<{req}>();', '      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }',
                    f'      {method}(std::move(decoded.value()), std::move(message)); return;', '    }']
        out += ['    default: {', f'      int error = connection.HandleUnknown(*message, {openness});',
                '      if (error) { connection.Close(error); return; }',
                '      OnUnknownMethod(message->header().ordinal, message->header().txid != 0); return;', '    }', '    }','  }','};']
        # Events are dispatched through the same checked typed codec path.
        out += [f'class {pname}Events {{',' public:', f'  virtual ~{pname}Events() = default;']
        for m in proto['methods']:
            if not m['has_request']:
                resp=cpp(m['maybe_response_payload']['identifier'])
                out += [f'  virtual void {m["name"]}({resp} value, const ::fidl::bsd::Incoming& context) {{}};']
        out += ['  virtual void OnUnknownEvent(uint64_t) {}', '  void Dispatch(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {','    switch (message->header().ordinal) {']
        for m in proto['methods']:
            if m['has_request']: continue
            resp=cpp(m['maybe_response_payload']['identifier']); ordinal=m['ordinal']
            out += [f'    case {ordinal}ULL: {{',f'      if (message->Validate({ordinal}ULL, 0)) {{ connection.Close(EPROTO); return; }}',
                    f'      auto decoded = message->Decode<{resp}>();', '      if (decoded.is_error()) { connection.Close(decoded.error_value()); return; }',
                    f'      {m["name"]}(std::move(decoded.value()), *message); return;', '    }']
        out += ['    default: {', f'      int error = connection.HandleUnknown(*message, {openness});',
                '      if (error) { connection.Close(error); return; }',
                '      OnUnknownEvent(message->header().ordinal); return;', '    }', '    }','  }','};',
                f'inline void {discard}(::fidl::bsd::Connection& connection, std::unique_ptr<::fidl::bsd::Incoming> message) {{ {pname}Events events; events.Dispatch(connection,std::move(message)); }}']
    out += ['}']
    (base/'bsd.h').write_text('\n'.join(out)+'\n')
    return ir, cpp

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--json',required=True,type=Path)
    p.add_argument('--root',required=True,type=Path)
    p.add_argument('--dependency-json',action='append',type=Path,default=[],
                   help='dependency-library compiler IR; repeat for transitive dependencies')
    p.add_argument('--c',action='store_true',help='also generate the native C application API')
    # The installed backend is private to the SDK and carries its templates.
    here=Path(__file__).resolve().parent
    if Path(__file__).name == 'fidlgen-bsd':
        installed=here.parent/'libexec/fidl'
        sys.path.insert(0,str(installed))
        default_templates=installed/'templates'
    else:
        sys.path.insert(0,str(here))
        default_templates=here.parents[2]/'contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen'
    p.add_argument('--templates',type=Path,default=default_templates,
                   help='fidlgen_cpp template directory')
    a=p.parse_args()
    try:
        a.root.parent.mkdir(parents=True, exist_ok=True)
        # Schema rejection leaves the caller's previous output intact.
        with tempfile.TemporaryDirectory(prefix='fidl-bsd-publish-', dir=a.root.parent) as temporary:
            stage=Path(temporary)
            generated = []
            for ir_path in dependency_order(a.json, a.dependency_json):
                ir, cpp = generate(ir_path,stage,a.templates,generated)
                if a.c:
                    from generate_bsd_c import generate_c
                    generate_c(ir,stage,cpp,generated)
                generated.append(ir)
            for source in sorted(stage.rglob('*')):
                if source.is_file():
                    destination=a.root/source.relative_to(stage)
                    destination.parent.mkdir(parents=True,exist_ok=True)
                    source.replace(destination)
    except (ValueError, OSError) as error: p.error(str(error))
