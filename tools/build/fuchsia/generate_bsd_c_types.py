# SPDX-License-Identifier: BSD-2-Clause
"""C layouts and checked conversions for reachable FIDL natural types."""
import hashlib

PRIMITIVES = dict(zip(
    'bool int8 uint8 int16 uint16 int32 uint32 int64 uint64 float32 float64'.split(),
    'bool int8_t uint8_t int16_t uint16_t int32_t uint32_t int64_t uint64_t float double'.split()))
KEYWORDS = set(('alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept '
    'auto bitand bitor bool break case catch char char8_t char16_t char32_t class '
    'compl concept const consteval constexpr constinit const_cast continue co_await '
    'co_return co_yield decltype default delete do double dynamic_cast else enum '
    'explicit export extern false float for friend goto if inline int long mutable '
    'namespace new noexcept not not_eq nullptr operator or or_eq private protected '
    'public register reinterpret_cast requires restrict return short signed sizeof '
    'static static_assert static_cast struct switch synchronized template this '
    'thread_local throw true try typedef typeid typename union unsigned using '
    'virtual void volatile wchar_t while xor xor_eq').split())

def cname(ident):
    return 'fidl_bsd_empty' if ident == 'fidl.bsd/Empty' else ident.replace('.', '_').replace('/', '_')

class CTypes:
    def __init__(self, ir, cpp, roots, dependencies=()):
        self.cpp = cpp
        self.prefix = ir['name'].replace('.', '_')
        self.decls = {}; self.owned = set()
        self.imports = [d['name'] for d in ir['library_dependencies'] if d['name'] != 'zx' or any(x['name'] == 'zx' for x in dependencies)]
        for library in [*dependencies, ir]:
            for kind in ('struct', 'table', 'union', 'enum', 'bits'):
                for d in library[kind + '_declarations']:
                    self.decls[d['name']] = (kind, d)
                    if library is ir: self.owned.add(d['name'])
        roots = set(roots) | self.owned
        self.decls['fidl.bsd/Empty'] = ('struct', {'name':'fidl.bsd/Empty', 'members':[]})
        self.used = set()
        self.helpers = {}
        self.serial = 0
        for ident in sorted(roots): self.visit_ident(ident)
        for ident in sorted(self.owned): self.member_names(ident)

    def fresh(self):
        self.serial += 1
        return 'item_' + str(self.serial)

    def helper(self, t):
        # Container element wrappers have readable, layout-derived C names.
        # Bounds validate values but do not change a string/vector C layout.
        def shape(value):
            kind = value['kind_v2']
            if kind == 'primitive': result = value['subtype']
            elif kind == 'identifier': result = cname(value['identifier'])
            elif kind in ('handle', 'endpoint'): result = 'descriptor'
            elif kind == 'array': result = 'array_' + str(value['element_count']) + '_' + shape(value['element_type'])
            elif kind == 'vector': result = 'vector_' + shape(value['element_type'])
            else: result = kind
            return result + ('_optional' if value.get('nullable') else '')
        suffix = shape(t)
        if len(suffix) > 96:
            suffix = suffix[:64] + '_' + hashlib.sha256(suffix.encode()).hexdigest()[:16]
        name = self.prefix + '_fidl_' + suffix
        if any(cname(ident) == name for ident in self.used):
            raise ValueError('C container helper collides with declaration: ' + name)
        self.helpers[name] = t
        return name

    def visit_ident(self, ident):
        if ident in self.used: return
        if ident not in self.decls: raise ValueError('C declaration is unavailable: ' + ident)
        self.used.add(ident)
        kind, d = self.decls[ident]
        if ident not in self.owned or kind in ('enum', 'bits'): return
        for m in d['members']:
            if not m.get('reserved'): self.visit(m['type'])

    def visit(self, t):
        kind = t['kind_v2']
        if kind == 'identifier': self.visit_ident(t['identifier'])
        elif kind in ('array', 'vector'):
            self.visit(t['element_type'])
            self.ctype(t['element_type'])
        elif kind == 'internal' and t.get('subtype') == 'framework_error': pass
        elif kind not in ('primitive', 'string', 'handle', 'endpoint'):
            raise ValueError('unsupported C field type: ' + kind)

    def members(self, ident):
        return [m for m in self.decls[ident][1]['members'] if not m.get('reserved')]

    def member_names(self, ident):
        kind, _ = self.decls[ident]
        if kind in ('enum', 'bits'): return
        original = {m['name'] for m in self.members(ident)}
        occupied = set()
        for m in sorted(self.members(ident), key=lambda m:m['name']):
            name = source = m['name']
            while True:
                fields = [name]
                if m['type']['kind_v2'] in ('string', 'vector'): fields += [name+'_size']
                if m['type']['kind_v2'] in ('string', 'vector') and m['type'].get('nullable'): fields += [name+'_present']
                if kind == 'table': fields += ['has_'+name]
                if name not in KEYWORDS and not any(f in occupied or (f in original and f != source) for f in fields): break
                name += '_fidl'
            occupied.update(fields)
            m['_c_name'] = name

    def complex(self, t):
        return t['kind_v2'] in ('array', 'vector', 'string')

    def ctype(self, t):
        k = t['kind_v2']
        if k == 'primitive': return PRIMITIVES[t['subtype']]
        if k == 'internal' and t.get('subtype') == 'framework_error': return 'int32_t'
        if k in ('handle', 'endpoint'): return 'int'
        if k == 'identifier':
            kind, _ = self.decls[t['identifier']]
            base = ('' if kind in ('enum', 'bits') else 'struct ') + cname(t['identifier'])
            return base + (' *' if t.get('nullable') else '')
        return 'struct ' + self.helper(t)

    def fields(self, t, name):
        k = t['kind_v2']
        if k == 'string': out = ['const char *'+name+';', 'size_t '+name+'_size;']
        elif k == 'vector': out = [self.ctype(t['element_type'])+' *'+name+';', 'size_t '+name+'_size;']
        elif k == 'array': out = [self.ctype(t['element_type'])+' '+name+'['+str(t['element_count'])+'];']
        else: out = [self.ctype(t)+' '+name+';']
        if k in ('string', 'vector') and t.get('nullable'): out += ['bool '+name+'_present;']
        return out

    def elem(self, t, expression):
        return expression + ('.data' if self.complex(t) else '')

    def header(self):
        # Build all helper declarations before emitting forward declarations.
        for ident in sorted(self.owned):
            kind, _ = self.decls[ident]
            if kind in ('enum', 'bits'): continue
            for m in self.members(ident):
                if kind == 'union': self.ctype(m['type'])
                else: self.fields(m['type'], m['_c_name'])
        previous = -1
        while previous != len(self.helpers):
            previous = len(self.helpers)
            for t in list(self.helpers.values()): self.fields(t, 'data')
        h = ['#include <fidl/'+name+'/c/bsd.h>' for name in self.imports]
        for ident in sorted(self.owned):
            kind, d = self.decls[ident]; cn = cname(ident)
            if kind not in ('enum', 'bits'):
                if ident != 'fidl.bsd/Empty': h += ['struct '+cn+';']
                continue
            subtype = d['type'] if isinstance(d['type'], str) else d['type']['subtype']
            h += [f'typedef {PRIMITIVES[subtype]} {cn};']
            for m in d['members']:
                value = int(m['value']['value'])
                literal = str(value)+'ULL' if value >= 0 else ('(-9223372036854775807LL - 1)' if value == -(1<<63) else str(value)+'LL')
                h += [f'#define {cn}_{m["name"]} (({cn}){literal})']
        h += ['struct '+name+';' for name in sorted(self.helpers)]
        done = set(); active = set()
        def deps(t):
            k = t['kind_v2']
            if k == 'identifier' and not t.get('nullable'):
                ident = t['identifier']
                if self.decls[ident][0] not in ('enum', 'bits'): emit(ident)
            elif k == 'array':
                e = t['element_type']
                if self.complex(e): emit(self.helper(e))
                else: deps(e)
        def emit(key):
            if key in done or (key not in self.owned and key not in self.helpers): return
            if key in active: raise ValueError('recursive inline C layout: '+key)
            active.add(key)
            if key in self.helpers:
                t = self.helpers[key]; deps(t)
                lines = self.fields(t, 'data'); cn = key
            else:
                kind, _ = self.decls[key]; cn = cname(key)
                if kind in ('enum', 'bits'): return
                lines = []
                for m in self.members(key):
                    t = m['type']; name = m['_c_name']
                    if kind == 'union' and self.complex(t): emit(self.helper(t))
                    else: deps(t)
                    if kind == 'table': lines += ['bool has_'+name+';']
                    lines += [self.ctype(t)+' '+name+';'] if kind == 'union' else self.fields(t, name)
                if kind == 'union':
                    h.extend(f'#define {cn}_{m["_c_name"]}_tag UINT64_C({m["ordinal"]})' for m in self.members(key))
                    h.append(f'#define {cn}_unknown_tag UINT64_MAX')
                    lines = ['uint64_t tag;', 'union {', *['    '+l for l in lines], '} value;']
            h.extend(['struct '+cn+' {', *['    '+l for l in (lines or ['unsigned char unused;'])], '};'])
            active.remove(key); done.add(key)
        for key in sorted(self.owned): emit(key)
        for key in sorted(self.helpers): emit(key)
        return h

    def conversion(self, t, src, dst, direction, depth='depth'):
        k = t['kind_v2']; out = []
        # Every C expression is a field base; strings and vectors have suffix fields.
        if direction == 'from':
            if k == 'primitive': return [f'{dst} = {src};']
            if k == 'internal': return [f'{dst} = static_cast<std::remove_cvref_t<decltype({dst})>>({src});']
            if k in ('handle', 'endpoint'): return [f'budget.DescriptorSlot({src});', f'{dst} = std::remove_cvref_t<decltype({dst})>(fidl::bsd::DescriptorForC({src}));']
            if k == 'identifier':
                ident = t['identifier']; kind, _ = self.decls[ident]
                if kind in ('enum', 'bits'): return [f'{dst} = static_cast<{self.cpp(ident)}>({src});']
                if t.get('nullable'):
                    expr = f'FromC({src}, budget, {depth}+1)'
                    make = f'std::make_unique<{self.cpp(ident)}>({expr})'
                    return [f'if ({src}) {{ {dst} = {make}; }} else {{ {dst}.reset(); }}']
                return [f'{dst} = FromC(&{src}, budget, {depth}+1);']
            nullable = t.get('nullable', False)
            if nullable:
                out += [f'if (!{src}_present) {{', f'  if ({src}_size || {src}) throw std::system_error(EINVAL, std::generic_category());', f'  {dst}.reset();', '} else {', f'{dst}.emplace();']
                dst = f'(*{dst})'
            if k in ('string', 'vector'):
                bound = t.get('maybe_element_count', 0xffffffff)
                out += [f'if ({src}_size > {bound}ULL || ({src}_size && !{src})) throw std::system_error(EINVAL, std::generic_category());', f'budget.Consume({src}_size);']
            if k == 'string': out += [f'{dst} = std::string({src} ? {src} : "", {src}_size);']
            else:
                e = t['element_type']; i = self.fresh()
                count = str(t['element_count']) if k == 'array' else src+'_size'
                if k == 'array': out += [f'budget.Consume({count});']
                else: out += [f'{dst}.reserve({count});']
                out += [f'for (size_t {i}=0; {i} < {count}; ++{i}) {{']
                target = f'{dst}[{i}]'
                if k == 'vector':
                    target = self.fresh()
                    out += [f'auto {target} = fidl::internal::DefaultConstructPossiblyInvalidObject<typename std::remove_cvref_t<decltype({dst})>::value_type>::Make();']
                out += self.conversion(e, self.elem(e, f'{src}[{i}]'), target, direction, depth+'+1')
                if k == 'vector': out += [f'{dst}.push_back(std::move({target}));']
                out += ['}']
            if nullable: out += ['}']
            return out
        if k == 'primitive': return [f'{dst} = {src};']
        if k == 'internal': return [f'{dst} = static_cast<int32_t>({src});']
        if k in ('handle', 'endpoint'):
            owner = src + ('.descriptor()' if k == 'endpoint' else '')
            return [f'arena.Borrow({owner}, &{dst});']
        if k == 'identifier':
            ident = t['identifier']; kind, _ = self.decls[ident]
            if kind in ('enum', 'bits'): return [f'{dst} = static_cast<{self.ctype(t)}>({src});']
            if t.get('nullable'):
                return [f'if ({src}) {{', f'{dst} = arena.Allocate<{cname(ident)}>(1);', f'ToC(*{src}, *{dst}, arena, {depth}+1);', '}']
            return [f'ToC({src}, {dst}, arena, {depth}+1);']
        nullable = t.get('nullable', False)
        if nullable:
            out += [f'{dst}_present = bool({src});', f'if ({src}) {{']
            src = f'(*{src})'
        if k == 'string': out += [f'{dst} = {src}.data(); {dst}_size = {src}.size();']
        else:
            e = t['element_type']; i = self.fresh()
            count = str(t['element_count']) if k == 'array' else src+'.size()'
            if k == 'vector': out += [f'{dst}_size = {count};', f'{dst} = arena.Allocate<{self.ctype(e)}>({count});']
            out += [f'for (size_t {i}=0; {i} < {count}; ++{i}) {{']
            out += self.conversion(e, f'{src}[{i}]', self.elem(e, f'{dst}[{i}]'), direction, depth+'+1')
            out += ['}']
        if nullable: out += ['}']
        return out

    def bridge(self):
        cc = []
        aggregates = [i for i in sorted(self.owned) if self.decls[i][0] not in ('enum', 'bits')]
        for ident in aggregates:
            cn = cname(ident); native = self.cpp(ident)
            cc += [f'inline {native} FromC(const {cn}*, fidl::bsd::CEncodeBudget&, size_t);', f'inline void ToC({native}&, {cn}&, fidl::bsd::CViewArena&, size_t);']
        for ident in aggregates:
            kind, d = self.decls[ident]; cn = cname(ident); native = self.cpp(ident)
            cc += [f'inline {native} FromC(const {cn}* input, fidl::bsd::CEncodeBudget& budget, size_t depth) {{', 'if (!input) throw std::system_error(EINVAL, std::generic_category());', 'budget.Enter(depth);', f'auto value = fidl::internal::DefaultConstructPossiblyInvalidObject<{native}>::Make();']
            if kind == 'union': cc += ['switch (input->tag) {']
            for m in self.members(ident):
                name = m['_c_name']; get = m['_cpp_name']; t = m['type']
                src = 'input->'+name; dst = 'value.'+get+'()'
                if kind == 'table':
                    cc += [f'if (input->has_{name}) {{', f'{dst}.emplace(fidl::internal::DefaultConstructPossiblyInvalidObject<typename std::remove_cvref_t<decltype({dst})>::value_type>::Make());']
                    dst = '(*'+dst+')'
                if kind == 'union':
                    cc += [f'case {m["ordinal"]}ULL: {{']
                    temp = self.fresh()
                    cc += [f'auto {temp} = fidl::internal::DefaultConstructPossiblyInvalidObject<std::remove_cvref_t<decltype({dst}.value())>>::Make();']
                    src = self.elem(t, 'input->value.'+name); dst = temp
                cc += self.conversion(t, src, dst, 'from')
                if kind == 'table': cc += ['}']
                if kind == 'union': cc += [f'value.{get}(std::move({dst})); break;', '}']
            if kind == 'union': cc += ['default: throw std::system_error(EINVAL, std::generic_category());', '}']
            cc += ['return value;', '}', f'inline {native} FromC(const {cn}* input) {{ fidl::bsd::CEncodeBudget budget; return FromC(input, budget, 0); }}']
            cc += [f'inline void ToC({native}& value, {cn}& data, fidl::bsd::CViewArena& arena, size_t depth) {{', 'if (depth > 64) throw std::system_error(EINVAL, std::generic_category());']
            if kind == 'union': cc += ['data.tag = static_cast<uint64_t>(value.Which());', 'switch (data.tag) {']
            for m in self.members(ident):
                name = m['_c_name']; get = m['_cpp_name']; t = m['type']
                src = 'value.'+get+'()'; dst = 'data.'+name
                if kind == 'table': cc += [f'data.has_{name} = bool({src});', f'if ({src}) {{']; src = '(*'+src+')'
                if kind == 'union': cc += [f'case {m["ordinal"]}ULL: {{']; src = src+'.value()'; dst = self.elem(t, 'data.value.'+name)
                cc += self.conversion(t, src, dst, 'to')
                if kind == 'table': cc += ['}']
                if kind == 'union': cc += ['break;', '}']
            if kind == 'union': cc += ['default: data.tag = UINT64_MAX; break;', '}']
            cc += ['}', f'struct View_{cn} {{', f'{cn} data{{}};', 'fidl::bsd::CViewArena arena;', f'explicit View_{cn}({native}& value) {{ ToC(value, data, arena, 0); }}', '};']
        return cc
