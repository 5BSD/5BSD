# SPDX-License-Identifier: BSD-2-Clause
"""Direct FIDL v2 wire encoders and decoders for the C ABI's structures.

For every aggregate the C bindings expose, emit CWEnc_<name>() (C struct to
wire bytes, written into the connection's packet) and CWDec_<name>() (wire
bytes to a C view, with strings copied NUL-terminated and other
variable-size data in a per-message arena).  The rules are the natural
codec's (contrib/fuchsia/sdk/lib/fidl/cpp: natural_coding_traits.h,
internal/natural_types.h, natural_decoder.h), including the order in which
out-of-line objects are laid out and validated, so both codecs produce and
accept the same bytes; lib/libfidl/tests/c_wire_test.cc checks this.
"""
from generate_bsd_c_types import cname

HANDLE_TYPES = {'handle': 0, 'channel': 4, 'socket': 14}
SAME_RIGHTS = 0x80000000
UNBOUNDED = 0xffffffff
CTYPES = {'bool': 'bool', 'int8': 'int8_t', 'uint8': 'uint8_t',
          'int16': 'int16_t', 'uint16': 'uint16_t', 'int32': 'int32_t',
          'uint32': 'uint32_t', 'int64': 'int64_t', 'uint64': 'uint64_t',
          'float32': 'float', 'float64': 'double'}


class Wire:
    def __init__(self, types):
        self.t = types
        self.serial = 0

    def fresh(self, stem='w'):
        self.serial += 1
        return f'{stem}{self.serial}'

    # -- type facts --------------------------------------------------------
    def decl(self, t):
        return self.t.decls[t['identifier']]

    def size(self, t):
        return t['type_shape_v2']['inline_size']

    def underlying(self, d):
        u = d['type']
        return u if isinstance(u, str) else u['subtype']

    def flat(self, t):
        """C element layout equals the wire layout (no validation needed)."""
        k = t['kind_v2']
        if k == 'primitive':
            return t['subtype'] != 'bool'
        if k == 'identifier' and not t.get('nullable'):
            kind, d = self.decl(t)
            return kind in ('enum', 'bits') and not d['strict']
        return False

    def scalar_check(self, t, value):
        """C++ condition that is true for an invalid scalar, or None."""
        k = t['kind_v2']
        if k == 'primitive' and t['subtype'] == 'bool':
            return f'({value}) > 1'
        if k == 'internal':
            # fidl::internal::FrameworkErr is a strict enum of one value.
            return f'({value}) != -2'
        if k == 'identifier':
            kind, d = self.decl(t)
            if kind == 'enum' and d['strict']:
                values = sorted({int(m['value']['value']) for m in d['members']})
                if not values:
                    return 'true'
                return ' && '.join(f'({value}) != {self.literal(v)}' for v in values)
            if kind == 'bits' and d['strict']:
                return f'(static_cast<uint64_t>({value}) & ~UINT64_C({int(d["mask"])})) != 0'
        return None

    @staticmethod
    def literal(v):
        if v == -(1 << 63):
            return '(-9223372036854775807LL - 1)'
        return f'{v}LL' if v < 0 else f'{v}ULL'

    def scalar_ctype(self, t):
        k = t['kind_v2']
        if k == 'primitive':
            return CTYPES[t['subtype']]
        if k == 'internal':
            return 'int32_t'
        kind, d = self.decl(t)
        return CTYPES[self.underlying(d)]

    def handle_spec(self, t):
        if t['kind_v2'] == 'endpoint':
            return 4, SAME_RIGHTS
        return HANDLE_TYPES[t['subtype']], t.get('rights', SAME_RIGHTS)

    def limit(self, t):
        return t.get('maybe_element_count', UNBOUNDED)

    def elem(self, t, expression):
        return self.t.elem(t, expression)

    # -- encoding ------------------------------------------------------------
    def enc(self, t, v, at, depth):
        """Encode C value base v at body offset expression at."""
        k = t['kind_v2']
        nullable = t.get('nullable', False)
        if k in ('primitive', 'internal') or (
                k == 'identifier' and self.decl(t)[0] in ('enum', 'bits')):
            ctype = self.scalar_ctype(t)
            out = []
            bad = self.scalar_check(t, v)
            if bad and k != 'primitive':
                out.append(f'if ({bad}) e.Fail(EINVAL);')
            if k == 'primitive' and t['subtype'] == 'bool':
                return out + [f'e.Put<uint8_t>({at}, ({v}) ? 1 : 0);']
            return out + [f'e.Put<{ctype}>({at}, {v});']
        if k in ('handle', 'endpoint'):
            obj, rights = self.handle_spec(t)
            return [f'e.Handle({at}, {v}, {obj}, {rights:#x}u, {str(nullable).lower()});']
        if k == 'identifier':
            kind, d = self.decl(t)
            fn = 'CWEnc_' + cname(t['identifier'])
            if kind == 'union':
                if nullable:
                    return [f'if ({v}) {fn}(e, {v}, {at}, {depth});']
                return [f'{fn}(e, &{v}, {at}, {depth});']
            if kind == 'table':
                return [f'{fn}(e, &{v}, {at}, {depth});']
            if nullable:
                o = self.fresh('o')
                return [f'if ({v}) {{',
                        f'  if ({depth} + 1 > fidl::bsd::cwire::kDepthMax) {{ e.Fail(EINVAL); }} else {{',
                        f'    e.Put<uint64_t>({at}, fidl::bsd::cwire::kAllocPresent);',
                        f'    size_t {o} = e.Alloc({d["type_shape_v2"]["inline_size"]});',
                        f'    {fn}(e, {v}, {o}, {depth} + 1);',
                        '  }',
                        '}']
            return [f'{fn}(e, &{v}, {at}, {depth});']
        out = []
        if nullable:
            out += [f'if (!{v}_present) {{',
                    f'  if ({v}_size || {v}) e.Fail(EINVAL);',
                    '} else {']
        if k == 'string':
            out += [f'e.String({at}, {v}, {v}_size, {self.limit(t)}u, {depth});']
        elif k == 'vector':
            e_t = t['element_type']; stride = self.size(e_t)
            b = self.fresh('b'); i = self.fresh('i')
            out += [f'if ({v}_size > {self.limit(t)}u || ({v}_size && !{v}) ||',
                    f'    {depth} + 1 > fidl::bsd::cwire::kDepthMax ||',
                    f'    {v}_size > {0x7fffffff // max(stride, 1)}u) {{',
                    '  e.Fail(EINVAL);',
                    '} else {',
                    f'  e.Put<uint64_t>({at}, {v}_size);',
                    f'  e.Put<uint64_t>({at} + 8, fidl::bsd::cwire::kAllocPresent);',
                    f'  size_t {b} = e.Alloc({v}_size * {stride});']
            if self.flat(e_t):
                out += [f'  e.PutBytes({b}, {v}, {v}_size * {stride});']
            else:
                out += [f'  for (size_t {i} = 0; {i} < {v}_size; ++{i}) {{']
                out += ['    ' + l for l in self.enc(
                    e_t, self.elem(e_t, f'{v}[{i}]'), f'{b} + {i} * {stride}',
                    f'{depth} + 1')]
                out += ['  }']
            out += ['}']
        elif k == 'array':
            e_t = t['element_type']; stride = self.size(e_t)
            n = t['element_count']; i = self.fresh('i')
            if self.flat(e_t):
                out += [f'e.PutBytes({at}, {v}, {n * stride});']
            else:
                out += [f'for (size_t {i} = 0; {i} < {n}; ++{i}) {{']
                out += ['  ' + l for l in self.enc(
                    e_t, self.elem(e_t, f'{v}[{i}]'), f'{at} + {i} * {stride}',
                    depth)]
                out += ['}']
        else:
            raise ValueError('unsupported C wire type: ' + k)
        if nullable:
            out += ['}']
        return out

    # -- decoding ------------------------------------------------------------
    def dec(self, t, v, at, depth):
        """Decode the wire value at body offset at into C value base v."""
        k = t['kind_v2']
        nullable = t.get('nullable', False)
        fail = 'return d.Fail();'
        if k in ('primitive', 'internal') or (
                k == 'identifier' and self.decl(t)[0] in ('enum', 'bits')):
            ctype = self.scalar_ctype(t)
            if k == 'primitive' and t['subtype'] == 'bool':
                x = self.fresh('x')
                return [f'{{ uint8_t {x} = d.Get<uint8_t>({at}); if ({x} > 1) {fail} {v} = {x} != 0; }}']
            out = [f'{v} = d.Get<{ctype}>({at});']
            bad = self.scalar_check(t, v)
            if bad:
                out.append(f'if ({bad}) {fail}')
            return out
        if k in ('handle', 'endpoint'):
            obj, rights = self.handle_spec(t)
            return [f'if (!d.Handle({at}, &{v}, {obj}, {rights:#x}u, {str(nullable).lower()})) return false;']
        if k == 'identifier':
            kind, d_ = self.decl(t)
            cn = cname(t['identifier']); fn = 'CWDec_' + cn
            if kind == 'union' and nullable:
                return [f'if (d.Get<uint64_t>({at}) == 0) {{',
                        f'  if (d.Get<uint64_t>({at} + 8) != 0) {fail}',
                        f'  {v} = nullptr;',
                        '} else {',
                        f'  {v} = d.arena().New<{cn}>(1);',
                        f'  if (!{fn}(d, {at}, {v}, {depth})) return false;',
                        '}']
            if kind in ('union', 'table') or not nullable:
                return [f'if (!{fn}(d, {at}, &{v}, {depth})) return false;']
            o = self.fresh('o')
            return [f'if (d.Get<uint64_t>({at}) == 0) {{',
                    f'  {v} = nullptr;',
                    '} else {',
                    f'  if ({depth} + 1 > fidl::bsd::cwire::kDepthMax) {fail}',
                    f'  {v} = d.arena().New<{cn}>(1);',
                    f'  size_t {o};',
                    f'  if (!d.Claim({d_["type_shape_v2"]["inline_size"]}, &{o})) return false;',
                    f'  if (!{fn}(d, {o}, {v}, {depth} + 1)) return false;',
                    '}']
        if k == 'string':
            present = f'&{v}_present' if nullable else 'nullptr'
            return [f'if (!d.String({at}, &{v}, &{v}_size, {present}, {self.limit(t)}u, {depth})) return false;']
        if k == 'vector':
            e_t = t['element_type']; stride = self.size(e_t)
            n = self.fresh('n'); b = self.fresh('b'); i = self.fresh('i')
            present = f'&{v}_present' if nullable else 'nullptr'
            ctype = self.t.ctype(e_t)
            out = [f'size_t {n}, {b};',
                   f'if (!d.VectorHeader({at}, {stride}, {self.limit(t)}u, {present}, {depth}, &{n}, &{b})) return false;',
                   f'{v}_size = {n};']
            if self.flat(e_t):
                out += [f'{v} = {n} ? reinterpret_cast<{ctype} *>(const_cast<uint8_t *>(d.Ptr({b}))) : nullptr;']
            else:
                out += [f'{v} = d.arena().New<{ctype}>({n});',
                        f'for (size_t {i} = 0; {i} < {n}; ++{i}) {{']
                out += ['  ' + l for l in self.dec(
                    e_t, self.elem(e_t, f'{v}[{i}]'), f'{b} + {i} * {stride}',
                    f'{depth} + 1')]
                out += ['}']
            return [f'{{'] + ['  ' + l for l in out] + ['}']
        if k == 'array':
            e_t = t['element_type']; stride = self.size(e_t)
            count = t['element_count']; i = self.fresh('i')
            if self.flat(e_t):
                return [f'memcpy({v}, d.Ptr({at}), {count * stride});']
            out = [f'for (size_t {i} = 0; {i} < {count}; ++{i}) {{']
            out += ['  ' + l for l in self.dec(
                e_t, self.elem(e_t, f'{v}[{i}]'), f'{at} + {i} * {stride}',
                depth)]
            return out + ['}']
        raise ValueError('unsupported C wire type: ' + k)

    # -- aggregates ------------------------------------------------------------
    def members(self, ident):
        return self.t.members(ident)

    def functions(self, idents):
        """Declarations and definitions for these aggregates."""
        decls, defs = [], []
        for ident in idents:
            kind, d = self.t.decls[ident]
            cn = cname(ident)
            decls += [f'inline void CWEnc_{cn}(fidl::bsd::cwire::Encoder&, const {cn}*, size_t, size_t);',
                      f'inline bool CWDec_{cn}(fidl::bsd::cwire::Decoder&, size_t, {cn}*, size_t);']
            getattr(self, kind)(ident, d, cn, defs)
        return decls + defs

    def struct(self, ident, d, cn, out):
        members = self.members(ident)
        enc = [f'inline void CWEnc_{cn}(fidl::bsd::cwire::Encoder& e, const {cn}* v, size_t at, size_t depth) {{',
               'if (e.error()) return;',
               '(void)v; (void)at; (void)depth;']
        dec = [f'inline bool CWDec_{cn}(fidl::bsd::cwire::Decoder& d, size_t at, {cn}* v, size_t depth) {{',
               '(void)v; (void)depth;']
        for m in members:
            off = m['field_shape_v2']['offset']
            enc += self.enc(m['type'], 'v->' + m['_c_name'], f'at + {off}', 'depth')
            dec += self.dec(m['type'], 'v->' + m['_c_name'], f'at + {off}', 'depth')
        if not members:
            dec += ['if (d.Get<uint8_t>(at) != 0) return d.Fail();']
        for m in members:
            start = m['field_shape_v2']['offset'] + self.size(m['type'])
            for j in range(m['field_shape_v2']['padding']):
                dec += [f'if (*d.Ptr(at + {start + j}) != 0) return d.Fail();']
        out += enc + ['}'] + dec + ['return d.ok();', '}']

    def union(self, ident, d, cn, out):
        enc = [f'inline void CWEnc_{cn}(fidl::bsd::cwire::Encoder& e, const {cn}* v, size_t at, size_t depth) {{',
               'if (e.error()) return;',
               'if (depth + 1 > fidl::bsd::cwire::kDepthMax) { e.Fail(EINVAL); return; }',
               'switch (v->tag) {']
        dec = [f'inline bool CWDec_{cn}(fidl::bsd::cwire::Decoder& d, size_t at, {cn}* v, size_t depth) {{',
               'const uint64_t tag = d.Get<uint64_t>(at);',
               'switch (tag) {']
        for m in self.members(ident):
            t = m['type']; size = self.size(t); ordinal = m['ordinal']
            base = self.elem(t, 'v->value.' + m['_c_name'])
            enc += [f'case {ordinal}ULL: {{',
                    f'  auto env = e.BeginEnvelope(at + 8, {size});',
                    f'  size_t target = e.EnvelopeTarget(env, {size});']
            enc += ['  ' + l for l in self.enc(t, base, 'target', 'depth + 1')]
            enc += ['  e.EndEnvelope(env);', f'  e.Put<uint64_t>(at, {ordinal}ULL);', '  return;', '}']
            dec += [f'case {ordinal}ULL: {{',
                    '  if (depth + 1 > fidl::bsd::cwire::kDepthMax) return d.Fail();',
                    '  fidl::bsd::cwire::Decoder::Envelope env;',
                    '  size_t target;',
                    f'  if (!d.BeginEnvelope(at + 8, {size}, &env, &target)) return false;']
            dec += ['  ' + l for l in self.dec(t, base, 'target', 'depth + 1')]
            dec += [f'  v->tag = {ordinal}ULL;', '  return d.EndEnvelope(env);', '}']
        enc += ['default: e.Fail(EINVAL); return;', '}', '}']
        if d['strict']:
            dec += ['default: return d.Fail();']
        else:
            dec += ['default:',
                    '  if (depth + 1 > fidl::bsd::cwire::kDepthMax) return d.Fail();',
                    '  if (!d.UnknownEnvelope(at + 8, true)) return false;',
                    '  if (tag == 0) return d.Fail();',
                    '  v->tag = UINT64_MAX;',
                    '  return true;']
        dec += ['}', '}']
        out += enc + dec

    def table(self, ident, d, cn, out):
        members = sorted(self.members(ident), key=lambda m: m['ordinal'])
        enc = [f'inline void CWEnc_{cn}(fidl::bsd::cwire::Encoder& e, const {cn}* v, size_t at, size_t depth) {{',
               'if (e.error()) return;',
               '(void)v; (void)depth;',
               'uint64_t count = 0;']
        for m in members:
            enc += [f'if (v->has_{m["_c_name"]}) count = {m["ordinal"]};']
        enc += ['e.Put<uint64_t>(at, count);',
                'e.Put<uint64_t>(at + 8, fidl::bsd::cwire::kAllocPresent);',
                'if (count == 0) return;',
                'if (depth + 2 > fidl::bsd::cwire::kDepthMax) { e.Fail(EINVAL); return; }',
                'size_t base = e.Alloc(count * 8);']
        for m in members:
            t = m['type']; size = self.size(t); name = m['_c_name']
            enc += [f'if (v->has_{name}) {{',
                    f'  auto env = e.BeginEnvelope(base + {(m["ordinal"] - 1) * 8}, {size});',
                    f'  size_t target = e.EnvelopeTarget(env, {size});']
            enc += ['  ' + l for l in self.enc(t, 'v->' + name, 'target', 'depth + 2')]
            enc += ['  e.EndEnvelope(env);', '}']
        enc += ['}']
        known = {m['ordinal']: m for m in members}
        dec = [f'inline bool CWDec_{cn}(fidl::bsd::cwire::Decoder& d, size_t at, {cn}* v, size_t depth) {{',
               'if (d.Get<uint64_t>(at + 8) != fidl::bsd::cwire::kAllocPresent) return d.Fail();',
               'if (depth + 2 > fidl::bsd::cwire::kDepthMax) return d.Fail();',
               'const uint64_t count = d.Get<uint64_t>(at);',
               'size_t base, bytes;',
               'if (__builtin_mul_overflow(count, size_t(8), &bytes) || !d.Claim(bytes, &base)) return d.Fail();',
               'for (uint64_t ordinal = 1; ordinal <= count; ++ordinal) {',
               '  const size_t env_at = base + (ordinal - 1) * 8;',
               '  switch (ordinal) {']
        for ordinal, m in sorted(known.items()):
            t = m['type']; size = self.size(t); name = m['_c_name']
            dec += [f'  case {ordinal}: {{',
                    '    if (d.Get<uint64_t>(env_at) == 0) break;',
                    f'    v->has_{name} = true;',
                    '    fidl::bsd::cwire::Decoder::Envelope env;',
                    '    size_t target;',
                    f'    if (!d.BeginEnvelope(env_at, {size}, &env, &target)) return false;']
            dec += ['    ' + l for l in self.dec(t, 'v->' + name, 'target', 'depth + 2')]
            dec += ['    if (!d.EndEnvelope(env)) return false;', '    break;', '  }']
        dec += ['  default:',
                '    if (!d.UnknownEnvelope(env_at, false)) return false;',
                '  }',
                '}',
                'return d.ok();',
                '}']
        out += enc + dec
