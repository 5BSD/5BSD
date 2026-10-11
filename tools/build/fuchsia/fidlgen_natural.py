# SPDX-License-Identifier: BSD-2-Clause
"""Native BSD natural C++ types from fidlc JSON IR.

This replaces the Go fidlgen_cpp stage of the BSD bindings.  It ports the
part of fidlgen_cpp the native backend uses -- the compiler model in
lib/fidlgen_cpp (names, keyword escaping, type mapping, declaration order,
struct padding) with the fuchsia-native.patch choices (fidl::bsd descriptor
and endpoint types, no __Fuchsia__ guards, the native transport) -- and
executes upstream's own templates from contrib/fuchsia/tools/fidl/
fidlgen_cpp/codegen through gotemplate.py.  Output is byte-identical to
`fidlgen_cpp -native-bsd` for the five files the backend publishes:
markers.h, common_types.{h,cc} and natural_types.{h,cc}.

Only the unified (natural) and wire name variants are modelled; HLCPP names
and the messaging, wire-type and conversion templates are not used by the
native bindings.
"""
import re
from pathlib import Path

import fidlgen_reserved as reserved
from gotemplate import Templates, TemplateError

TEMPLATE_FILES = (
    'file_markers.tmpl', 'file_common_types_header.tmpl',
    'file_common_types_source.tmpl', 'file_natural_types_header.tmpl',
    'file_natural_types_source.tmpl', 'natural_struct.tmpl',
    'natural_table.tmpl', 'natural_union.tmpl', 'fragment_enum.tmpl',
    'fragment_bits.tmpl', 'fragment_const.tmpl', 'fragment_alias.tmpl')
FILES = ('Markers', 'CommonTypesHeader', 'CommonTypesSource',
         'NaturalTypesHeader', 'NaturalTypesSource')
TEMPLATE_DIR = 'contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen'


class GeneratorError(Exception):
    pass


# ------------------------------------------------------------ name casing
def _is_upper(c):
    return c.isupper()


def name_parts(name):
    """fidlgen.nameParts: RFC-0040 identifier parts."""
    parts = []
    for part in name.split('_'):
        start = 0
        last = part[:1]
        last_start = 0
        for i, cur in enumerate(part):
            if i == 0:
                continue
            if _is_upper(cur) and not _is_upper(last):
                parts.append(part[start:i])
                start = i
            if not (_is_upper(cur) or cur.isdigit()) and _is_upper(last) \
                    and start != last_start:
                parts.append(part[start:last_start])
                start = last_start
            last_start = i
            last = cur
        parts.append(part[start:])
    return parts


def _title(s):
    return s[:1].upper() + s[1:]


def to_snake_case(name):
    return '_'.join(p.lower() for p in name_parts(name))


def to_upper_camel_case(name):
    return ''.join(_title(p.lower()) or '_' for p in name_parts(name))


def remove_leading_k(name):
    if len(name) >= 2 and name[0] == 'k' and name[1].isupper():
        return name[1:]
    return name


def const_name_to_k_camel_case(name):
    return 'k' + to_upper_camel_case(remove_leading_k(name))


_UNIVERSAL = set(reserved.CPP_KEYWORDS + reserved.ERRNOS +
                 reserved.FIDL_NAMES + reserved.MISC_NAMES +
                 reserved.ZX_NAMES + reserved.MACRO_NAMES)
_NAMESPACE_RESERVED = set(reserved.CPP_KEYWORDS + reserved.ERRNOS +
                          reserved.MISC_NAMES + reserved.ZX_NAMES +
                          reserved.MACRO_NAMES)
_TYPE_RESERVED = _UNIVERSAL | {'Clone'}


def change_if_reserved(name, names):
    return name + '_' if name in names else name


# ------------------------------------------------------------ C++ names
class Variant:
    """fidlgen_cpp's currentVariant: which name UseUnified/UseWire print."""
    current = None


class Namespace(tuple):
    def Namespace(self):
        return self

    def __str__(self):
        return '::' + self.NoLeading() if self else ''

    def NoLeading(self):
        return '::'.join(self)

    def append(self, part):
        return Namespace(self + (part,))


class _Part:
    pass


class StringPart(_Part):
    def __init__(self, s):
        self.s = s

    def __str__(self):
        return self.s

    def Self(self):
        return self.s

    def nest(self, name):
        return NestedPart(self, StringPart(name))

    def template(self, args):
        return TemplatePart(self, args)

    def append_name(self, suffix):
        return StringPart(self.s + suffix)


class NestedPart(_Part):
    def __init__(self, left, right):
        self.left, self.right = left, right

    def __str__(self):
        return f'{self.left}::{self.right}'

    def Self(self):
        return self.right.Self()

    def nest(self, name):
        return NestedPart(self.left, self.right.nest(name))

    def template(self, args):
        return TemplatePart(self, args)

    def append_name(self, suffix):
        return NestedPart(self.left, self.right.append_name(suffix))


class TemplatePart(_Part):
    def __init__(self, tmpl, args):
        self.tmpl, self.args = tmpl, args

    def __str__(self):
        return f'{self.tmpl}<{self.args}>'

    def Self(self):
        return self.tmpl.Self()

    def nest(self, name):
        return NestedPart(self, StringPart(name))


class Name:
    def __init__(self, part, ns=Namespace()):
        self.part, self.ns = part, ns

    def __str__(self):
        ns = str(self.ns)
        return (ns + '::' if ns else '') + str(self.part)

    def __eq__(self, other):
        return isinstance(other, Name) and str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    def Name(self):
        return str(self.part)

    def Self(self):
        return self.part.Self()

    def NoLeading(self):
        ns = self.ns.NoLeading()
        return (ns + '::' if ns else '') + str(self.part)

    def Namespace(self):
        return self.ns

    def nest(self, nested):
        return Name(self.part.nest(nested), self.ns)

    def template(self, arg):
        return Name(self.part.template(str(arg)), self.ns)

    def array_template(self, arg, count):
        return Name(self.part.template(f'{arg}, {count}'), self.ns)

    def append_name(self, suffix):
        return Name(self.part.append_name(suffix), self.ns)


def make_name(text):
    i = text.rfind('::')
    if i < 0:
        return Name(StringPart(text))
    return Name(StringPart(text[i + 2:]), Namespace(text[:i].split('::')))


def simple_name(text):
    return Name(StringPart(text))


class NameVariants:
    """nameVariants with the Unified and Wire names (HLCPP is unused)."""

    def __init__(self, unified=None, wire=None):
        self.Unified, self.Wire = unified, wire

    def _pick(self):
        if Variant.current == 'unified':
            return self.Unified
        if Variant.current == 'wire':
            return self.Wire
        raise GeneratorError('name printed with no variant selected')

    def __str__(self):
        return str(self._pick())

    def Name(self):
        return self._pick().Name()

    def Self(self):
        return self._pick().Self()

    def NoLeading(self):
        return self._pick().NoLeading()

    def Namespace(self):
        return self._pick().Namespace()

    def nest(self, c):
        return NameVariants(self.Unified.nest(c), self.Wire.nest(c))

    def nest_variants(self, v):
        return NameVariants(self.Unified.nest(v.Unified.Name()),
                            self.Wire.nest(v.Wire.Name()))

    def append_name(self, suffix):
        return NameVariants(self.Unified.append_name(suffix),
                            self.Wire.append_name(suffix))

    def set_names(self, names):
        self.Unified, self.Wire = names.Unified, names.Wire


def common(name):
    return NameVariants(name, name)


# Declaration and member naming contexts (name_transforms.go).
def unified_namespace(library):
    return Namespace((change_if_reserved('_'.join(library),
                                         _NAMESPACE_RESERVED),))


def wire_namespace(library):
    return unified_namespace(library).append('wire')


def _decl_names(library, name, transform, reserved_names, wire_ns):
    leaf = change_if_reserved(transform(name), reserved_names)
    unified = unified_namespace(library)
    wire = wire_namespace(library) if wire_ns else unified
    return NameVariants(Name(StringPart(leaf), unified),
                        Name(StringPart(leaf), wire))


DECL_CONTEXT = {
    'const': (const_name_to_k_camel_case, _UNIVERSAL, True),
    'alias': (to_upper_camel_case, _TYPE_RESERVED, True),
    'bits': (to_upper_camel_case, _TYPE_RESERVED, True),
    'enum': (to_upper_camel_case, _TYPE_RESERVED, True),
    'struct': (to_upper_camel_case, _TYPE_RESERVED, True),
    'table': (to_upper_camel_case, _TYPE_RESERVED, True),
    'union': (to_upper_camel_case, _TYPE_RESERVED, True),
    'protocol': (to_upper_camel_case, _UNIVERSAL, False),
    'service': (to_upper_camel_case, _UNIVERSAL, False),
}
MEMBER_CONTEXT = {
    'bits': const_name_to_k_camel_case,
    'enum': const_name_to_k_camel_case,
    'struct': to_snake_case,
    'table': to_snake_case,
    'union': to_snake_case,
    'protocol': to_upper_camel_case,
    'service': to_snake_case,
}


def member_names(kind, name):
    n = simple_name(change_if_reserved(MEMBER_CONTEXT[kind](name), _UNIVERSAL))
    return NameVariants(n, n)


def union_tag_names(name):
    # unionMemberTagContext reserves no names.
    n = simple_name(const_name_to_k_camel_case(name))
    return NameVariants(n, n)


ZIRCON_NAMES = {'Rights': ('zx_rights_t', 'ZX_RIGHT'),
                'ObjType': ('zx_obj_type_t', 'ZX_OBJ_TYPE')}
ZIRCON_TIMES = {
    'InstantMono': 'fidl::basic_time<ZX_CLOCK_MONOTONIC>',
    'InstantBoot': 'fidl::basic_time<ZX_CLOCK_BOOT>',
    'InstantMonoTicks': 'fidl::basic_ticks<ZX_CLOCK_MONOTONIC>',
    'InstantBootTicks': 'fidl::basic_ticks<ZX_CLOCK_BOOT>',
}
HANDLE_SUBTYPE_CONSTS = {
    'handle': 'NONE', 'debuglog': 'DEBUGLOG', 'suspendtoken': 'SUSPEND_TOKEN'}
for _s in ('bti channel clock counter event eventpair exception fifo guest '
           'interrupt iob iommu job msi pager pmt port process profile '
           'resource socket stream thread timer vcpu vmar vmo').split():
    HANDLE_SUBTYPE_CONSTS[_s] = _s.upper()

PRIMITIVES = {'bool': 'bool', 'int8': 'int8_t', 'int16': 'int16_t',
              'int32': 'int32_t', 'int64': 'int64_t', 'uint8': 'uint8_t',
              'uint16': 'uint16_t', 'uint32': 'uint32_t',
              'uint64': 'uint64_t', 'float32': 'float', 'float64': 'double'}
BITS = {'bool': 8, 'int8': 8, 'int16': 16, 'int32': 32, 'int64': 64,
        'uint8': 8, 'uint16': 16, 'uint32': 32, 'uint64': 64,
        'float32': 32, 'float64': 64}


def parse_identifier(eci):
    """EncodedCompoundIdentifier "a.b/Decl.member" -> (library, name, member)."""
    library, _, rest = eci.partition('/')
    name, _, member = rest.partition('.')
    return tuple(library.split('.')), name, member


# ------------------------------------------------------------ IR helpers
class Attributes:
    def __init__(self, element):
        self._attributes = element.get('maybe_attributes', [])

    def lookup_attribute(self, name):
        for a in self._attributes:
            if to_snake_case(a['name']) == to_snake_case(name):
                return a
        return None

    def Docs(self):
        attr = self.lookup_attribute('doc')
        if attr is None or len(attr.get('arguments', [])) != 1:
            return ''
        value = attr['arguments'][0]['value']['value']
        if value == '':
            return ''
        return ''.join('\n///' + c for c in value[:-1].split('\n'))


class TypeShape:
    def __init__(self, shape):
        self.InlineSize = shape['inline_size']
        self.Alignment = shape['alignment']
        self.Depth = shape['depth']
        self.MaxHandles = shape['max_handles']
        self.MaxOutOfLine = shape['max_out_of_line']

    def HasPointer(self):
        return self.Depth > 0


class Serializable:
    def __init__(self, decl, attributes):
        library, name, _ = parse_identifier(decl['name'])
        self.IsSerializable = attributes.lookup_attribute(
            'serializable') is not None
        self.Name = '.'.join(library + (name,))


class Strict:
    def __init__(self, strict):
        self.Strictness = bool(strict)

    def IsStrict(self):
        return self.Strictness

    def IsFlexible(self):
        return not self.Strictness


class ConstantValue:
    def __init__(self, unified='', wire=''):
        self.unified, self.wire = unified, wire

    def IsSet(self):
        return self.unified != '' and self.wire != ''

    def __str__(self):
        return self.unified if Variant.current == 'unified' else self.wire


# ------------------------------------------------------------ declarations
class Type(NameVariants):
    def __init__(self):
        super().__init__()
        self.Kind = None
        self.Nullable = False
        self.IsResource = False
        self.ElementType = None
        self.ElementCount = None
        self.InlineInEnvelope = False
        self.NaturalFieldConstraint = ''

    def IsPrimitiveType(self):
        return self.Kind in ('primitive', 'bits', 'enum')


class Decl(NameVariants, Attributes):
    def __init__(self, decl, names):
        NameVariants.__init__(self, names.Unified, names.Wire)
        Attributes.__init__(self, decl)

    def Kind(self):
        return self.KIND


class Kinds:
    Alias, Bits, Const, Enum = 'alias', 'bits', 'const', 'enum'
    Protocol, Service, Struct, Table, Union = (
        'protocol', 'service', 'struct', 'table', 'union')


class StructMember(NameVariants, Attributes):
    def __init__(self, member, names, typ, default, offset):
        NameVariants.__init__(self, names.Unified, names.Wire)
        Attributes.__init__(self, member)
        self.Type = typ
        self.DefaultValue = default
        self.OffsetV2 = offset
        self.NaturalConstraint = typ.NaturalFieldConstraint

    def NaturalInitializer(self):
        def unwrap(t):
            if t.IsPrimitiveType():
                return '{}'
            if t.Kind == 'array':
                return unwrap(t.ElementType)
            return ''
        return '' if self.Type.Nullable else unwrap(self.Type)

    def NaturalPossiblyInvalidDefaultInitializer(self):
        if not self.Type.Nullable:
            if self.Type.Kind == 'array':
                return ('::fidl::internal::DefaultConstructPossiblyInvalid'
                        f'Object<{self.Type.Unified}>::Make()')
            if self.Type.Kind in ('struct', 'table', 'union'):
                return ('::fidl::internal::DefaultConstructPossiblyInvalid'
                        'ObjectTag{}')
        return '{}'


class PaddingMarker:
    def __init__(self, offset, width, mask):
        self.Offset, self.MaskBitWidth, self.Mask = offset, width, mask


class Struct(Decl):
    KIND = Kinds.Struct


class Table(Decl):
    KIND = Kinds.Table


class TableMember(NameVariants, Attributes):
    def __init__(self, member, names, typ):
        NameVariants.__init__(self, names.Unified, names.Wire)
        Attributes.__init__(self, member)
        self.Type = typ
        self.Ordinal = member['ordinal']
        self.NaturalConstraint = typ.NaturalFieldConstraint
        self.MethodHasName = 'has_' + member['name']


class Union(Decl):
    KIND = Kinds.Union


class UnionMember(NameVariants, Attributes):
    def UpperCamelCaseName(self):
        return to_upper_camel_case(self.Name())


class Enum(Decl):
    KIND = Kinds.Enum

    def IsResourceType(self):
        return False

    def IsCompatibleWithError(self):
        return self._subtype in ('int32', 'uint32')

    def UnknownValueForTmpl(self):
        if self.Strictness:
            raise GeneratorError('unknown value of a strict enum')
        value = int(self._raw['maybe_unknown_value'])
        if self._subtype.startswith('int'):
            # Go reads the raw value as int64; it prints signed.
            return value - (1 << 64) if value >= 1 << 63 else value
        return value & ((1 << 64) - 1)

    def UnusedEnumValueForTmpl(self):
        import math
        bits = BITS[self._subtype]
        if len(self.Members) and math.log2(len(self.Members)) >= bits:
            return self.UnknownValueForTmpl()
        signed = not self._subtype.startswith('uint')
        values = set()
        for m in self._raw['members']:
            values.add(int(m['value']['value']))
        top = ((1 << 64) - 1) >> (64 - bits)
        i = top // 2 if signed else top
        while True:
            if i not in values:
                return i & ((1 << 64) - 1)
            i -= 1


class EnumMember(NameVariants, Attributes):
    pass


class RawNamed:
    def __init__(self, name):
        self.Name = name


class Bits(Decl):
    KIND = Kinds.Bits

    def IsResourceType(self):
        return False


class BitsMember(NameVariants, Attributes):
    pass


class Const(Decl):
    KIND = Kinds.Const


class Alias(Decl):
    KIND = Kinds.Alias

    def IsResourceType(self):
        return self._resource


class Protocol(Decl):
    KIND = Kinds.Protocol

    def OpennessValue(self):
        openness = self._raw.get('openness', '')
        return {'open': '::fidl::internal::Openness::kOpen',
                'ajar': '::fidl::internal::Openness::kAjar',
                'closed': '::fidl::internal::Openness::kClosed',
                '': '::fidl::internal::Openness::kClosed'}[openness]


class Method(NameVariants, Attributes):
    def HasDomainError(self):
        return self._result is not None and self._result['has_error']

    def HasFrameworkError(self):
        return self._result is not None and self._result['framework']

    def HasNonEmptyPayload(self):
        if self.HasResponsePayload:
            if self._result is None:
                return True
            return self._result['value_parameters'] > 0
        return False


class FilenameData:
    def __init__(self, library):
        self.library = library

    def LibraryDots(self):
        return '.'.join(self.library)


class Root:
    def __init__(self):
        self.Experiments = []
        self.HandleTypes = []
        self.Library = ()
        self.Decls = []
        self.Dependencies = []
        self.ContainsDriverReferences = False

    def _of(self, kind):
        return [d for d in self.Decls if d.Kind() == kind]

    def Aliases(self):
        return self._of(Kinds.Alias)

    def Bits(self):
        return self._of(Kinds.Bits)

    def Consts(self):
        return self._of(Kinds.Const)

    def Enums(self):
        return self._of(Kinds.Enum)

    def Protocols(self):
        return self._of(Kinds.Protocol)

    def Structs(self):
        return self._of(Kinds.Struct)

    def Tables(self):
        return self._of(Kinds.Table)

    def Unions(self):
        return self._of(Kinds.Union)

    def Namespace(self):
        return unified_namespace(self.Library)


# ------------------------------------------------------------ the compiler
DECL_KEYS = (('const', 'const_declarations'), ('bits', 'bits_declarations'),
             ('enum', 'enum_declarations'),
             ('resource', 'experimental_resource_declarations'),
             ('protocol', 'protocol_declarations'),
             ('service', 'service_declarations'),
             ('struct', 'struct_declarations'),
             ('struct', 'external_struct_declarations'),
             ('table', 'table_declarations'), ('union', 'union_declarations'),
             ('alias', 'alias_declarations'),
             ('new_type', 'new_type_declarations'),
             ('overlay', 'overlay_declarations'))


def for_each_decl(ir):
    """fidlgen Root.ForEachDecl order: (kind, declaration)."""
    for kind, key in DECL_KEYS:
        for decl in ir.get(key, []):
            yield kind, decl


class Compiler:
    def __init__(self, ir):
        self.ir = ir
        self.library = tuple(ir['name'].split('.'))
        # DeclInfo: local declarations and every dependency's declarations.
        self.decls = {}
        for kind, decl in for_each_decl(ir):
            self.decls[decl['name']] = {'kind': kind,
                                        'resource': decl.get('resource')}
        for library in ir.get('library_dependencies', []):
            for name, info in library['declarations'].items():
                self.decls[name] = info
        self.handle_types = set()
        self.structs = {}

    # compileNameVariants
    def names(self, eci):
        library, name, member = parse_identifier(eci)
        if library == ('zx',) and self.library != ('zx',):
            return common(self.zircon_name(name, member, eci))
        info = self.decls.get(library and '.'.join(library) + '/' + name)
        if info is None:
            raise GeneratorError('unknown identifier: ' + eci)
        transform, reserved_names, wire_ns = DECL_CONTEXT[info['kind']]
        names = _decl_names(library, name, transform, reserved_names, wire_ns)
        if member:
            names = names.nest_variants(member_names(info['kind'], member))
        return names

    @staticmethod
    def zircon_name(name, member, eci):
        if member:
            if name in ZIRCON_NAMES:
                return make_name(ZIRCON_NAMES[name][1] + '_' + member.upper())
        else:
            if name in ZIRCON_NAMES:
                return make_name(ZIRCON_NAMES[name][0])
            if name == name.upper():
                return make_name('ZX_' + name)
        raise GeneratorError('Unknown zircon identifier: ' + eci)

    def is_resource(self, eci):
        info = self.decls[eci]
        return bool(info.get('resource'))

    def compile_type(self, val, maybe_alias=None):
        if maybe_alias is not None:
            library, name, _ = parse_identifier(maybe_alias['name'])
            if library == ('zx',) and name in ZIRCON_TIMES:
                r = Type()
                r.set_names(common(make_name(ZIRCON_TIMES[name])))
                r.Kind = 'primitive'
                r.Nullable = val.get('nullable', False)
                r.InlineInEnvelope = val['type_shape_v2']['inline_size'] <= 4
                r.NaturalFieldConstraint = \
                    'fidl::internal::NaturalCodingConstraintEmpty'
                return r
        r = Type()
        kind = val['kind_v2']
        r.Nullable = bool(val.get('nullable', False))
        r.InlineInEnvelope = val['type_shape_v2']['inline_size'] <= 4
        if kind == 'array':
            t = self.compile_type(val['element_type'],
                                  val.get('experimental_maybe_from_alias'))
            count = val['element_count']
            r.set_names(NameVariants(
                make_name('std::array').array_template(t.Unified, count),
                make_name('fidl::Array').array_template(t.Wire, count)))
            r.Kind = 'array'
            r.IsResource = t.IsResource
            r.ElementType = t
            r.ElementCount = count
            r.NaturalFieldConstraint = t.NaturalFieldConstraint
        elif kind == 'vector':
            t = self.compile_type(val['element_type'],
                                  val.get('experimental_maybe_from_alias'))
            unified = make_name('std::vector').template(t.Unified)
            if r.Nullable:
                unified = make_name('std::optional').template(unified)
            r.set_names(NameVariants(
                unified, make_name('fidl::VectorView').template(t.Wire)))
            r.Kind = 'vector'
            r.IsResource = t.IsResource
            r.ElementType = t
            count = val.get('maybe_element_count')
            if count is not None:
                r.NaturalFieldConstraint = (
                    'fidl::internal::NaturalCodingConstraintVector<'
                    f'{t.NaturalFieldConstraint}, {count}>')
            else:
                r.NaturalFieldConstraint = (
                    'fidl::internal::NaturalCodingConstraintVector<'
                    f'{t.NaturalFieldConstraint}>')
        elif kind == 'string':
            unified = make_name('std::string')
            if r.Nullable:
                unified = make_name('std::optional').template(unified)
            r.set_names(NameVariants(unified, make_name('fidl::StringView')))
            r.Kind = 'string'
            count = val.get('maybe_element_count')
            r.NaturalFieldConstraint = (
                f'fidl::internal::NaturalCodingConstraintString<{count}>'
                if count is not None else
                'fidl::internal::NaturalCodingConstraintString<>')
        elif kind == 'handle':
            subtype = val['subtype']
            self.handle_types.add(subtype)
            if val['resource_identifier'] != 'zx/Handle':
                raise GeneratorError('unhandled resource identifier ' +
                                     val['resource_identifier'])
            zx = make_name('zx::' + ('suspend_token' if subtype ==
                                     'suspendtoken' else subtype))
            r.set_names(NameVariants(make_name('fidl::bsd::Descriptor'), zx))
            r.Kind = 'handle'
            r.IsResource = True
            r.NaturalFieldConstraint = (
                'fidl::internal::NaturalCodingConstraintHandle<ZX_OBJ_TYPE_'
                f'{HANDLE_SUBTYPE_CONSTS[subtype]}, {val["rights"]:#x}, '
                f'{"true" if r.Nullable else "false"}>')
        elif kind == 'endpoint':
            if val.get('protocol_transport', 'Channel') != 'Channel':
                raise GeneratorError('only Channel endpoints are native')
            p = self.names(val['protocol'])
            self.handle_types.add('channel')
            end = 'ClientEnd' if val['role'] == 'client' else 'ServerEnd'
            r.set_names(NameVariants(
                make_name('fidl::bsd::' + end).template(p.Unified),
                make_name('fidl::' + end).template(p.Wire)))
            r.Kind = 'endpoint'
            r.IsResource = True
            r.NaturalFieldConstraint = (
                'fidl::internal::NaturalCodingConstraintHandle<'
                'ZX_OBJ_TYPE_CHANNEL, ZX_RIGHT_SAME_RIGHTS, '
                f'{"true" if r.Nullable else "false"}>')
        elif kind == 'primitive':
            r.set_names(common(make_name(PRIMITIVES[val['subtype']])))
            r.Kind = 'primitive'
            r.NaturalFieldConstraint = \
                'fidl::internal::NaturalCodingConstraintEmpty'
        elif kind == 'internal':
            if val['subtype'] != 'framework_error':
                raise GeneratorError('unknown internal type ' +
                                     val['subtype'])
            r.set_names(common(make_name('fidl::internal::FrameworkErr')))
            r.Kind = 'enum'
            r.NaturalFieldConstraint = \
                'fidl::internal::NaturalCodingConstraintEmpty'
        elif kind == 'identifier':
            eci = val['identifier']
            names = self.names(eci)
            info = self.decls.get(eci)
            if info is None:
                raise GeneratorError('unknown identifier: ' + eci)
            decl_kind = info['kind']
            if decl_kind not in ('bits', 'enum', 'const', 'struct', 'table',
                                 'union'):
                raise GeneratorError('unknown declaration type: ' + decl_kind)
            r.Kind = decl_kind
            if decl_kind in ('struct', 'table', 'union'):
                r.IsResource = bool(info.get('resource'))
            if r.Nullable:
                wire = ('fidl::WireOptional' if decl_kind == 'union'
                        else 'fidl::ObjectView')
                r.set_names(NameVariants(
                    make_name('fidl::Box').template(names.Unified),
                    make_name(wire).template(names.Wire)))
            else:
                r.set_names(names)
            r.NaturalFieldConstraint = \
                'fidl::internal::NaturalCodingConstraintEmpty'
        else:
            raise GeneratorError('unknown type kind: ' + kind)
        return r

    def compile_literal(self, literal, typ):
        kind, value = literal['kind'], literal['value']
        if kind == 'string':
            return '"' + value.replace('\\', '\\\\').replace('"', '\\"') \
                .replace('\n', '\\n').replace('\t', '\\t') \
                .replace('\r', '\\r') + '"'
        if kind == 'numeric':
            if value in ('-9223372036854775808', '0x8000000000000000'):
                return '(-9223372036854775807ll-1)'
            if value.startswith('0x') or value.startswith('0b'):
                return value
            if '.' in value:
                if typ.get('kind_v2') == 'primitive' and \
                        typ.get('subtype') == 'float32':
                    return value + 'f'
                return value
            if not value.startswith('-'):
                return value + 'u'
            return value
        if kind == 'bool':
            return value
        if kind == 'default':
            return 'default'
        raise GeneratorError('unknown literal kind: ' + kind)

    def compile_constant(self, val, t, typ):
        kind = val['kind']
        if kind == 'identifier':
            n = self.names(val['identifier'])
            return ConstantValue(str(n.Unified), str(n.Wire))
        if kind == 'literal':
            lit = self.compile_literal(val['literal'], typ)
            if t is not None and t.Kind == 'bits':
                if val['value'] != '0':
                    raise GeneratorError('bits literal must be 0')
                return self.static_cast(lit, t)
            return ConstantValue(lit, lit)
        if kind == 'binary_operator':
            return self.static_cast(val['value'], t)
        raise GeneratorError('unknown constant kind: ' + kind)

    @staticmethod
    def static_cast(value, t):
        return ConstantValue(f'static_cast<{t.Unified}>({value})',
                             f'static_cast<{t.Wire}>({value})')

    # -- declarations
    def compile_struct(self, val):
        r = Struct(val, self.names(val['name']))
        r.IsResourceType = lambda: bool(val.get('resource'))
        r.TypeShapeV2 = TypeShape(val['type_shape_v2'])
        r.Serializable = Serializable(val, r)
        r.PaddingV2 = padding_markers(val)
        members = val['members']
        r.Members = [self.compile_struct_member(m) for m in members]
        r._empty = not members
        if not members:
            r.Members = [self.compile_struct_member({
                'name': '__reserved',
                'type': {'kind_v2': 'primitive', 'subtype': 'uint8',
                         'type_shape_v2': {'inline_size': 1}},
                'maybe_default_value': {
                    'kind': 'literal', 'value': '0',
                    'literal': {'kind': 'numeric', 'value': '0'}},
                'field_shape_v2': {'offset': 0, 'padding': 0}})]
        r.IsEmpty = lambda: r._empty
        return r

    def compile_struct_member(self, val):
        t = self.compile_type(val['type'],
                              val.get('experimental_maybe_from_alias'))
        default = ConstantValue()
        if val.get('maybe_default_value') is not None:
            default = self.compile_constant(val['maybe_default_value'], t,
                                            val['type'])
        return StructMember(val, member_names('struct', val['name']), t,
                            default, val['field_shape_v2']['offset'])

    def compile_table(self, val):
        r = Table(val, self.names(val['name']))
        r.IsResourceType = lambda: bool(val.get('resource'))
        r.TypeShapeV2 = TypeShape(val['type_shape_v2'])
        r.Serializable = Serializable(val, r)
        r.Members = [TableMember(m, member_names('table', m['name']),
                                 self.compile_type(
                                     m['type'],
                                     m.get('experimental_maybe_from_alias')))
                     for m in val['members']]
        return r

    def compile_union(self, val):
        name = self.names(val['name'])
        r = Union(val, name)
        Strict.__init__(r, val['strict'])
        r.IsStrict = lambda: r.Strictness
        r.IsFlexible = lambda: not r.Strictness
        r.IsResourceType = lambda: bool(val.get('resource'))
        r.TypeShapeV2 = TypeShape(val['type_shape_v2'])
        r.Serializable = Serializable(val, r)
        r.TagEnum = name.nest('Tag')
        r.TagUnknown = r.TagEnum.nest(
            '_do_not_handle_this__write_a_default_case_instead')
        r.Members = []
        for index, m in enumerate(val['members'], 1):
            names = member_names('union', m['name'])
            t = self.compile_type(m['type'],
                                  m.get('experimental_maybe_from_alias'))
            member = UnionMember(names.Unified, names.Wire)
            Attributes.__init__(member, m)
            member.Ordinal = m['ordinal']
            member.Type = t
            member.TagName = r.TagEnum.nest_variants(
                union_tag_names(m['name']))
            member.NaturalConstraint = t.NaturalFieldConstraint
            member.NaturalIndex = index
            r.Members.append(member)
        return r

    def compile_enum(self, val):
        r = Enum(val, self.names(val['name']))
        Strict.__init__(r, val['strict'])
        r.IsStrict = lambda: r.Strictness
        r.IsFlexible = lambda: not r.Strictness
        r._raw = val
        r._subtype = val['type']
        r.Enum = RawNamed(val['name'])
        r.Type = common(make_name(PRIMITIVES[val['type']]))
        primitive = {'kind_v2': 'primitive', 'subtype': val['type']}
        r.Members = []
        for m in val['members']:
            names = member_names('enum', m['name'])
            member = EnumMember(names.Unified, names.Wire)
            Attributes.__init__(member, m)
            member.Value = self.compile_constant(m['value'], None, primitive)
            member.EnumMember = RawNamed(m['name'])
            member.IsUnknown = (lambda a=member: a.lookup_attribute(
                'Unknown') is not None)
            r.Members.append(member)
        return r

    def compile_bits(self, val):
        r = Bits(val, self.names(val['name']))
        Strict.__init__(r, val['strict'])
        r.IsStrict = lambda: r.Strictness
        r.IsFlexible = lambda: not r.Strictness
        r.Type = NameVariants(*_pair(self.compile_type(val['type'])))
        r.Mask = val['mask']
        r.Members = []
        for m in val['members']:
            names = member_names('bits', m['name'])
            member = BitsMember(names.Unified, names.Wire)
            Attributes.__init__(member, m)
            member.Value = self.compile_constant(m['value'], None, val['type'])
            r.Members.append(member)
        return r

    def compile_const(self, val):
        r = Const(val, self.names(val['name']))
        if val['type']['kind_v2'] == 'string':
            r.Extern = True
            r.Decorator = 'const'
            r.Type = common(make_name('char*'))
            r.Value = self.compile_constant(val['value'], None, val['type'])
        else:
            t = self.compile_type(val['type'])
            r.Extern = False
            r.Decorator = 'constexpr'
            r.Type = t
            r.Value = self.compile_constant(val['value'], t, val['type'])
        return r

    def compile_alias(self, val):
        r = Alias(val, self.names(val['name']))
        t = self.compile_type(val['type'],
                              val.get('experimental_maybe_from_alias'))
        r._resource = t.IsResource
        r.Type = NameVariants(t.Unified, t.Wire)
        return r

    def compile_protocol(self, val, results):
        transport = 'Channel'
        for a in val.get('maybe_attributes', []):
            if to_snake_case(a['name']) == 'transport':
                args = a.get('arguments', [])
                if len(args) == 1 and args[0]['value']['value']:
                    transport = args[0]['value']['value']
        if transport != 'Channel':
            raise GeneratorError('only Channel protocols are native')
        name = self.names(val['name'])
        r = Protocol(val, name)
        r._raw = val
        r.DiscoverableName = discoverable_name(val, r)
        r.Methods = []
        for m in val['methods']:
            names = member_names('protocol', m['name'])
            method = Method(names.Unified, names.Wire)
            Attributes.__init__(method, m)
            method.Marker = name.nest(names.Wire.Name())
            method.Ordinal = m['ordinal']
            method.HasRequest = m['has_request']
            method.HasRequestPayload = 'maybe_request_payload' in m
            method.HasResponse = m['has_response']
            method.HasResponsePayload = 'maybe_response_payload' in m
            method._result = None
            if 'maybe_response_success_type' in m:
                method._result = results[
                    m['maybe_response_payload']['identifier']]
            r.Methods.append(method)
        return r

    def result_info(self, m):
        """compileResult: what the marker templates need of a result."""
        value = m['maybe_response_success_type']
        ident = value.get('identifier')
        info = self.decls.get(ident) if ident else None
        if info is not None and info['kind'] == 'struct':
            struct = self.structs.get(ident)
            if struct is None:
                raise GeneratorError(
                    f'message body value type {ident} not found')
            count = len(struct['members'])
        else:
            count = 1
        flexible = not m.get('strict', True)
        return {'has_error': m['has_error'],
                'framework': m['has_request'] and m['has_response'] and
                flexible,
                'value_parameters': count}

    def compile(self):
        ir = self.ir
        root = Root()
        root.Experiments = ir.get('experiments', [])
        root.Library = self.library
        for decl in ir.get('struct_declarations', []) + \
                ir.get('external_struct_declarations', []):
            self.structs[decl['name']] = decl
        decls = {}
        for v in ir.get('alias_declarations', []):
            decls[v['name']] = self.compile_alias(v)
        for v in ir.get('bits_declarations', []):
            decls[v['name']] = self.compile_bits(v)
        for v in ir.get('const_declarations', []):
            decls[v['name']] = self.compile_const(v)
        for v in ir.get('enum_declarations', []):
            decls[v['name']] = self.compile_enum(v)
        for v in ir.get('table_declarations', []):
            decls[v['name']] = self.compile_table(v)
        for v in ir.get('union_declarations', []):
            decls[v['name']] = self.compile_union(v)
        for v in ir.get('struct_declarations', []):
            decls[v['name']] = self.compile_struct(v)
        results = {}
        for p in ir.get('protocol_declarations', []):
            for m in p['methods']:
                if 'maybe_response_success_type' in m:
                    results[m['maybe_response_payload']['identifier']] = \
                        self.result_info(m)
        for p in ir.get('protocol_declarations', []):
            decls[p['name']] = self.compile_protocol(p, results)
        if ir.get('service_declarations'):
            raise GeneratorError('services are not supported natively')
        for decl in sorted_decls(ir):
            if decl['name'] in decls:
                root.Decls.append(decls[decl['name']])
        for library in ir.get('library_dependencies', []):
            if library['name'] in (ir['name'], 'zx'):
                continue
            root.Dependencies.append(tuple(library['name'].split('.')))
        if ir.get('protocol_declarations'):
            self.handle_types.add('channel')
        if self.handle_types:
            root.HandleTypes = ['fidl/bsd/descriptor.h', 'fidl/bsd/endpoint.h']
        return root

    def bsd_names(self):
        """The C++ spelling of every type and member (bsd_names.go)."""
        types, members = {}, {}
        for ident, info in sorted(self.decls.items()):
            if info['kind'] in ('alias', 'bits', 'const', 'enum', 'protocol',
                                'struct', 'table', 'union'):
                types[ident] = str(self.names(ident).Unified)
        for key, kind in (('struct_declarations', 'struct'),
                          ('table_declarations', 'table'),
                          ('union_declarations', 'union')):
            for d in self.ir.get(key, []):
                for m in d['members']:
                    members[d['name'] + '/' + m['name']] = str(
                        member_names(kind, m['name']).Unified)
        for d in self.ir.get('protocol_declarations', []):
            for m in d['methods']:
                members[d['name'] + '/' + m['name']] = str(
                    member_names('protocol', m['name']).Unified)
        return {'types': types, 'members': members}


def _pair(t):
    return t.Unified, t.Wire


def discoverable_name(val, attributes):
    attr = attributes.lookup_attribute('discoverable')
    if attr is None:
        return ''
    name = None
    for arg in attr.get('arguments', []):
        if arg['name'] == 'name':
            name = arg['value']['value']
    if name is None:
        library, decl, _ = parse_identifier(val['name'])
        name = '.'.join(library + (decl,))
    return '"' + name + '"'


# ------------------------------------------------------------ padding
def padding_markers(struct):
    """fidlgen Struct.BuildPaddingMarkers with the default (flat) config."""
    shape = struct['type_shape_v2']
    mask = bytearray(shape['inline_size'])
    end = shape['inline_size'] - 1
    for member in reversed(struct['members']):
        field = member['field_shape_v2']
        for j in range(field['padding']):
            mask[end - j] = 0xff
        end = field['offset'] - 1
    markers = []
    for size in (8, 4, 2):
        if shape['alignment'] < size:
            continue
        for i in range(0, len(mask) - size + 1, size):
            chunk = mask[i:i + size]
            if 0xff in chunk:
                markers.append(PaddingMarker(
                    i, size * 8, int.from_bytes(chunk, 'little')))
                mask[i:i + size] = bytes(size)
    if 0xff in mask:
        raise GeneratorError('padding left in an alignment-1 struct')
    return markers


# ------------------------------------------------------------ ordering
def _location_key(decl):
    loc = decl['location']
    return (loc['filename'], loc['line'], loc['column'], loc['length'])


def sorted_decls(ir):
    """DeclDepGraph.SortedDecls: dependencies first, then source order."""
    local = {}
    rev = {}

    def node(name):
        return rev.setdefault(name, set())

    def dep(owner, name):
        node(name).add(owner)

    def from_type(owner, t):
        if t.get('nullable') or t['kind_v2'] == 'endpoint':
            return
        kind = t['kind_v2']
        if kind in ('array', 'vector'):
            from_type(owner, t['element_type'])
        elif kind == 'handle':
            dep(owner, t['resource_identifier'])
        elif kind == 'identifier':
            dep(owner, t['identifier'])

    def from_constant(owner, c):
        if c['kind'] == 'identifier':
            dep(owner, c['identifier'])

    def from_ctor(owner, ctor):
        if ctor.get('nullable'):
            return
        if '/' in ctor['name']:
            dep(owner, ctor['name'])
        for arg in ctor.get('args', []):
            from_ctor(owner, arg)

    for kind, decl in for_each_decl(ir):
        name = decl['name']
        node(name)
        local[name] = decl
        if kind == 'const':
            from_type(name, decl['type'])
            from_constant(name, decl['value'])
        elif kind == 'bits':
            from_type(name, decl['type'])
            for m in decl['members']:
                from_constant(name, m['value'])
        elif kind == 'enum':
            for m in decl['members']:
                from_constant(name, m['value'])
        elif kind == 'resource':
            for p in decl.get('properties', []):
                from_type(name, p['type'])
        elif kind == 'protocol':
            for c in decl.get('composed_protocols', []):
                dep(name, c['name'])
            for m in decl['methods']:
                for key in ('maybe_request_payload', 'maybe_response_payload'):
                    if key in m:
                        dep(name, m[key]['identifier'])
        elif kind == 'service':
            for m in decl['members']:
                from_type(name, m['type'])
        elif kind in ('struct', 'table', 'union', 'overlay'):
            for m in decl['members']:
                from_type(name, m['type'])
                if kind == 'struct' and m.get('maybe_default_value'):
                    from_constant(name, m['maybe_default_value'])
                if m.get('experimental_maybe_from_alias'):
                    from_ctor(name, m['experimental_maybe_from_alias'])
        elif kind == 'alias':
            from_ctor(name, decl['partial_type_ctor'])
        elif kind == 'new_type':
            if decl.get('experimental_maybe_from_alias'):
                from_ctor(name, decl['experimental_maybe_from_alias'])
            else:
                from_type(name, decl['type'])

    def normalize(names):
        # Visit order is the reverse of the final order: local declarations
        # in reverse source order, then imported names in reverse.
        loc = sorted((n for n in names if n in local),
                     key=lambda n: _location_key(local[n]), reverse=True)
        ext = sorted((n for n in names if n not in local), reverse=True)
        return loc + ext

    out = []
    state = {}

    def visit(name, chain):
        chain = chain + [name]
        if name in state:
            if state[name] == 'processing':
                raise GeneratorError('cyclic dependency: ' +
                                     ' <- '.join(chain))
            return
        state[name] = 'processing'
        for d in normalize(rev[name]):
            visit(d, chain)
        if name in local:
            out.insert(0, local[name])
        state[name] = 'done'

    for name in normalize(list(rev)):
        visit(name, [])
    return out


# ------------------------------------------------------------ templates
class _Namespaces:
    def __init__(self):
        self.current = Namespace()
        self.stack = []

    def ensure(self, arg):
        if isinstance(arg, str):
            new = [p for p in arg.split('::')]
            while new and new[0] == '':
                new = new[1:]
        else:
            new = list(arg.Namespace())
        target = Namespace(new)
        cur = list(self.current)
        while new and cur and new[0] == cur[0]:
            new, cur = new[1:], cur[1:]
        lines = [f'}}  // namespace {c}' for c in reversed(cur)]
        lines += [f'namespace {n} {{' for n in new]
        self.current = target
        return '\n'.join(lines) + '\n'

    def begin(self, condition=True):
        if condition:
            self.stack.append(self.current)
        return ''

    def end(self, condition=True):
        if not condition:
            return ''
        return self.ensure(self.stack.pop())

    def end_of_file(self):
        if self.stack:
            raise GeneratorError('namespace stack not empty at end of file')
        return self.ensure('::')


def _use(variant):
    Variant.current = variant
    return ''


def load_templates(directory):
    ns = _Namespaces()
    funcs = {
        'Eq': lambda a, b: a == b,
        'NEq': lambda a, b: a != b,
        'Add': lambda a, b: a + b,
        'Sub': lambda a, b: a - b,
        'Kinds': lambda: Kinds,
        'EnsureNamespace': ns.ensure,
        'EndOfFile': ns.end_of_file,
        'IfdefFuchsia': lambda: ns.begin(),
        'EndifFuchsia': lambda: ns.end(),
        'IfdefFuchsiaIf': lambda c: ns.begin(c),
        'EndifFuchsiaIf': lambda c: ns.end(c),
        'UseUnified': lambda: _use('unified'),
        'UseWire': lambda: _use('wire'),
        'NativeBSD': lambda: True,
    }
    templates = Templates(funcs)
    funcs['Filename'] = lambda name, library: templates.execute(
        'Filename:' + name, FilenameData(library))
    templates.funcs.update(funcs)
    for name in TEMPLATE_FILES:
        templates.parse(name, (Path(directory) / name).read_text())
    return templates


# removeEmptyBlocks (fidlgen_cpp generator.go), with Go's ReplaceAll
# treatment of empty matches: one abutting the previous match is skipped.
_BLANK = re.compile(r'^[\t\n\f\r ]*$[\r\n]*', re.M)
_IFDEFS = [re.compile(p, re.M) for p in (
    r'#endif  // __Fuchsia__[\t\n\f\r ]+#ifdef __Fuchsia__',
    r'#ifdef __Fuchsia__[\t\n\f\r ]+#endif  // __Fuchsia__',
    r'#endif  // __FIDL_SUPPORT_HANDLES[\t\n\f\r ]+#if __FIDL_SUPPORT_HANDLES',
    r'#if __FIDL_SUPPORT_HANDLES[\t\n\f\r ]+#endif  // __FIDL_SUPPORT_HANDLES')]
_EMPTY_NS = re.compile(
    r'namespace ([a-z0-9_]+) \{[\t\n\f\r ]*\}  // namespace ([a-z0-9_]+)',
    re.M)


def _go_replace_all(pattern, text, replacement):
    out, pos, last_end = [], 0, -1
    search = 0
    while search <= len(text):
        m = pattern.search(text, search)
        if m is None:
            break
        if m.start() == m.end() and m.start() == last_end:
            search = m.start() + 1
            continue
        out.append(text[pos:m.start()])
        out.append(replacement)
        pos = m.end()
        last_end = m.end()
        search = m.end() if m.end() > m.start() else m.end() + 1
    out.append(text[pos:])
    return ''.join(out)


def remove_empty_blocks(source):
    while True:
        length = len(source)
        source = _go_replace_all(_BLANK, source, '\n')
        for pattern in _IFDEFS:
            source = pattern.sub('', source)
        source = _EMPTY_NS.sub(
            lambda m: '' if m.group(1) == m.group(2) else m.group(0), source)
        if len(source) == length:
            return source


def generate(ir, template_dir):
    """Return ({relative path: text} for the five native C++ files, names).

    TEMPLATE_DIR is fidlgen_cpp's codegen directory (TEMPLATE_DIR below the
    source root, or the SDK's installed copy).  The names are the C++
    spelling of every declaration and member, for the BSD adapters.
    """
    compiler = Compiler(ir)
    root = compiler.compile()
    templates = load_templates(template_dir)
    out = {}
    for name in FILES:
        path = templates.execute('Filename:' + name,
                                 FilenameData(root.Library))
        try:
            text = templates.execute('File:' + name, root)
        except TemplateError as error:
            raise GeneratorError(f'{path}: {error}') from error
        out[path] = remove_empty_blocks(text)
    return out, compiler.bsd_names()
