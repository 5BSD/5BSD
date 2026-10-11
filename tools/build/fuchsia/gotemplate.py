# SPDX-License-Identifier: BSD-2-Clause
"""A Go text/template interpreter for the upstream fidlgen_cpp templates.

The FIDL natural-type generator executes Fuchsia's own .tmpl files
(contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen) unchanged, so this module
implements the subset of text/template those files use, with Go's
whitespace rules: {{- and -}} trim markers, comments, define/template,
if/else if/else, range (with $i, $v := and else), with, variables,
pipelines, parenthesized commands, field and method chains, and string,
number and boolean literals.  Data objects expose Go field and method names
as Python attributes; a method is called when a chain reaches it.

Values print as Go's fmt.Sprint would for the types the generator uses:
booleans as true/false, integers in decimal and everything else through
str().  Truth follows Go: false, 0, nil and empty strings and lists are
false; any other object is true.
"""
import re

__all__ = ['Templates', 'TemplateError', 'truth', 'printf']


class TemplateError(Exception):
    pass


# ---------------------------------------------------------------- lexing
_SPACE = ' \t\r\n'


def _lex(source, name):
    """Split SOURCE into ('text', s) and ('action', body) items."""
    items = []
    pos = 0
    trim_next = False
    while True:
        start = source.find('{{', pos)
        text = source[pos:] if start < 0 else source[pos:start]
        if trim_next:
            text = text.lstrip(_SPACE)
        if start < 0:
            if text:
                items.append(('text', text))
            return items
        inner = start + 2
        if source[inner:inner + 1] == '-' and \
                source[inner + 1:inner + 2] in tuple(_SPACE):
            text = text.rstrip(_SPACE)
            inner += 2
        if text:
            items.append(('text', text))
        # A comment ends at the first */, then an optional " -", then }}.
        if source.startswith('/*', inner):
            close = source.find('*/', inner)
            if close < 0:
                raise TemplateError(f'{name}: unclosed comment')
            after = close + 2
            rest = source[after:]
            if rest.startswith(' -}}'):
                pos, trim_next = after + 4, True
            elif rest.startswith('}}'):
                pos, trim_next = after + 2, False
            else:
                raise TemplateError(f'{name}: comment ends without }}}}')
            continue
        end = _action_end(source, inner, name)
        body = source[inner:end]
        trim_next = False
        if body.endswith(' -') or (len(body) >= 2 and body[-1] == '-' and
                                   body[-2] in _SPACE):
            body = body[:-1]
            trim_next = True
        items.append(('action', body))
        pos = end + 2


def _action_end(source, pos, name):
    """Index of the }} closing the action starting at POS (skipping quotes)."""
    i = pos
    while i < len(source):
        c = source[i]
        if c == '"':
            i += 1
            while i < len(source) and source[i] != '"':
                i += 2 if source[i] == '\\' else 1
        elif c == '`':
            i = source.index('`', i + 1)
        elif c == "'":
            i += 1
            while source[i] != "'":
                i += 2 if source[i] == '\\' else 1
        elif source.startswith('}}', i):
            return i
        i += 1
    raise TemplateError(f'{name}: unclosed action')


_TOKEN = re.compile(r'''
    (?P<space>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<raw>`[^`]*`)
  | (?P<char>'(?:[^'\\]|\\.)+')
  | (?P<declare>:=)
  | (?P<assign>=)
  | (?P<pipe>\|)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<comma>,)
  | (?P<number>[-+]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|
                       [0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?))
  | (?P<variable>\$[A-Za-z0-9_]*)
  | (?P<field>(?:\.[A-Za-z_][A-Za-z0-9_]*)+|\.)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
''', re.X)
_CHAIN = re.compile(r'(?:\.[A-Za-z_][A-Za-z0-9_]*)+')


def _tokens(body, name):
    out = []
    pos = 0
    while pos < len(body):
        m = _TOKEN.match(body, pos)
        if not m:
            raise TemplateError(f'{name}: bad token in {{{{{body}}}}}')
        kind = m.lastgroup
        value = m.group()
        pos = m.end()
        if kind == 'space':
            continue
        # A field chain may follow a variable, identifier or ')'.
        if kind in ('variable', 'ident', 'rparen'):
            c = _CHAIN.match(body, pos)
            if c:
                out.append((kind, value))
                out.append(('chain', c.group()))
                pos = c.end()
                continue
        out.append((kind, value))
    return out


# ---------------------------------------------------------------- parsing
class _Node:
    pass


class _Text(_Node):
    def __init__(self, text):
        self.text = text


class _Action(_Node):
    def __init__(self, pipe):
        self.pipe = pipe


class _If(_Node):
    def __init__(self, kind, pipe, body, other):
        self.kind, self.pipe, self.body, self.other = kind, pipe, body, other


class _Range(_Node):
    def __init__(self, pipe, body, other):
        self.pipe, self.body, self.other = pipe, body, other


class _Call(_Node):
    def __init__(self, name, pipe):
        self.name, self.pipe = name, pipe


class _Pipe:
    def __init__(self, decl, assign, commands):
        self.decl, self.assign, self.commands = decl, assign, commands


def _string(token):
    kind, value = token
    if kind == 'raw':
        return value[1:-1]
    if kind != 'string':
        raise TemplateError('expected string, found ' + value)
    return bytes(value[1:-1], 'utf-8').decode('unicode_escape')


class _Parser:
    def __init__(self, name, source, templates):
        self.name = name
        self.items = _lex(source, name)
        self.pos = 0
        self.templates = templates

    def parse(self):
        nodes, end = self.list(top=True)
        return nodes

    def list(self, top=False):
        """Parse until {{end}} or {{else ...}}; return (nodes, terminator)."""
        nodes = []
        while self.pos < len(self.items):
            kind, value = self.items[self.pos]
            self.pos += 1
            if kind == 'text':
                nodes.append(_Text(value))
                continue
            toks = _tokens(value, self.name)
            if not toks:
                raise TemplateError(f'{self.name}: empty action')
            head = toks[0]
            if head == ('ident', 'end'):
                return nodes, ('end', None)
            if head == ('ident', 'else'):
                return nodes, ('else', toks[1:])
            if head[0] == 'ident' and head[1] in ('if', 'with', 'range'):
                nodes.append(self.control(head[1], toks[1:]))
            elif head == ('ident', 'define'):
                tname = _string(toks[1])
                body, term = self.list()
                if term[0] != 'end':
                    raise TemplateError(f'{self.name}: define {tname}: else')
                self.templates[tname] = body
            elif head == ('ident', 'template'):
                tname = _string(toks[1])
                pipe = self.pipe(toks[2:]) if len(toks) > 2 else None
                nodes.append(_Call(tname, pipe))
            elif head[0] == 'ident' and head[1] in ('block', 'break',
                                                    'continue'):
                raise TemplateError(f'{self.name}: {head[1]} unsupported')
            else:
                nodes.append(_Action(self.pipe(toks)))
        if not top:
            raise TemplateError(f'{self.name}: missing {{{{end}}}}')
        return nodes, ('eof', None)

    def control(self, kind, toks):
        pipe = self.pipe(toks)
        body, term = self.list()
        other = None
        if term[0] == 'else':
            rest = term[1]
            if rest and rest[0] in (('ident', 'if'), ('ident', 'with')):
                # {{else if ...}}: the chain shares the outer {{end}}.
                other = [self.control(rest[0][1], rest[1:])]
            else:
                other, term = self.list()
                if term[0] != 'end':
                    raise TemplateError(f'{self.name}: else after else')
        if kind == 'range':
            return _Range(pipe, body, other)
        return _If(kind, pipe, body, other)

    def pipe(self, toks):
        decl, assign = [], False
        # $a, $b := ...  or  $a := ...  or  $a = ...
        i = 0
        while (i < len(toks) and toks[i][0] == 'variable' and
               i + 1 < len(toks) and toks[i + 1][0] in
               ('comma', 'declare', 'assign')):
            decl.append(toks[i][1])
            if toks[i + 1][0] == 'comma':
                i += 2
                continue
            assign = toks[i + 1][0] == 'assign'
            i += 2
            break
        else:
            if decl:
                raise TemplateError(f'{self.name}: bad declaration')
        commands, current, depth = [], [], 0
        for tok in toks[i:]:
            if tok[0] == 'lparen':
                depth += 1
            elif tok[0] == 'rparen':
                depth -= 1
            if tok[0] == 'pipe' and depth == 0:
                commands.append(self.command(current))
                current = []
            else:
                current.append(tok)
        commands.append(self.command(current))
        return _Pipe(decl, assign, commands)

    def command(self, toks):
        """A command is a list of operands."""
        operands, i = [], 0
        while i < len(toks):
            tok = toks[i]
            if tok[0] == 'lparen':
                depth, j = 1, i + 1
                while depth:
                    if toks[j][0] == 'lparen':
                        depth += 1
                    elif toks[j][0] == 'rparen':
                        depth -= 1
                    j += 1
                operand = ('pipe', self.pipe(toks[i + 1:j - 1]))
                i = j
            else:
                operand = tok
                i += 1
            if i < len(toks) and toks[i][0] == 'chain':
                operand = ('chained', operand, toks[i][1][1:].split('.'))
                i += 1
            operands.append(operand)
        if not operands:
            raise TemplateError(f'{self.name}: empty command')
        return operands


# ---------------------------------------------------------------- execution
def truth(value):
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (str, list, tuple, dict)):
        return len(value) > 0
    return True


def show(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return '<no value>'
    return str(value)


def printf(fmt, *args):
    """fmt.Sprintf for the verbs the templates use."""
    out, i, n = [], 0, 0
    while i < len(fmt):
        c = fmt[i]
        if c != '%':
            out.append(c)
            i += 1
            continue
        m = re.compile(r'%([#+\- 0]*)(\d*)(?:\.(\d+))?([a-zA-Z%])').match(
            fmt, i)
        if not m:
            raise TemplateError('bad printf format ' + fmt)
        flags, width, _, verb = m.groups()
        i = m.end()
        if verb == '%':
            out.append('%')
            continue
        arg = args[n]
        n += 1
        if verb in 'xXdob':
            if isinstance(arg, bool) or not isinstance(arg, int):
                raise TemplateError(f'%{verb} of non-integer {arg!r}')
            out.append(('%' + flags + width + verb) % arg if verb != 'b'
                       else format(arg, 'b'))
        elif verb == 't':
            out.append(show(bool(arg)))
        elif verb in 'sv':
            out.append(('%' + flags + width + 's') % show(arg))
        elif verb == 'q':
            out.append('"' + show(arg).replace('\\', '\\\\')
                       .replace('"', '\\"') + '"')
        else:
            raise TemplateError('unsupported printf verb %' + verb)
    return ''.join(out)


_BUILTINS = {
    'not': lambda x: not truth(x),
    'len': len,
    'printf': printf,
    'print': lambda *a: ''.join(show(x) for x in a),
    'eq': lambda a, *b: any(a == x for x in b),
    'ne': lambda a, b: a != b,
    'and': lambda *a: next((x for x in a if not truth(x)), a[-1]),
    'or': lambda *a: next((x for x in a if truth(x)), a[-1]),
    'index': lambda x, *k: _index(x, k),
}


def _index(value, keys):
    for k in keys:
        value = value[k]
    return value


_MISSING = object()


def _field(value, name):
    attr = getattr(value, name, _MISSING)
    if attr is _MISSING:
        if isinstance(value, dict) and name in value:
            return value[name]
        raise TemplateError(
            f"can't evaluate field {name} in type {type(value).__name__}")
    return attr


class Templates:
    """A set of named templates parsed from one or more sources."""

    def __init__(self, funcs=None):
        self.templates = {}
        self.funcs = dict(_BUILTINS)
        self.funcs.update(funcs or {})

    def parse(self, name, source):
        _Parser(name, source, self.templates).parse()

    def execute(self, name, data):
        if name not in self.templates:
            raise TemplateError('no template ' + repr(name))
        out = []
        self._run(self.templates[name], data, [('$', data)], out)
        return ''.join(out)

    # Variables are a stack of (name, value); control structures pop what
    # they declared when they end, as Go scopes do.
    def _run(self, nodes, dot, scope, out):
        for node in nodes:
            if isinstance(node, _Text):
                out.append(node.text)
            elif isinstance(node, _Action):
                value = self._pipe(node.pipe, dot, scope)
                if not node.pipe.decl:
                    out.append(show(value))
            elif isinstance(node, _If):
                mark = len(scope)
                value = self._pipe(node.pipe, dot, scope)
                if truth(value):
                    self._run(node.body, value if node.kind == 'with'
                              else dot, scope, out)
                elif node.other is not None:
                    self._run(node.other, dot, scope, out)
                del scope[mark:]
            elif isinstance(node, _Range):
                self._range(node, dot, scope, out)
            elif isinstance(node, _Call):
                arg = self._pipe(node.pipe, dot, scope) if node.pipe else None
                if node.name not in self.templates:
                    raise TemplateError('no template ' + repr(node.name))
                self._run(self.templates[node.name], arg, [('$', arg)], out)

    def _range(self, node, dot, scope, out):
        mark = len(scope)
        decl = node.pipe.decl
        pipe = _Pipe([], False, node.pipe.commands)
        value = self._pipe(pipe, dot, scope)
        if isinstance(value, dict):
            items = sorted(value.items())
        elif value is None:
            items = []
        else:
            items = list(enumerate(value))
        if not items:
            if node.other is not None:
                self._run(node.other, dot, scope, out)
            del scope[mark:]
            return
        for key, element in items:
            if len(decl) == 1:
                scope.append((decl[0], element))
            elif len(decl) == 2:
                scope.append((decl[0], key))
                scope.append((decl[1], element))
            inner = len(scope)
            self._run(node.body, element, scope, out)
            del scope[inner:]
            del scope[mark:]

    def _pipe(self, pipe, dot, scope):
        value = _MISSING
        for command in pipe.commands:
            value = self._command(command, dot, scope, value)
        if pipe.decl:
            if pipe.assign:
                for i in range(len(scope) - 1, -1, -1):
                    if scope[i][0] == pipe.decl[0]:
                        scope[i] = (pipe.decl[0], value)
                        break
                else:
                    raise TemplateError('undefined variable ' + pipe.decl[0])
            else:
                scope.append((pipe.decl[0], value))
        return value

    def _command(self, operands, dot, scope, piped):
        first = operands[0]
        args = [self._operand(o, dot, scope) for o in operands[1:]]
        if piped is not _MISSING:
            args.append(piped)
        if first[0] == 'ident' and first[1] not in ('true', 'false', 'nil'):
            name = first[1]
            if name not in self.funcs:
                raise TemplateError('function %r not defined' % name)
            return self.funcs[name](*args)
        if first[0] == 'chained' and first[1][0] == 'ident' and \
                first[1][1] not in ('true', 'false', 'nil'):
            fn = self.funcs[first[1][1]]
            return self._chain(fn(), first[2], args)
        if first[0] == 'field':
            if first[1] == '.':
                if args:
                    raise TemplateError("can't give argument to non-function")
                return dot
            return self._chain(dot, first[1][1:].split('.'), args)
        if first[0] == 'chained':
            base = self._operand(first[1], dot, scope)
            return self._chain(base, first[2], args)
        if args:
            raise TemplateError("can't give argument to non-function")
        return self._operand(first, dot, scope)

    def _chain(self, value, names, args):
        for i, name in enumerate(names):
            attr = _field(value, name)
            if callable(attr) and not isinstance(attr, type):
                attr = attr(*args) if i == len(names) - 1 else attr()
            elif args and i == len(names) - 1:
                raise TemplateError(f'{name} is not a method but has arguments')
            value = attr
        return value

    def _operand(self, operand, dot, scope):
        kind = operand[0]
        if kind == 'pipe':
            return self._pipe(operand[1], dot, scope)
        if kind == 'chained':
            base = self._operand(operand[1], dot, scope)
            return self._chain(base, operand[2], [])
        value = operand[1]
        if kind == 'field':
            return dot if value == '.' else self._chain(
                dot, value[1:].split('.'), [])
        if kind == 'variable':
            for name, v in reversed(scope):
                if name == value:
                    return v
            raise TemplateError('undefined variable ' + value)
        if kind in ('string', 'raw'):
            return _string(operand)
        if kind == 'number':
            text = value.replace('_', '')
            if re.fullmatch(r'[-+]?0[xX][0-9a-fA-F]+', text):
                return int(text, 16)
            if re.fullmatch(r'[-+]?0[bB][01]+', text):
                return int(text, 2)
            if re.fullmatch(r'[-+]?0[oO][0-7]+', text):
                return int(text, 8)
            if re.fullmatch(r'[-+]?[0-9]+', text):
                return int(text)
            return float(text)
        if kind == 'ident':
            if value == 'true':
                return True
            if value == 'false':
                return False
            if value == 'nil':
                return None
            fn = self.funcs.get(value)
            if fn is None:
                raise TemplateError('function %r not defined' % value)
            return fn()
        raise TemplateError('unexpected operand ' + repr(operand))
