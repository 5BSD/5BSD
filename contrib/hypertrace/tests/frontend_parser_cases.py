# SPDX-License-Identifier: BSD-2-Clause
"""Rule-derived cases for frontend-parser-corpus.py.

Each entry: id, src, expect ('ok', 'D_TAG' or ('D_TAG', 'message fragment')),
optional flags/opts/args/mode/oflags/keep and a structural check(result, K)
where K holds the DIF constants parsed from sys/dtrace.h.  The comment on
each group names the rule the cases were written from.
"""
import re
import frontend_parser as fp

B = 'BEGIN '
XL = ('struct xin { int a; }; struct xout { int b; }; '
      'translator struct xout < struct xin *p > { b = p->a; }; ')
ET = fp.ETAGS
CASES = []


def ok(cid, src, **kw):
    CASES.append(dict(id=cid, src=src, expect='ok', **kw))


def bad(cid, src, tag, sub=None, **kw):
    CASES.append(dict(id=cid, src=src, expect=(tag, sub) if sub else tag, **kw))


def out_has(*frags):
    return lambda r, K: all(f in r['output'] for f in frags)


def nacts(n):
    return lambda r, K: sum(len(s['acts']) for s in r['stmts']) == n


def ops(r, K):
    """Opcodes of every action DIFO, in order."""
    return [[i >> 24 for i in a['difo']['insns']] for s in r['stmts'] for a in s['acts'] if a['difo']]


def const_action(value, size=None):
    """The last action is a folded constant: setx <value>; ret."""
    def check(r, K):
        a = r['stmts'][-1]['acts'][-1]['difo']
        ins = [i for i in a['insns'] if i >> 24 != K['DIF_OP_TYPECAST']]
        if [i >> 24 for i in ins] != [K['DIF_OP_SETX'], K['DIF_OP_RET']]:
            return False
        v = int(a['ints'][ins[0] >> 8 & 0xffff])
        bits = 8 * a['rsize']
        return (v & ((1 << bits) - 1)) == (value & ((1 << bits) - 1)) and (size is None or a['rsize'] == size)
    return check


# --- Lexer: reserved words (D guide "Identifiers and Keywords") cannot be used
# as identifiers; a longer identifier that merely starts with one is fine.
RESERVED = ['auto', 'break', 'case', 'char', 'const', 'continue', 'counter', 'default', 'do',
            'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'import', 'inline',
            'int', 'long', 'offsetof', 'probe', 'provider', 'register', 'restrict', 'return',
            'self', 'short', 'signed', 'sizeof', 'static', 'string', 'stringof', 'struct',
            'switch', 'this', 'translator', 'typedef', 'union', 'unsigned', 'userland', 'void',
            'volatile', 'while', 'xlate']
for w in RESERVED:
    bad(f'kw-outer-{w}', f'int a97, {w}; ' + B + '{ trace(1); }', 'D_SYNTAX')
    ok(f'kw-prefix-{w}', f'int {w}_x; ' + B + f'{{ trace({w}_x); }}')
# Inside a clause (lexer state S0) the same words are keywords too.
for w in ['auto', 'break', 'case', 'continue', 'counter', 'default', 'do', 'double', 'enum',
          'extern', 'float', 'for', 'goto', 'import', 'inline', 'long', 'probe', 'provider',
          'register', 'restrict', 'return', 'short', 'signed', 'static', 'switch', 'translator',
          'typedef', 'union', 'unsigned', 'volatile', 'while', 'char', 'const', 'void', 'struct',
          'int', 'string']:
    bad(f'kw-clause-{w}', B + f'{{ {w} = 1; }}', 'D_SYNTAX')

# --- Lexer: integer constants (C99 6.4.4.1 typing, D_INT_* diagnostics).
ok('int-suffix-u', B + '{ trace(1u); }', check=const_action(1, 4))
ok('int-suffix-U', B + '{ trace(1U); }', check=const_action(1, 4))
ok('int-suffix-ul', B + '{ trace(1ul); }', check=const_action(1, 8))
ok('int-suffix-ULL', B + '{ trace(1ULL); }', check=const_action(1, 8))
ok('int-hex-U-unsigned', B + '{ trace(0xffffffffU > 0); }', check=const_action(1))
ok('int-dec-ll-max', B + '{ trace(9223372036854775807); }', check=const_action(0x7fffffffffffffff, 8))
bad('int-dec-too-big', B + '{ trace(18446744073709551615); }', 'D_INT_OFLOW', 'cannot be represented')
ok('int-dec-u-max', B + '{ trace(18446744073709551615u); }', check=const_action(0xffffffffffffffff, 8))
bad('int-strtoull-range', B + '{ trace(99999999999999999999); }', 'D_INT_OFLOW', 'results in integer overflow')
bad('int-octal-digit', B + '{ trace(0129); }', 'D_INT_DIGIT')
bad('float-constant', B + '{ trace(1.5); }', 'D_SYNTAX', 'floating-point constants are not permitted')
bad('float-exponent', B + '{ trace(1e10); }', 'D_SYNTAX', 'floating-point')
ok('char-escape-x', B + "{ trace('\\x41'); }", check=const_action(0x41, 4))
ok('char-escape-oct', B + "{ trace('\\101'); }", check=const_action(0x41, 4))
ok('char-multi', B + "{ trace('ab'); }", check=const_action(0x6162, 4))
ok('char-eight', B + "{ trace('abcdefgh'); }", check=const_action(0x6162636465666768, 8))
bad('char-newline', B + "{ trace('a\n'); }", 'D_CHR_NL')
bad('string-newline-s0', B + '{ trace("a\n"); }', 'D_STR_NL')

# --- Lexer: comments, #! lines, stray brackets and characters.
ok('comment-block', '/* lead */ ' + B + '{ /* inner */ trace(1); }')
bad('comment-nested', B + '{ /* a /* b */ trace(1); }', 'D_SYNTAX', '/* encountered inside a comment')
ok('interp-line', '#!/usr/sbin/dtrace -s\n' + B + '{ trace(1); }')
ok('interp-line-indented', '  #!/usr/sbin/dtrace -s\n' + B + '{ trace(1); }')
bad('extra-rparen', B + '{ trace(1)); }', 'D_SYNTAX', 'extra ) in input stream')
bad('extra-rbrack', B + '{ trace(1]); }', 'D_SYNTAX', 'extra ] in input stream')
bad('extra-rbrace', 'int } ' + B + '{ trace(1); }', 'D_SYNTAX', 'extra } in input stream')
bad('extra-rbrace-outer', B + '{ trace(1); }}', 'D_SYNTAX', 'syntax error near "}"')
bad('pred-unclosed-paren', B + '/(1/ { trace(1); }', 'D_SYNTAX', 'closing ) expected in predicate before /')
bad('pred-unclosed-brack', B + '/a[1/ { trace(1); }', 'D_SYNTAX', 'closing ] expected in predicate before /')
bad('stray-char-clause', B + '{ trace(1) # 2; }', 'D_SYNTAX', 'syntax error near "#"')
bad('stray-char-outer', 'int x; ` ' + B + '{ trace(1); }', 'D_SYNTAX')
bad('stray-char-backslash', B + '{ trace(1 \\ 2); }', 'D_SYNTAX', 'syntax error near')

# --- Lexer: macro arguments ($n, $$n, $target, $pid) and macro variables.
ok('macro-int', B + '{ trace($1); }', args=['p', '42'], check=const_action(42))
ok('macro-neg', B + '{ trace($1); }', args=['p', '-5'], check=const_action(-5))
ok('macro-pos', B + '{ trace($1); }', args=['p', '+5'], check=const_action(5))
ok('macro-hex-suffix', B + '{ trace($1 > 0); }', args=['p', '0xffffffffU'], check=const_action(1))
bad('macro-oflow', B + '{ trace($1); }', 'D_MACRO_OFLOW', args=['p', '99999999999999999999'])
ok('macro-string', B + '{ trace($$1); }', args=['p', 'hello'],
   check=lambda r, K: 'hello' in r['stmts'][0]['acts'][0]['difo']['strtab'])
ok('macro-quoted-string', B + '{ trace($1); }', args=['p', '"quoted"'],
   check=lambda r, K: 'quoted' in r['stmts'][0]['acts'][0]['difo']['strtab'])
ok('macro-ident', 'int foo; ' + B + '{ trace($1); }', args=['p', 'foo'])
bad('macro-dollar-undef', B + '{ trace($$3); }', ('D_MACRO_UNDEF'), args=['p'])
ok('macro-dollar-defarg', B + '{ trace($$3); }', args=['p'], flags=ET | fp.DEFARG,
   check=lambda r, K: r['stmts'][0]['acts'][0]['difo']['rkind'] == K['DIF_TYPE_STRING'])
ok('macro-defarg-int', B + '{ trace($4); }', args=['p'], flags=ET | fp.DEFARG, check=const_action(0))
ok('macro-escape', B + '{ trace($$1); }', args=['p', 'a\\tb'],
   check=lambda r, K: 'a\tb' in r['stmts'][0]['acts'][0]['difo']['strtab'])
ok('macro-var-pid', B + '{ trace($pid); }')
ok('macro-var-dollar-pid', B + '{ trace($$pid); }')
bad('macro-var-undef', B + '{ trace($nosuchmacro97); }', 'D_MACRO_UNDEF', 'macro variable')
bad('macro-var-dollar-undef', B + '{ trace($$nosuchmacro97); }', 'D_MACRO_UNDEF', 'macro variable')
bad('macro-unused', B + '{ trace(1); }', 'D_MACRO_UNUSED', args=['p', 'x'])
ok('macro-in-pdesc', 'dtrace:::$1 { trace(1); }', args=['p', 'BEGIN'],
   check=lambda r, K: r['stmts'][0]['probe'][3] == 'BEGIN')

# --- Aggregations: '@' alone names the default aggregation @_.
ok('agg-anon', B + '{ @ = count(); }')
ok('agg-anon-key', B + '{ @[1] = count(); }')

# --- Grammar productions.
ok('probe-list', 'BEGIN, END { trace(1); }', check=lambda r, K: len(r['stmts']) == 2)
ok('pdesc-no-pred-no-act', 'BEGIN {}')
ok('pdesc-pred-empty-acts', 'BEGIN /1/ {}')
bad('pdesc-no-body', 'BEGIN', 'D_SYNTAX', 'expected predicate and/or actions', mode='file')
ok('pdesc-no-body-string', 'BEGIN', check=nacts(0))
bad('pdesc-pred-no-body', 'BEGIN /1/', 'D_SYNTAX', 'expected actions { } following')
ok('empty-statement', B + '{ ; ; trace(1); ; }')
ok('stmt-no-semicolon', B + '{ trace(1) }')
# Member names after . and -> may be D keywords (dtrace_keyword_ident); D
# declarations cannot create such members, so the member lookup must fail
# with D_TYPE_MEMBER naming the keyword (the grammar accepted it).
for w in ['probe', 'provider', 'self', 'string', 'stringof', 'userland', 'xlate', 'translator']:
    bad(f'dot-keyword-{w}', 'struct k { int a; }; struct k g; ' + B + f'{{ trace(g.{w}); }}',
        'D_TYPE_MEMBER', w)
    bad(f'arrow-keyword-{w}', 'struct k { int a; }; struct k *gp; ' + B + f'{{ trace(gp->{w}); }}',
        'D_TYPE_MEMBER', w)
    bad(f'offsetof-keyword-{w}', 'struct k { int a; }; ' + B + f'{{ trace(offsetof(struct k, {w})); }}',
        'D_UNKNOWN', f'failed to determine offset of {w}')
ok('dot-tname-member', 'typedef int tt; struct m { int tt; }; struct m g; ' + B + '{ trace(g.tt); }')
ok('arrow-tname-member', 'typedef int tt; struct m { int tt; }; struct m *gp; ' + B + '{ trace(gp->tt); }')
ok('offsetof-tname', 'typedef int tt; struct k { int a; int tt; }; ' + B +
   '{ trace(offsetof(struct k, tt)); }', check=const_action(4))
ok('unary-plus', B + '{ x = 1; trace(+x); }')
ok('comma-expr', B + '{ x = 1; y = 2; trace((x, y)); }')
ok('auto-class-rejected-later', B + '{ trace(1); }')
bad('decl-auto', 'auto int x; ' + B + '{ trace(1); }', 'D_DECL_BADCLASS')
bad('decl-static', 'static int x; ' + B + '{ trace(1); }', 'D_DECL_BADCLASS')
ok('decl-self', 'self int sx; ' + B + '{ self->sx = 1; }')
ok('decl-this', 'this int tx; ' + B + '{ this->tx = 1; }')
ok('decl-extern', 'extern int ext97; ' + B + '{ trace(1); }')
ok('decl-double', 'double d; ' + B + '{ trace(1); }')
ok('decl-float-type', 'typedef float ft; ' + B + '{ trace(sizeof (ft)); }', check=const_action(4))
ok('decl-double-type', 'typedef double dt97; ' + B + '{ trace(sizeof (dt97)); }', check=const_action(8))
ok('decl-userland', B + '{ this->p = (userland int *)arg0; }')
ok('decl-restrict', 'int * restrict rp; ' + B + '{ trace(1); }')
ok('decl-volatile', 'volatile int vx; ' + B + '{ trace(vx); }')
ok('decl-const-ptr', 'int * const cp; ' + B + '{ trace(1); }')
ok('decl-ptr-volatile', 'int * volatile pv; ' + B + '{ trace(1); }')
ok('decl-ptr-restrict', 'int * restrict * rpp; ' + B + '{ trace(1); }')
ok('decl-tag-only-struct', 'struct tagonly97 { int a; }; ' + B + '{ trace(sizeof (struct tagonly97)); }',
   check=const_action(4))
ok('decl-struct-tname-tag', 'typedef int tn97; struct tn97 { int a; int b; }; ' + B +
   '{ trace(sizeof (struct tn97)); }', check=const_action(8))
ok('decl-enum-tname-tag', 'typedef int te97; enum te97 { TE97A }; ' + B + '{ trace(TE97A); }',
   check=const_action(0))
ok('decl-enum-anon', 'enum { ANON97A = 3, ANON97B }; ' + B + '{ trace(ANON97B); }', check=const_action(4))
ok('decl-enum-ref', 'enum er97 { ER97A = 5 }; enum er97 e97; ' + B + '{ trace(sizeof (enum er97)); }',
   check=const_action(4))
ok('decl-enum-tname-ref', 'typedef int te98; enum te98 { TE98A }; enum te98 v98; ' + B + '{ trace(1); }')
ok('decl-paren-declarator', 'int (px97); ' + B + '{ trace(px97); }')
ok('decl-func-ptr', 'int (*fp97)(int); ' + B + '{ trace(1); }')
ok('decl-func-varargs', 'int fv97(int, ...); ' + B + '{ trace(1); }')
ok('decl-func-noargs', 'int fn97(); ' + B + '{ trace(1); }')
ok('decl-abstract-array', B + '{ trace(sizeof (int [3])); }', check=const_action(12))
ok('decl-abstract-func-ptr', B + '{ trace(sizeof (int (*)(int))); }', check=const_action(8))
ok('decl-abstract-func', B + '{ trace(sizeof (int (*)())); }', check=const_action(8))
ok('decl-ptr-const', B + '{ trace(sizeof (int * const)); }', check=const_action(8))
ok('decl-multi-declarator', 'int ma97, mb97; ' + B + '{ trace(ma97 + mb97); }')
ok('decl-struct-multi-members', 'struct mm97 { int a, b; char c[4]; }; ' + B +
   '{ trace(sizeof (struct mm97)); }', check=const_action(12))
ok('decl-struct-anon-member-bf', 'struct ab97 { int a : 3; int : 5; int b : 4; int : 0; }; ' + B +
   '{ trace(sizeof (struct ab97)); }')
ok('decl-union', 'union u97 { int a; char b[8]; }; ' + B + '{ trace(sizeof (union u97)); }',
   check=const_action(8))

# --- Probe descriptions.
ok('pdesc-full', 'dtrace:::BEGIN { trace(1); }')
ok('pdesc-target', 'nosuchvm97:dtrace:::BEGIN { trace(1); }')
bad('pdesc-id-numeric', '1234 { trace(1); }', 'D_PDESC_INVAL')

# --- Constant folding of unary operators (C semantics, K&R A7.4).
ok('fold-bneg', B + '{ trace(~0); }', check=const_action(-1, 4))
ok('fold-bneg-unsigned', B + '{ trace(~0u); }', check=const_action(0xffffffff, 4))
ok('fold-lneg', B + '{ trace(!5); }', check=const_action(0, 4))
ok('fold-lneg-zero', B + '{ trace(!0); }', check=const_action(1, 4))
ok('fold-lneg-type', B + '{ trace(sizeof (!5l)); }', check=const_action(4))
ok('fold-ineg-unsigned', B + '{ trace(-1u); }', check=const_action(0xffffffff, 4))
ok('fold-cast-narrow-signed', B + '{ trace((char)200 < 0); }', check=const_action(1))
ok('fold-cast-widen-signed', B + '{ trace((int)(char)-56 < 0); }', check=const_action(1))
ok('fold-rsh-signed', B + '{ trace(-8l >> 1); }', check=const_action(-4, 8))
ok('fold-cond-promote', B + '{ trace(sizeof (1 ? 1 : 2l)); }', check=const_action(8))
ok('fold-cond-false', B + '{ trace(0 ? 1 : 2); }', check=const_action(2))

# --- Unary operator type rules (K&R A7.4; dt_cook_op1).
ok('postinc-new-var', B + '{ cnt97++; trace(cnt97); }',
   check=lambda r, K: any(v['name'] == 'cnt97' and v['tsize'] == 8
                          for s in r['stmts'] for a in s['acts'] for v in a['difo']['vars']))
ok('predec-new-var', B + '{ --cnt98; }')
bad('ipos-string', B + '{ trace(+"a"); }', 'D_OP_ARITH', 'operator +')
bad('ineg-string', B + '{ trace(-"a"); }', 'D_OP_ARITH', 'operator -')
bad('bneg-string', B + '{ trace(~"a"); }', 'D_OP_INT', 'operator ~')
bad('lneg-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(!g); }', 'D_OP_SCALAR', 'operator !')
bad('addrof-agg', B + '{ @a = count(); } END { trace(&@a); }', 'D_ADDROF_VAR')
bad('addrof-dyn-array', B + '{ a[1] = 2; trace(&a); }', 'D_IDENT_BADREF', 'may not be referenced as scalar')
bad('addrof-xlate', XL + B + '{ trace(&xlate<struct xout>((struct xin *)arg0)); }', 'D_ADDROF_VAR', 'dynamic object')
bad('addrof-rvalue', B + '{ trace(&(1 + timestamp)); }', 'D_ADDROF_LVAL')
ok('addrof-member', 'struct s { int a; int b; }; struct s g; ' + B + '{ trace((uintptr_t)&g.b); }')
ok('addrof-deref', B + '{ this->p = (int *)arg0; trace((uintptr_t)&*this->p); }')
bad('sizeof-forward', 'struct fw97; ' + B + '{ trace(sizeof (struct fw97)); }', 'D_SIZEOF_TYPE')
bad('sizeof-forward-expr', 'struct fw98; ' + B + '{ trace(sizeof (*(struct fw98 *)0)); }', 'D_SIZEOF_TYPE')
ok('sizeof-string-const', B + '{ trace(sizeof ("abc")); }', check=const_action(4))
ok('sizeof-expr-var', B + '{ x97 = 1; trace(sizeof (x97)); }', check=const_action(4))
ok('stringof-int', B + '{ trace(stringof(1)); }',
   check=lambda r, K: r['stmts'][0]['acts'][0]['difo']['rkind'] == K['DIF_TYPE_STRING'])
ok('stringof-ptr', B + '{ trace(stringof((char *)arg0)); }')
ok('stringof-string', B + '{ trace(stringof("x")); }')
bad('preinc-struct', 'struct s { int a; }; struct s g; ' + B + '{ ++g; }', 'D_OP_SCALAR', 'operator ++')
bad('postdec-struct', 'struct s { int a; }; struct s g; ' + B + '{ g--; }', 'D_OP_SCALAR', 'operator --')
bad('preinc-voidptr', B + '{ this->v = (void *)0; ++this->v; }', 'D_OP_VFPTR', 'operator ++')
bad('postinc-rvalue', B + '{ (timestamp + 1)++; }', 'D_OP_LVAL', 'operator ++')
bad('predec-builtin', B + '{ --timestamp; }', 'D_OP_WRITE', 'operator --')
ok('inc-member-ptr', 'struct s { int a; }; ' + B + '{ this->p = (struct s *)arg0; this->p->a++; }')
bad('deref-func-ptr', 'int (*fp99)(int); ' + B + '{ trace(*fp99); }', 'D_DEREF_FUNC')
ok('deref-array', 'int arr97[4]; ' + B + '{ trace(*arr97); }')
ok('deref-string-member', 'struct s { char name[8]; }; ' + B +
   '{ this->p = (struct s *)arg0; trace(stringof(this->p->name)); }')

# --- Binary operators (K&R A7.6-A7.18; dt_cook_op2).
bad('band-string', B + '{ trace("a" & 1); }', 'D_OP_INT', 'operator &')
bad('bor-string', B + '{ trace(1 | "a"); }', 'D_OP_INT', 'operator |')
bad('xor-string', B + '{ trace("a" ^ 1); }', 'D_OP_INT', 'operator ^')
bad('lsh-string', B + '{ trace("a" << 1); }', 'D_OP_INT', 'operator <<')
bad('rsh-string', B + '{ trace(1 >> "a"); }', 'D_OP_INT', 'operator >>')
bad('mod-string', B + '{ trace(1 % "a"); }', 'D_OP_INT', 'operator %')
bad('div-string', B + '{ trace(1 / "a"); }', 'D_OP_ARITH', 'operator /')
bad('mul-string', B + '{ trace("a" * 2); }', 'D_OP_ARITH', 'operator *')
bad('land-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(g && 1); }', 'D_OP_SCALAR', 'operator &&')
bad('lor-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(1 || g); }', 'D_OP_SCALAR', 'operator ||')
bad('lxor-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(g ^^ 1); }', 'D_OP_SCALAR', 'operator ^^')
ok('lxor-runtime', B + '{ trace(timestamp ^^ 0); }')
for op in ['<', '<=', '>', '>=', '==', '!=']:
    bad(f'cmp-incompat-{op}', 'struct s { int a; }; struct s g; ' + B + f'{{ trace(g {op} 1); }}',
        'D_OP_INCOMPAT', f'"struct s" {op} "int"')
ok('cmp-strings', B + '{ trace(execname == "init"); }')
ok('cmp-string-charptr', B + '{ trace((char *)arg0 == execname); }')
ok('cmp-ptr-zero', B + '{ trace((int *)arg0 == 0); }')
ok('cmp-ptr-voidptr', B + '{ trace((int *)arg0 != (void *)arg1); }')
bad('cmp-ptr-incompat', B + '{ trace((int *)arg0 == (char *)arg1); }', 'D_OP_INCOMPAT')
bad('cmp-ptr-int-nonzero', B + '{ trace((int *)arg0 == 1); }', 'D_OP_INCOMPAT')
ok('cmp-userland-same', B + '{ trace((userland int *)arg0 == (int *)arg1); }')
bad('cmp-userland-mixed', B + '{ trace((userland int *)arg0 == (void *)arg1); }', 'D_OP_INCOMPAT')
ok('cmp-enum-tag', 'enum ce97 { CE97A, CE97B }; enum ce97 ev97; ' + B + '{ trace(ev97 == CE97B); }')
ok('cmp-enum-tag-local', 'enum ce98 { LOCAL98 = 4 }; enum ce98 ev98; ' + B + '{ trace(ev98 != LOCAL98); }')
ok('cmp-enum-array', 'enum ce99 { CE99A = 7 }; enum ce99 ea99[2]; ' + B + '{ trace(ea99[0] == CE99A); }')
ok('ptr-plus-int', B + '{ trace((int *)arg0 + 1); }')
ok('int-plus-ptr', B + '{ trace(1 + (int *)arg0); }')
ok('ptr-minus-ptr', B + '{ trace((int *)arg0 - (int *)arg1); }')
ok('string-plus-int', B + '{ trace(execname + 1); }')
bad('ptr-plus-ptr', B + '{ trace((int *)arg0 + (int *)arg1); }', 'D_OP_INCOMPAT', '+')
bad('int-minus-ptr', B + '{ trace(1 - (int *)arg0); }', 'D_OP_INCOMPAT')
bad('voidptr-plus-int', B + '{ trace((void *)arg0 + 1); }', 'D_OP_INCOMPAT')
for op in ['|=', '^=', '&=', '<<=', '>>=', '%=']:
    ok(f'asgn-int-{op}', B + f'{{ v97 = 7; v97 {op} 2; }}')
    bad(f'asgn-new-{op}', B + f'{{ n97 {op} 2; }}', 'D_VAR_UNDEF', 'n97')
    bad(f'asgn-string-{op}', B + f'{{ s97 = "a"; s97 {op} 2; }}', 'D_OP_INT', f'operator {op}')
for op in ['*=', '/=']:
    ok(f'asgn-int-{op}', B + f'{{ v98 = 7; v98 {op} 2; }}')
    bad(f'asgn-new-{op}', B + f'{{ n98 {op} 2; }}', 'D_VAR_UNDEF', 'n98')
    bad(f'asgn-string-{op}', B + f'{{ s98 = "a"; s98 {op} 2; }}', 'D_OP_ARITH', f'operator {op}')
for op in ['+=', '-=']:
    ok(f'asgn-int-{op}', B + f'{{ v99 = 7; v99 {op} 2; }}')
    bad(f'asgn-new-{op}', B + f'{{ n99 {op} 2; }}', 'D_VAR_UNDEF', 'n99')
    ok(f'asgn-ptr-{op}', B + f'{{ this->p = (int *)arg0; this->p {op} 2; }}')
    bad(f'asgn-string-{op}', B + f'{{ s99 = "a"; s99 {op} 2; }}', 'D_OP_INCOMPAT', op)
    bad(f'asgn-struct-{op}', 'struct s { int a; }; struct s g; ' + B + f'{{ g {op} 1; }}', 'D_OP_VFPTR')
    bad(f'asgn-voidptr-{op}', B + f'{{ this->v = (void *)arg0; this->v {op} 1; }}', 'D_OP_VFPTR')
    bad(f'asgn-ptr-ptr-{op}', B + f'{{ this->p = (int *)arg0; this->p {op} (char *)arg1; }}', 'D_OP_INCOMPAT')
bad('asgn-array', 'int arr98[2]; int arr99[2]; ' + B + '{ arr98 = arr99; }', 'D_OP_ARRFUN')
bad('asgn-incompat', 'struct s { int a; }; struct s g; ' + B + '{ x = 1; x = g; }', 'D_OP_INCOMPAT', '=')
bad('asgn-agg-twice', B + '{ (@a = count()) = count(); }', 'D_OP_LVAL', 'operator =')
ok('asgn-self-new', B + '{ self->t97 = timestamp; }')
ok('asgn-this-new', B + '{ this->t97 = timestamp; trace(this->t97); }')
ok('self-array-morph', B + '{ self->ta97[1] = 2; trace(self->ta97[1]); }')
bad('this-array-morph', B + '{ this->ta98[1] = 2; }', 'D_ARR_LOCAL')
bad('scalar-as-array', B + '{ sc97 = 1; trace(sc97[1]); }', 'D_DEREF_NONPTR')
bad('decl-scalar-as-array', 'int gs97; ' + B + '{ trace(gs97[1]); }', 'D_DEREF_NONPTR')
ok('ptr-index', B + '{ this->p = (int *)arg0; trace(this->p[2]); }')
bad('self-scalar-index', B + '{ self->sx = 1; trace(self->sx[1]); }', 'D_DEREF_NONPTR')
bad('builtin-as-array', B + '{ trace(timestamp[1]); }', 'D_DEREF_NONPTR')
bad('agg-mdim', B + '{ @a[1][2] = count(); }', 'D_AGG_MDIM')
bad('dot-nonident', 'struct s { int a; }; struct s g; ' + B + '{ trace(g.(1)); }', 'D_SYNTAX')
bad('arrow-non-ptr', 'struct s { int a; }; struct s g; ' + B + '{ trace(g->a); }', 'D_OP_PTR', 'must be applied to a pointer')
bad('arrow-ptr-int', B + '{ trace(((int *)arg0)->a); }', 'D_OP_SOU', 'pointer to type "int"')
bad('dot-int', B + '{ x = 1; trace(x.a); }', 'D_OP_SOU', 'cannot be applied to type "int"')
bad('arrow-forward', 'struct fw99; ' + B + '{ trace(((struct fw99 *)arg0)->a); }', 'D_OP_INCOMPLETE', 'fw99')
ok('arrow-forward-resolved', 'struct fr97; struct fr97 *fp97; struct fr97 { int a; }; ' + B +
   '{ trace(fp97->a); }')
ok('dot-lvalue-assign', 'struct s { int a; }; ' + B +
   '{ this->p = (struct s *)arg0; (*this->p).a = 1; }')
ok('userland-member', 'struct s { int *p; }; ' + B + '{ this->u = (userland struct s *)arg0; trace(this->u->p); }')
ok('cast-to-void', B + '{ (void)timestamp; }')
ok('cast-ptr-ptr', B + '{ trace((char *)(int *)arg0); }')
ok('cast-scalar-to-string', B + '{ trace((string)arg0); }')
bad('cast-struct-int', 'struct s { int a; }; struct s g; ' + B + '{ trace((int)g); }', 'D_CAST_INVAL')
bad('cast-int-struct', 'struct s { int a; }; ' + B + '{ trace((struct s)1); }', 'D_CAST_INVAL')
ok('cast-same-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(((struct s)g).a); }')
bad('comma-dynamic', XL + B + '{ trace((xlate<struct xout>((struct xin *)arg0), 1)); }', 'D_OP_DYN', 'operator ,')
bad('comma-action', B + '{ trace((trace(1), 1)); }', 'D_OP_ACT', 'operator ,')
bad('comma-action-right', B + '{ x = (1, trace(1)); }', 'D_OP_ACT')

# --- Conditional operator (K&R A7.16; dt_cook_op3).
bad('cond-struct', 'struct s { int a; }; struct s g; ' + B + '{ trace(g ? 1 : 2); }', 'D_OP_SCALAR', 'operator ?:')
bad('cond-dynamic', XL + B + '{ trace(timestamp ? xlate<struct xout>((struct xin *)arg0) : 2); }', 'D_OP_DYN', 'operator ?:')
ok('cond-ints', B + '{ trace(timestamp ? 1 : 2l); }')
ok('cond-strings', B + '{ trace(timestamp ? "a" : execname); }',
   check=lambda r, K: r['stmts'][0]['acts'][0]['difo']['rkind'] == K['DIF_TYPE_STRING'])
ok('cond-ptr-compat', B + '{ trace(timestamp ? (int *)arg0 : (int *)0); }')
bad('cond-incompat', 'struct s { int a; }; struct s g; ' + B + '{ trace(timestamp ? g : 1); }', 'D_OP_INCOMPAT')
bad('cond-action', B + '{ timestamp ? trace(1) : trace(2); }', 'D_OP_ACT', 'conditional context')
ok('cond-same-struct', 'struct s { int a; }; struct s g; struct s h; ' + B + '{ trace((timestamp ? g : h).a); }')

# --- Identifier resolution (dt_xcook_ident).
bad('ident-agg-as-scalar', B + '{ @a = count(); } END { trace(a); }', 'D_IDENT_UNDEF')
bad('ident-func-as-var', B + '{ trace(strlen); }', 'D_IDENT_BADREF', 'may not be referenced as')
bad('ident-scope-undef', B + '{ trace(nosuchmod97`nosuchsym97); }', 'D_IDENT_UNDEF', 'nosuchmod97`nosuchsym97')
bad('ident-uscope-undef', B + '{ trace(``nosuchsym97); }', 'D_IDENT_UNDEF', '``')
bad('ident-kscope-undef', B + '{ trace(`nosuchsym98); }', 'D_IDENT_UNDEF', '`nosuchsym98')
bad('ident-sym-user-ref', B + '{ trace(``ticks); }', 'D_IDENT_UNDEF')
bad('ident-sym-notypes', B + '{ trace(`ticks); }', 'D_SYM_NOTYPES', 'kernel`ticks')
ok('ident-addr-notypes', B + '{ trace((uintptr_t)&`ticks); }')
bad('ident-sym-notypes-mod', B + '{ trace(kernel`ticks); }', 'D_SYM_NOTYPES')

# --- Declaration specifiers and declarators (dt_decl.c; K&R A8).
bad('decl-void-attr', 'unsigned void x; ' + B + '{ trace(1); }', 'D_DECL_VOIDATTR')
bad('decl-void-long', 'long void x; ' + B + '{ trace(1); }', 'D_DECL_VOIDATTR')
bad('decl-char-long', 'long char x; ' + B + '{ trace(1); }', 'D_DECL_CHARATTR')
bad('decl-signed-struct', 'struct s { int a; }; signed struct s x; ' + B + '{ trace(1); }', 'D_DECL_SIGNINT')
ok('decl-long-double', 'long double ld97; ' + B + '{ trace(sizeof (ld97)); }', check=const_action(16))
ok('decl-long-long-int', 'long long int lli97; ' + B + '{ trace(sizeof (lli97)); }', check=const_action(8))
ok('decl-short-int', 'short int si97; ' + B + '{ trace(sizeof (si97)); }', check=const_action(2))
ok('decl-unsigned-alone', 'unsigned u97; ' + B + '{ trace(sizeof (u97)); }', check=const_action(4))
ok('decl-signed-char', 'signed char sc97; ' + B + '{ trace(sizeof (sc97)); }', check=const_action(1))
ok('decl-const-only', 'const cx97; ' + B + '{ trace(sizeof (cx97)); }', check=const_action(4))
bad('decl-old-style', 'int a97 b97; ' + B + '{ trace(1); }', 'D_SYNTAX')
bad('decl-typedef-redecl-tname', 'typedef int td97; typedef int td97; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
ok('decl-var-named-like-type', 'typedef int td99; int td99x; ' + B + '{ trace(td99x); }')
ok('decl-tname-as-var', 'typedef int tdv97; tdv97 tdv97v; ' + B + '{ trace(tdv97v); }')
bad('decl-typedef-of-global', 'int gv97; typedef int gv97; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'global variable')
bad('decl-typedef-builtin', 'typedef int timestamp; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
bad('decl-redecl-builtin', 'int timestamp; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'built-in identifier')
bad('decl-var-named-typedef', 'int uint64_t; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
bad('decl-redecl-type', 'int rd97; char rd97; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'current: scalar char')
ok('decl-redecl-same', 'int rd98; int rd98; ' + B + '{ trace(rd98); }')
bad('decl-assoc-redecl-key', 'int ar97[int]; int ar97[char]; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'key #1')
bad('decl-assoc-redecl-len', 'int ar98[int]; int ar98[int, int]; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'tuple length')
ok('decl-assoc-redecl-same', 'int ar99[int, string]; int ar99[int, string]; ' + B + '{ ar99[1, "a"] = 1; }')
bad('decl-assoc-vs-scalar', 'int as97; int as97[int]; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
ok('decl-self-assoc', 'self int sa97[int]; ' + B + '{ self->sa97[1] = 2; }')
bad('decl-array-of-assoc', 'int aa97[2][int]; ' + B + '{ trace(1); }', 'D_DECL_DYNOBJ', 'array of associative arrays')
ok('decl-assoc-of-array', 'int aa98[int][2]; ' + B + '{ trace(1); }')
bad('decl-array-of-void', 'void av97[2]; ' + B + '{ trace(1); }', 'D_DECL_VOIDOBJ', 'array of void')
bad('decl-incomplete-struct', 'struct is97; struct is97 x97; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
bad('decl-incomplete-union', 'union iu97; union iu97 x97; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
bad('decl-enum-forward-var', 'enum ie97 x97; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
bad('decl-two-classes', 'extern self int x97; ' + B + '{ trace(1); }', 'D_DECL_CLASS')
bad('decl-param-class', 'int pvcx[static int]; ' + B + '{ trace(1); }', 'D_DECL_PARMCLASS')
ok('decl-param-register', 'int pr97[register int]; ' + B + '{ trace(1); }')
bad('decl-proto-void-name', 'int pv97(void x); ' + B + '{ trace(1); }', 'D_DECL_PROTO_NAME')
bad('decl-proto-dyn', 'int pvdx[int [int]]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_TYPE')
bad('decl-proto-void-array', 'int pva97[void]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_TYPE')
bad('decl-proto-varargs-array', 'int pvx97[...]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_VARARGS')
bad('decl-proto-dup-name', 'int dn97[int a, int a]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_FORM', 'already declared')
bad('decl-member-scope', 'struct ms97 { int D`a; }; ' + B + '{ trace(1); }', 'D_DECL_SCOPE')
bad('decl-member-dynamic', 'struct md97 { int a[int]; }; ' + B + '{ trace(1); }', 'D_DECL_DYNOBJ', 'dynamic member')
bad('decl-member-incomplete', 'struct mi97; struct mo97 { struct mi97 m; }; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
bad('decl-member-void', 'struct mv97 { void v; }; ' + B + '{ trace(1); }', 'D_DECL_VOIDOBJ', 'void member')
ok('decl-member-from-other-ctf', 'struct mc97 { uint64_t a; string s; }; ' + B + '{ trace(sizeof (struct mc97)); }')
ok('decl-bitfield-zero-anon', 'struct bz97 { int a : 3; int : 0; int b : 3; }; ' + B + '{ trace(1); }')
bad('decl-bitfield-void', 'struct bv97 { void a : 3; }; ' + B + '{ trace(1); }', 'D_DECL_VOIDOBJ')
bad('decl-enum-redecl', 'enum er98 { ER98A }; enum er98 { ER98B }; ' + B + '{ trace(1); }', 'D_DECL_TYPERED')
ok('decl-enum-forward-then-define', 'enum ef97; enum ef97 { EF97A = 3 }; ' + B + '{ trace(EF97A); }', check=const_action(3))
bad('decl-enum-scope', 'enum es97 { D`x }; ' + B + '{ trace(1); }', 'D_DECL_SCOPE', 'enumerator name')
bad('decl-enum-overflow-explicit', 'enum eo97 { EO97A = 0x80000000 }; ' + B + '{ trace(1); }', 'D_DECL_ENOFLOW')
bad('decl-enum-underflow', 'enum eu97 { EU97A = -0x80000001L }; ' + B + '{ trace(1); }', 'D_DECL_ENOFLOW')
ok('decl-enum-min', 'enum em97 { EM97A = -2147483647 - 1, EM97B }; ' + B + '{ trace(EM97B); }', check=const_action(-0x7fffffff))
ok('decl-enum-ref-prior', 'enum ep97 { EP97A = 5, EP97B = EP97A }; ' + B + '{ trace(EP97B); }', check=const_action(5))
bad('decl-enum-dup-global', 'enum ed97 { timestamp }; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
bad('decl-enum-dup-enumerator', 'enum ea97 { EA97X }; enum eb97 { EA97X }; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
ok('decl-inline-scalar', 'inline int il97 = 3 + 4; ' + B + '{ trace(il97); }', check=const_action(7))
ok('decl-inline-array', 'inline int ia97[int x] = x * 2; ' + B + '{ trace(ia97[21]); }')
ok('decl-inline-string', 'inline string is98 = "abc"; ' + B + '{ trace(is98); }')
ok('decl-inline-var', 'inline uint64_t it97 = timestamp; ' + B + '{ trace(it97); }')
bad('decl-inline-class', 'inline extern int ix97 = 3; ' + B + '{ trace(1); }', 'D_DECL_BADCLASS', 'inline declaration')
bad('decl-inline-redef', 'inline int ir97 = 3; inline int ir97 = 4; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'identifier redefined')
bad('decl-inline-redef-var', 'int ir98; inline int ir98 = 4; ' + B + '{ trace(1); }', 'D_DECL_IDRED')
bad('decl-inline-array-nosig', 'inline int in97[] = 3; ' + B + '{ trace(1); }', 'D_DECL_ARRNULL', 'tuple signature')
bad('decl-inline-scalar-array', 'inline int in98[3] = 3; ' + B + '{ trace(1); }', 'D_DECL_ARRNULL', 'scalar array')
bad('decl-inline-void', 'inline void iv97 = 3; ' + B + '{ trace(1); }', 'D_DECL_VOIDOBJ', 'void inline')
bad('decl-inline-incomplete', 'struct ii97; inline struct ii97 iv98 = 3; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
bad('decl-inline-incompat', 'struct s { int a; }; struct s g; inline int ic97 = g; ' + B + '{ trace(1); }', 'D_OP_INCOMPAT', 'inline ic97')
bad('decl-inline-recursive', 'inline int iq97 = iq97 + 1; ' + B + '{ trace(1); }', 'D_IDENT_UNDEF')
bad('decl-scoped-ident', 'int D`x97; ' + B + '{ trace(1); }', 'D_DECL_SCOPE')
ok('decl-extern-func', 'extern int ef98(int); ' + B + '{ trace(1); }')
ok('decl-func-as-extern', 'int ef99(int); int ef99(int); ' + B + '{ trace(1); }')
bad('decl-extern-redecl', 'extern int ex97; extern char ex97; ' + B + '{ trace(1); }', 'D_DECL_IDRED', 'D`ex97')
ok('decl-typedef-copy', 'typedef uint64_t tc97; ' + B + '{ trace(sizeof (tc97)); }', check=const_action(8))
bad('decl-local-assoc', 'this int la97[int]; ' + B + '{ trace(1); }', 'D_DECL_LOCASSC')
ok('decl-this-scalar-redecl', 'this int tr97; this int tr97; ' + B + '{ this->tr97 = 1; }')
ok('include-depth', '# 1 "hdr.h" 1\nstruct hdr97 { int a; };\n# 3 "prog.d" 2\n' + B + '{ trace(sizeof (struct hdr97)); }',
   check=const_action(4))
ok('include-enum', '# 1 "hdr.h" 1\nenum he97 { HE97 = 9 };\ntypedef int ht97;\nint hv97;\n# 5 "prog.d" 2\n' + B + '{ trace(HE97); }')
ok('include-exit-at-top', '# 3 "prog.d" 2\n' + B + '{ trace(1); }')
ok('line-dev-fd', '# 1 "/dev/fd/3"\n' + B + '{ trace(1); }')
ok('decl-enum-unsigned-wrap', 'enum ew97 { EW97A = -0x80000001 }; ' + B + '{ trace(EW97A); }', check=const_action(0x7fffffff))

# --- Translators (D guide "Translators"; dt_node_xlator, dt_cook_xlator, dt_xlator.c).
ok('xlate-basic', XL + B + '{ trace(xlate<struct xout>((struct xin *)arg0).b); }')
ok('xlate-ptr', XL + B + '{ trace(xlate<struct xout *>((struct xin *)arg0)->b); }')
ok('xlate-deref-ptr', XL + B + '{ trace((*xlate<struct xout *>((struct xin *)arg0)).b); }')
ok('xlate-empty', 'struct ein { int a; }; struct eout { int b; }; '
   'translator struct eout < struct ein *p > { }; ' + B + '{ trace(1); }')
ok('xlate-union-out', 'struct uin { int a; }; union uout { int b; long c; }; '
   'translator union uout < struct uin *p > { b = p->a; }; ' + B +
   '{ trace(xlate<union uout>((struct uin *)arg0).b); }')
bad('xlate-out-scalar', 'struct sin { int a; }; translator int < struct sin *p > { }; ' + B + '{ trace(1); }',
    'D_XLATE_SOU', 'must be a struct or union')
bad('xlate-out-forward', 'struct fin { int a; }; struct fout; translator struct fout < struct fin *p > { }; ' + B + '{ trace(1); }',
    'D_XLATE_SOU', 'incomplete')
bad('xlate-member-missing', XL + B + '{ trace(xlate<struct xout>((struct xin *)arg0).c); }', 'D_XLATE_NOCONV')
bad('xlate-member-missing-ptr', XL + B + '{ trace(xlate<struct xout *>((struct xin *)arg0)->c); }', 'D_XLATE_NOCONV')
ok('xlate-member-not-defined', 'struct pin { int a; }; struct pout { int b; int c; }; '
   'translator struct pout < struct pin *p > { b = p->a; }; ' + B +
   '{ trace(xlate<struct pout>((struct pin *)arg0).b); }')
bad('xlate-none', XL + B + '{ trace(xlate<struct xout>(1)); }', 'D_XLATE_NONE')
ok('xlate-by-value-src', 'struct vin { int a; }; struct vout { int b; }; '
   'translator struct vout < struct vin v > { b = v.a; }; struct vin gv97; ' + B +
   '{ trace(xlate<struct vout>(gv97).b); }')
bad('xlate-addrof', XL + B + '{ trace(&xlate<struct xout>((struct xin *)arg0)); }', 'D_ADDROF_VAR')
ok('xlate-inline', XL + 'inline struct xout *xi97 = xlate<struct xout *>((struct xin *)0); ' + B + '{ trace(xi97->b); }')
bad('xlate-inline-incompat', XL + 'struct other97 { int z; }; '
    'inline struct other97 *xi98 = xlate<struct xout *>((struct xin *)0); ' + B + '{ trace(1); }',
    'D_OP_INCOMPAT', 'inline xi98')
ok('xlate-dynamic-mode', XL + B + '{ trace(xlate<struct xout>((struct xin *)arg0).b); }', opts=['xlate=dynamic'])
ok('xlate-member-uses-local', 'struct lin { int a; int b; }; struct lout { int s; }; '
   'translator struct lout < struct lin *p > { s = p->a + p->b; }; ' + B +
   '{ trace(xlate<struct lout>((struct lin *)arg0).s); }')

# --- Providers and probes (USDT definitions; dt_node_provider/probe, dt_cook_provider).
ok('prov-basic', 'provider pvax { probe ev(int, char *); }; ' + B + '{ trace(1); }')
ok('prov-empty', 'provider pvbx { }; ' + B + '{ trace(1); }')
ok('prov-xargs', 'provider pvcx { probe ev(int x, long y) : (long y, int x); }; ' + B + '{ trace(1); }')
bad('prov-xargs-unnamed', 'provider pvdx { probe ev(int x) : (long z); }; ' + B + '{ trace(1); }',
    'D_DECL_PROTO_FORM', 'not declared')
ok('prov-xargs-xlate', XL + 'provider pvex { probe ev(struct xin *p) : (struct xout *p); }; ' + B + '{ trace(1); }')
bad('prov-xargs-noxlate', 'struct nin { int a; }; struct nout { int b; }; '
    'provider pvfx { probe ev(struct nin *p) : (struct nout *p); }; ' + B + '{ trace(1); }',
    'D_PROV_PRXLATOR', 'is not defined')
bad('prov-probe-dup', 'provider pvgx { probe ev(int); probe ev(int); }; ' + B + '{ trace(1); }', 'D_PROV_PRDUP')
ok('prov-redecl-same', 'provider pvhx { probe ev(int); }; provider pvhx { probe ev(int); }; ' + B + '{ trace(1); }')
bad('prov-redecl-argc', 'provider pvix { probe ev(int); }; provider pvix { probe ev(int, int); }; ' + B + '{ trace(1); }',
    'D_PROV_INCOMPAT', 'prototype mismatch')
bad('prov-redecl-argtype', 'provider pvjx { probe ev(int); }; provider pvjx { probe ev(char *); }; ' + B + '{ trace(1); }',
    'D_PROV_INCOMPAT', 'argument #1 mismatch')
bad('prov-redecl-new-probe', 'provider pvkx { probe ev(int); }; provider pvkx { probe other(int); }; ' + B + '{ trace(1); }',
    'D_PROV_INCOMPAT', 'not defined')
ok('prov-redecl-add-xargs', 'provider pvlx { probe ev(int x); }; provider pvlx { probe ev(int x) : (int x); }; ' + B + '{ trace(1); }')
bad('prov-redecl-input-mismatch', 'provider pvmx { probe ev(int x) : (int x); }; '
    'provider pvmx { probe ev(long x) : (int x); }; ' + B + '{ trace(1); }', 'D_PROV_INCOMPAT', 'input')
bad('prov-name-scope', 'provider a`b { probe ev(); }; ' + B + '{ trace(1); }', 'D_PROV_BADNAME', 'scoping operator')
bad('prov-name-long', 'provider ' + 'p' * 70 + ' { probe ev(); }; ' + B + '{ trace(1); }', 'D_PROV_BADNAME', 'may not exceed')
bad('prov-name-digit', 'provider pn97 { probe ev(); }; ' + B + '{ trace(1); }', 'D_PROV_BADNAME', 'end with a digit')
bad('probe-name-scope', 'provider po { probe a`b(); }; ' + B + '{ trace(1); }', 'D_PROV_BADNAME', 'scoping operator')
bad('probe-name-long', 'provider pp { probe ' + 'e' * 70 + '(); }; ' + B + '{ trace(1); }', 'D_PROV_BADNAME', 'may not exceed')
bad('probe-input-args-256', 'provider pq { probe ev(' + ', '.join(['int'] * 256) + '); }; ' + B + '{ trace(1); }',
    'D_PROV_PRARGLEN', 'input prototype')
bad('probe-output-args-256', 'provider pr { probe ev(int x) : (' + ', '.join(['int x'] * 256) + '); }; ' + B + '{ trace(1); }',
    'D_PROV_PRARGLEN', 'output prototype')
ok('probe-hyphenated', 'provider ps { probe ev__start(); }; ' + B + '{ trace(1); }')
ok('prov-tree-dump', 'provider pt { probe ev(int); }; ' + B + '{ trace(1); }', opts=['tree=4'],
   check=out_has('PROVIDER pt (decl)', 'PROBE ::ev'))

# --- Pragmas and control lines (dt_pragma.c).
ok('pragma-attributes-ident', '#pragma D attributes Evolving/Evolving/Common pa_ident97\n'
   'inline int pa_ident97 = 1;\n' + B + '{ trace(pa_ident97); }')
ok('pragma-attributes-existing', 'inline int pa_ex97 = 1;\n#pragma D attributes Evolving/Evolving/Common pa_ex97\n'
   + B + '{ trace(pa_ex97); }')
bad('pragma-attributes-malformed', '#pragma D attributes Evolving/Evolving/Common\n' + B + '{ trace(1); }',
    'D_PRAGMA_MALFORM')
bad('pragma-attributes-badattr', '#pragma D attributes Nonsense pvax\n' + B + '{ trace(1); }', 'D_PRAGMA_INVAL')
for part in ['provider', 'module', 'function', 'name', 'args']:
    ok(f'pragma-attr-provider-{part}', 'provider pvzx { probe ev(); };\n'
       f'#pragma D attributes Evolving/Evolving/Common provider pvzx {part}\n' + B + '{ trace(1); }')
bad('pragma-attr-provider-badpart', 'provider pvyx { probe ev(); };\n'
    '#pragma D attributes Evolving/Evolving/Common provider pvyx bogus\n' + B + '{ trace(1); }',
    'D_PRAGMA_INVAL', 'invalid component')
bad('pragma-attr-provider-malformed', '#pragma D attributes Evolving/Evolving/Common provider px97\n' + B + '{ trace(1); }',
    'D_PRAGMA_MALFORM')
bad('pragma-attr-provider-unknown', '#pragma D attributes Evolving/Evolving/Common provider nosuchprovx name\n'
    + B + '{ trace(1); }', 'D_PRAGMA_UNUSED')
bad('pragma-attr-builtin', '#pragma D attributes Evolving/Evolving/Common timestamp\n' + B + '{ trace(1); }',
    'D_PRAGMA_SCOPE')
ok('pragma-binding-deferred', '#pragma D binding "1.0" pb_def97\ninline int pb_def97 = 2;\n' + B + '{ trace(pb_def97); }')
ok('pragma-binding-existing', 'inline int pb_ex97 = 2;\n#pragma D binding "1.0" pb_ex97\n' + B + '{ trace(pb_ex97); }')
bad('pragma-binding-malformed', '#pragma D binding pvbx\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('pragma-binding-badver', '#pragma D binding "x.y" pb98\n' + B + '{ trace(1); }', 'D_PRAGMA_INVAL')
bad('pragma-binding-builtin', '#pragma D binding "1.0" timestamp\n' + B + '{ trace(1); }', 'D_PRAGMA_SCOPE')
bad('pragma-depends-malformed', '#pragma D depends_on provider\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
ok('pragma-depends-provider', 'provider dpx { probe ev(); };\n#pragma D depends_on provider dpx\n' + B + '{ trace(1); }')
bad('pragma-depends-provider-missing', '#pragma D depends_on provider nosuchprov98\n' + B + '{ trace(1); }',
    'D_PRAGMA_DEPEND', 'requires provider')
ok('pragma-depends-module', '#pragma D depends_on module D\n' + B + '{ trace(1); }')
bad('pragma-depends-module-missing', '#pragma D depends_on module nosuchmod98\n' + B + '{ trace(1); }',
    'D_PRAGMA_DEPEND', 'requires module')
bad('pragma-depends-class', '#pragma D depends_on bogus x\n' + B + '{ trace(1); }', 'D_PRAGMA_INVAL', 'invalid class')
bad('pragma-error-strings', '#error "quoted text" and words\n' + B + '{ trace(1); }', 'D_PRAGERR', 'quoted text and words')
bad('pragma-error-pragma', '#pragma error stop\n' + B + '{ trace(1); }', 'D_PRAGERR')
ok('pragma-ident', '#ident "version 1"\n#pragma ident "x"\n' + B + '{ trace(1); }')
ok('pragma-option', '#pragma D option quiet\n' + B + '{ trace(1); }')
ok('pragma-option-value', '#pragma D option bufsize=8k\n' + B + '{ trace(1); }')
bad('pragma-option-superfluous', '#pragma D option quiet extra\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM', 'superfluous')
bad('pragma-option-bad-value', '#pragma D option bufsize=nonsense\n' + B + '{ trace(1); }', 'D_PRAGMA_OPTSET', "to 'nonsense'")
bad('pragma-option-string', '#pragma D option "quiet"\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
ok('pragma-unknown-ignored', '#pragma weak foo\n' + B + '{ trace(1); }')
bad('pragma-d-unknown', '#pragma D nosuchpragma\n' + B + '{ trace(1); }', 'D_PRAGMA_INVAL')
bad('control-string-first', '#"text"\n' + B + '{ trace(1); }', 'D_PRAGCTL_INVAL')
ok('control-empty', '#\n' + B + '{ trace(1); }')
ok('line-directive', '#line 40 "named.d"\n' + B + '{ trace(1); }')
ok('line-number-only', '# 40\n' + B + '{ trace(1); }')
bad('line-error-reports-line', '#line 40 "named.d"\n' + B + '{ trace(1 +); }', 'D_SYNTAX', 'named.d')
bad('line-malformed', '#line "x"\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('line-malformed-state', '# 4 "x" "y"\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('control-newline-string', '#error "unterminated\n' + B + '{ trace(1); }', 'D_STR_NL')
# DTRACE_C_CTL processes control lines only and yields no program (errno 0).
CASES.append(dict(id='ctl-only', src='#pragma D option quiet\n' + B + '{ trace(1); }', flags=ET | fp.CTL, expect='noprog'))
CASES.append(dict(id='ctl-only-skip-clause', src=B + '{ trace(1 +); }\n#pragma D option quiet\n', flags=ET | fp.CTL, expect='noprog'))
bad('ctl-only-bad-pragma', '#pragma D option nosuchopt97\n' + B + '{ trace(1); }', 'D_PRAGMA_OPTSET', flags=ET | fp.CTL)

# --- Attribute minimum (-e / DTRACE_C_EATTR with option amin).
# The clause takes the probe's attributes (BEGIN: Unstable) first, so with a
# Standard minimum the clause itself is named; with an Unstable minimum the
# clause passes and the Private variable curthread is named.
bad('attr-min-clause', B + '{ }', 'D_ATTR_MIN', 'clause', flags=ET | fp.EATTR,
    opts=['amin=Standard/Standard/Common'])
bad('attr-min-var', B + '{ trace(curthread); }', 'D_ATTR_MIN', 'scalar curthread (Stable/Private/Common)', flags=ET | fp.EATTR,
    opts=['amin=Unstable/Unstable/Common'])
ok('attr-min-met', B + '{ trace(1); }', flags=ET | fp.EATTR, opts=['amin=Unstable/Unstable/Common'])

# --- Foreign HyperTrace targets: a probe argument of a clause for another
# target is typed "bottom" (dt_idcook_args leaves it unresolved) and type
# checks that need its type are deferred to the target.  Each clause ends
# with a reference to an undefined variable, so the first error reported is
# that sentinel D_IDENT_UNDEF: no earlier type error may occur.  (A complete
# compile cannot be used: dt_as.c copies the NULL module name of a bottom-
# typed variable into the variable table -- reported to the dt_as owner.)
FT = 'nosuchvmx:fbt::foo:entry '
for cid, body in [('bot-arith', 'trace(args[0] + 1); trace(1 + args[0]); trace(args[0] - 1); trace(args[0] + args[1]);'
                   ' trace((char *)arg0 + args[0]); trace(args[0] + (char *)arg0);'),
                  ('bot-member', 'trace(args[0]->a); trace(args[0].b);'),
                  ('bot-int-ops', 'trace(args[0] & 1); trace(1 | args[0]); trace(args[0] << 2); trace(args[0] % 3);'
                   ' trace(args[0] * 2); trace(2 / args[0]);'),
                  ('bot-logic', 'trace(args[0] && 1); trace(args[0] ^^ args[1]);'),
                  ('bot-cmp', 'trace(args[0] == 1); trace(args[0] < args[1]); trace(1 >= args[0]);'),
                  ('bot-asgn', 'x = 1; x += args[0]; x -= args[1]; x |= args[0]; x *= args[0]; this->p = (char *)arg0; this->p += args[0];'),
                  ('bot-cond', 'trace(args[0] ? 1 : 2); trace(timestamp ? args[0] : 1); trace(timestamp ? 1 : args[0]);'
                   ' trace(timestamp ? args[0] : args[1]);'),
                  ('bot-unary', 'trace(-args[0]); trace(!args[0]); trace(~args[0]); trace(*args[0]);'),
                  ('bot-cast', 'trace((int)args[0]);'),
                  ('bot-pred', None)]:
    src = FT + ('/args[0]/ { trace(1); trace(nosuchvar97); }' if body is None
                else '{ ' + body + ' trace(nosuchvar97); }')
    bad(cid, src, 'D_IDENT_UNDEF', 'nosuchvar97', flags=ET | fp.NOLIBS | fp.ZDEFS)

# --- Probe descriptions and identifiers.
bad('pdesc-id-provider-spec', '1234 { trace(1); }', 'D_PDESC_INVAL', 'not permitted', mode='prog-provider')
bad('pdesc-id-too-big', '99999999999 { trace(1); }', 'D_PDESC_INVAL', 'exceeds maximum')
bad('pdesc-id-unknown', '4097 { trace(1); }', 'D_PDESC_INVAL', 'invalid probe identifier')
ok('pspec-mode-provider', 'dtrace { trace(1); }', mode='prog-provider', flags=ET | fp.ZDEFS)
ok('pspec-mode-mod', 'nosuchmod { trace(1); }', mode='prog-mod', flags=ET | fp.ZDEFS)
ok('pspec-mode-func', 'nosuchfunc { trace(1); }', mode='prog-func', flags=ET | fp.ZDEFS)
ok('pspec-type-star', 'int*x97; ' + B + '{ trace(x97); }')
ok('pspec-type-star-glob', 'int* { trace(1); }', flags=ET | fp.PSPEC | fp.ZDEFS)
ok('pspec-type-name', 'uint64_t*p97; ' + B + '{ trace(p97); }')
bad('outer-bad-char', '@ ' + B + '{ trace(1); }', 'D_SYNTAX', 'syntax error near "@"')
ok('backslash-newline', B + '{ trace(1 +\\\n 2); }', check=const_action(3))

# --- Predicates and clause cooking.
ok('pred-forward-ref', B + '/pvfx == 1/ { pvfx = 1; }')
bad('pred-undef-both', B + '/nosuchvar97 == 1/ { trace(1); }', 'D_IDENT_UNDEF')
bad('pred-type', 'struct s { int a; }; struct s g; ' + B + '/g/ { trace(1); }', 'D_PRED_SCALAR')
bad('pred-act-error', B + '/pf98 == 1/ { pf98 = 1; trace(1 / 0); }', 'D_DIV_ZERO')
ok('if-else', B + '{ if (timestamp) { trace(1); } else { trace(2); } }')
ok('if-only', B + '{ if (timestamp > 1) trace(1); }')

# --- With the D system libraries (/usr/lib/dtrace): their translators and
# inlines are parsed and cooked like user declarations.
ok('libs-loaded', B + '{ trace(1); }', libs=True)
ok('libs-tree', B + '{ trace(1); }', libs=True, opts=['tree=1'], check=out_has('PROGRAM attr=', 'INLINE'))

# --- Scanner input handling: file input, very long tokens (scanner buffer
# growth), NUL bytes, unterminated constructs.
ok('file-input', B + '{ trace(1); }', mode='file', check=const_action(1))
ok('file-type', 'struct ft97 { int a; }', mode='typefile')
bad('long-pspec', 'dtrace:::' + 'n' * 40000 + ' { trace(1); }', 'D_PDESC_INVAL')
bad('long-ident', B + '{ ' + 'v' * 40000 + ' = 1; trace(' + 'v' * 40000 + ' + 1 +); }', 'D_SYNTAX')
bad('nul-in-file', B + '{ trace(1);\0 }', 'D_SYNTAX', mode='file')
# End of input inside a comment or a control line is an error (the
# behaviour of the original lex input() routine, documented in dt_lex.l).
bad('eof-in-comment', B + '{ trace(1); } /* never closed', 'D_SYNTAX', 'before matching */')
bad('eof-in-comment-file', B + '{ trace(1); } /* never closed', 'D_SYNTAX', 'before matching */', mode='file')
bad('eof-in-control', B + '{ trace(1); }\n#pragma D option quiet', 'D_SYNTAX', 'before end of control line')
ok('control-final-newline', B + '{ trace(1); }\n#pragma D option quiet\n')
# depends_on provider consults the kernel's provider list first, then the
# providers known to libdtrace (modelled sysctl; see frontend-parser-shim.c).
ok('pragma-depends-kernel-list', '#pragma D depends_on provider kprovx\n' + B + '{ trace(1); }',
   providers='dtrace kprovx profile')
ok('pragma-depends-not-in-list', 'provider lprovx { probe ev(); };\n#pragma D depends_on provider lprovx\n'
   + B + '{ trace(1); }', providers='dtrace profile')
bad('pragma-depends-neither', '#pragma D depends_on provider mprovx\n' + B + '{ trace(1); }',
    'D_PRAGMA_DEPEND', providers='dtrace profile')
# Library dependencies (#pragma D depends_on library) in a private libdir.
ok('lib-depends-ok', B + '{ trace(fb97 + fc97); }',
   libfiles={'fb97.d': '#pragma D depends_on library fc97.d\ninline int fb97 = fc97 + 1;\n',
             'fc97.d': 'inline int fc97 = 2;\n'})
bad('lib-main-depends', '#pragma D depends_on library fd97.d\n' + B + '{ trace(1); }', 'D_PRAGMA_DEPEND',
    'main program may not explicitly depend on a library', libfiles={'fd97.d': 'inline int fd97 = 1;\n'})
# DIF return types of traced values (dt_node_diftype): a userland struct is
# traced by user reference, a kernel struct by reference.
ok('diftype-byuref', 'struct s { int a; int b; }; ' + B + '{ trace(*(userland struct s *)arg0); }',
   check=lambda r, K: r['stmts'][-1]['acts'][-1]['difo']['rflags'] & K['DIF_TF_BYUREF'] == K['DIF_TF_BYUREF'])
ok('diftype-byref', 'struct s { int a; int b; }; ' + B + '{ trace(*(struct s *)arg0); }',
   check=lambda r, K: r['stmts'][-1]['acts'][-1]['difo']['rflags'] & K['DIF_TF_BYREF'] == K['DIF_TF_BYREF'])
# Translator lookup passes (dt_xlator_lookup): exact source type, resolved
# source base type, then argument-compatible source (void * matches any
# pointer).  In dynamic translation mode the program's DOF exports the
# translators it references.
ok('xlate-fuzzy-void', XL + B + '{ trace(xlate<struct xout>((void *)arg0).b); }')
ok('xlate-typedef-src', 'struct tin { int a; }; struct tout { int b; }; typedef struct tin *tinp_t; '
   'translator struct tout < tinp_t p > { b = p->a; }; ' + B + '{ trace(xlate<struct tout>((struct tin *)arg0).b); }')
ok('xlate-typedef-use', 'struct uin2 { int a; }; struct uout2 { int b; }; typedef struct uin2 *uinp_t; '
   'translator struct uout2 < struct uin2 *p > { b = p->a; }; ' + B + '{ trace(xlate<struct uout2>((uinp_t)arg0).b); }')
ok('xlate-dynamic-dof', XL + B + '{ trace(xlate<struct xout>((struct xin *)arg0).b); }', opts=['xlate=dynamic'],
   dof=True, check=lambda r, K: r.get('dof') is True)
# Grammar productions for abstract declarators and parameter lists.
ok('decl-ptr-qual-ptr', 'int * const * pqp97; ' + B + '{ trace(sizeof (pqp97)); }', check=const_action(8))
ok('abs-ptr-array', B + '{ trace(sizeof (int *[3])); }', check=const_action(24))
ok('param-abstract', 'int pa98(int *, char (*)(int)); ' + B + '{ trace(1); }')
ok('param-func-type', 'int pf98(int (int)); ' + B + '{ trace(1); }')
ok('array-of-array-abs', B + '{ trace(sizeof (int [2][3])); }', check=const_action(24))
# The parser's stack is bounded (YYMAXDEPTH); exceeding it is reported.
bad('yacc-stack-overflow', B + '{ trace(' + '(' * 12000 + '1' + ')' * 12000 + '); }', 'D_SYNTAX',
    'yacc stack overflow')
# dtrace_type_strcompile() of an empty string has no type: an empty unit.
CASES.append(dict(id='type-empty', src='', mode='type', expect=('*', 'empty D program')))
# A library whose dependency cannot be found in the library path, or whose
# dependency failed to load, is itself not loaded (dt_load_libs reports
# library errors only through the libraries' absence): the program compiles,
# but the library's definitions are undefined.
bad('lib-depends-missing', B + '{ trace(fa97); }', 'D_IDENT_UNDEF', 'fa97',
    libfiles={'fa97.d': '#pragma D depends_on library nosuchlib97.d\ninline int fa97 = 1;\n'})
# A syntax error in a library is reported for that library file.
bad('lib-depends-failed', B + '{ trace(fe97); }', '*', 'ff97.d", line 1: syntax error',
    libfiles={'fe97.d': '#pragma D depends_on library ff97.d\ninline int fe97 = 1;\n',
              'ff97.d': 'inline int ff97 = ;\n'})
ok('lib-depends-missing-unused', B + '{ trace(1); }',
   libfiles={'fg97.d': '#pragma D depends_on library nosuchlib98.d\ninline int fg97 = 1;\n'})
# Constant inlines take their declared type (converted as by assignment);
# a same-width change of signedness re-extends the value (dt_cg_typecast).
ok('inline-const-narrow', 'inline unsigned char UC = 0x1ff; ' + B + '{ trace(UC); }', check=const_action(0xff, 1))
ok('inline-const-sign', 'inline int IS = 0xffffffff; ' + B + '{ trace(IS < 0); }', check=const_action(1))
ok('inline-const-in-expr', 'inline unsigned char UD = 0x1ff; ' + B + '{ trace(UD + 1); }', check=const_action(0x100))
ok('fold-cast-same-size-sign', B + '{ trace((int)0x80000000 < 0); }', check=const_action(1))
ok('fold-cast-unsigned-same', B + '{ trace((unsigned int)-1 == 0xffffffffu); }', check=const_action(1))
# D_ATTR_MIN names the first cooked node below the minimum (dt_node_name):
# an inline or translator whose stability #pragma D attributes lowered.
bad('attr-min-inline', 'inline uint64_t ilp = timestamp;\n#pragma D attributes Private/Private/Common ilp\n'
    + B + '{ trace(ilp); }', 'D_ATTR_MIN', 'ilp', flags=ET | fp.EATTR, opts=['amin=Unstable/Unstable/Common'])
bad('attr-min-xlate', '#pragma D attributes Private/Private/Common translator\n' + XL + B +
    '{ trace(xlate<struct xout>((struct xin *)arg0).b); }', 'D_ATTR_MIN', 'operator xlate',
    flags=ET | fp.EATTR, opts=['amin=Unstable/Unstable/Common'])
ok('tree-bitfield', 'struct bf { int a : 3; }; struct bf g; ' + B + '{ trace(g.a); }', opts=['tree=2'],
   check=out_has('LVAL,WRITE,BITF)'))
# Typedef names seen as the next token (yacc lookahead) after a type is set.
bad('decl-typedef-tname-redecl', 'typedef int td8; typedef td8 td8; ' + B + '{ trace(1); }', 'D_DECL_IDRED',
    'typedef redeclared: td8')
bad('probe-output-noname', 'provider pwx { probe ev(int x) : (int); }; ' + B + '{ trace(1); }',
    'D_DECL_PROTO_NAME', 'requires a name')
ok('decl-func-ptr-ptr', 'int (**fpp9)(int); ' + B + '{ trace(sizeof (fpp9)); }', check=const_action(8))
ok('decl-func-returning-ptr', 'int *frp9(int); ' + B + '{ trace(1); }')
ok('decl-enum-in-struct', 'struct es9 { enum ee9 { EE9A = 4 } e; int b; }; ' + B + '{ trace(EE9A); }',
   check=const_action(4))
ok('include-enum-shadowed', '# 1 "h.h" 1\nenum { timestamp, other9 };\n# 3 "p.d" 2\n' + B + '{ trace(other9); }',
   check=const_action(1))
bad('decl-error-in-scope', 'struct sc9 { int a[nosuchvar9]; }; ' + B + '{ trace(1); }', 'D_IDENT_UNDEF')
# A program declaring USDT providers has no probe sites until it is linked
# with the objects that contain them (dtrace -G), so its DOF cannot be made.
ok('prov-xargs-xlate-dof', XL + 'provider pxdx { probe ev(struct xin *p) : (struct xout *p); }; ' + B + '{ trace(1); }',
   dof=True, check=lambda r, K: r.get('doferror') == 'No probe sites found for declared provider')
# Outer-scope (S2) keywords and control lines/interpreter lines inside clauses.
ok('outer-float-decl', 'float ff9; ' + B + '{ trace(sizeof (ff9)); }', check=const_action(4))
ok('outer-string-decl', 'string ss9; ' + B + '{ ss9 = "a"; trace(ss9); }')
ok('outer-restrict-first', 'restrict int *rr9; ' + B + '{ trace(1); }')
bad('outer-counter', 'counter cc9; ' + B + '{ trace(1); }', 'D_SYNTAX')
bad('outer-import', 'import ii9; ' + B + '{ trace(1); }', 'D_SYNTAX')
ok('clause-interp-line', B + '{\n#!/usr/sbin/dtrace\n trace(1); }')
ok('clause-control-line', B + '{\n#pragma D option quiet\n trace(1); }')
ok('macro-lone-quote', B + '{ trace($$1); }', args=['p', '"'],
   check=lambda r, K: '"' in r['stmts'][0]['acts'][0]['difo']['strtab'])
ok('pspec-glob-star-notype', 'BEGI* { trace(1); }', flags=ET | fp.ZDEFS)
bad('control-quote-eof', B + '{ trace(1); }\n#error "abc', 'D_SYNTAX', 'syntax error near """')
# Final pass: logical xor folds to 0/1 (D guide: ^^ is true when exactly one
# operand is non-zero).
ok('fold-lxor-1', B + '{ trace(3 ^^ 0); }', check=const_action(1, 4))
ok('fold-lxor-0', B + '{ trace(2 ^^ 5); }', check=const_action(0, 4))
ok('inline-array-anon-param', 'inline int ib97[int] = 5; ' + B + '{ trace(1); }')
ok('assoc-element-index', B + '{ a[1] = (int *)arg0; trace(a[1][2]); }')
ok('userland-ptr-add-flag', B + '{ trace((userland int *)arg0 + 1); }', opts=['tree=2'],
   check=out_has('OP2 + (type=<int *> attr=[s/s/c] flags=COOK,USER)'))
ok('xlate-assign-var', XL + B + '{ xv = xlate<struct xout>((struct xin *)arg0); trace(xv.b); }')
ok('cast-int-to-double', B + '{ trace(sizeof ((double)arg0)); }', check=const_action(8))
ok('cond-string-charptr', B + '{ trace(timestamp ? "a" : (char *)arg0); }',
   check=lambda r, K: r['stmts'][0]['acts'][0]['difo']['rkind'] == K['DIF_TYPE_STRING'])
ok('tree-agg-tuple', B + '{ @a[1, 2] = count(); }', opts=['tree=2'],
   check=lambda r, K: re.search(r'AGGREGATE @a attr=\S+ \[\n.*INT 0x1.*\n\s+,\n.*INT 0x2.*\n\s+\] = ', r['output']) is not None)
bad('nested-scope-error', 'struct no97 { struct ni97 { int a : -1; } x; }; ' + B + '{ trace(1); }', 'D_DECL_BFCONST')

# --- Round 2.
# A call through anything but an identifier: the grammar accepts any postfix
# expression before "(", dt_node_func requires a function name.
bad('call-non-ident-int', B + '{ trace((1)()); }', 'D_FUNC_IDENT', 'not of function type')
bad('call-non-ident-string', B + '{ ("a")(1); }', 'D_FUNC_IDENT')
# Casts from an array to a pointer type (K&R A7.5; arrays are not scalars).
ok('cast-array-to-ptr', 'int arr97[4]; ' + B + '{ trace((char *)arr97); }')
# A zero constant on the left of a pointer comparison or conditional.
ok('ptr-zero-left-cmp', B + '{ trace(0 == (int *)arg0); }')
ok('ptr-zero-left-cond', B + '{ trace(timestamp ? 0 : (int *)arg0); }')
# Associative array keys of the stack/symbol types compare as compatible
# with themselves (dt_node_is_argcompat), and the tracing functions are then
# rejected by code generation: they are not D expressions.
for fn in ['stack()', 'immstack()', 'sym(arg0)', 'usym(arg0)']:
    bad(f'key-{fn.split("(")[0]}', B + f'{{ a[{fn}] = 1; trace(a[{fn}]); }}', 'D_CG_EXPR',
        f'{fn.split("(")[0]}( ) may not be called from a D expression')
ok('key-struct', 'struct ks { int x; }; struct ks g; ' + B + '{ a[g] = 1; trace(a[g]); }')
# Type names in diagnostics: a function pointer is named "function pointer".
bad('fptr-type-name', 'int (*fp97)(int); ' + B + '{ trace(fp97 + "a"); }', 'D_OP_INCOMPAT',
    '"function pointer" + "string"')
# Multiple backquotes in a type name: only a link-map id (LM<hex>) may follow
# the object (dt_type_lookup); otherwise no type is named.
CASES.append(dict(id='type-scope-3', src='D`x`y`int', mode='type', expect=('*', 'syntax error')))
CASES.append(dict(id='type-scope-lm', src='D`LM1`y`int', mode='type', expect=('*', 'syntax error')))
CASES.append(dict(id='type-scope-4', src='D`a`b`c`int', mode='type', expect=('*', 'syntax error')))
# A foreign-target variable is recorded with DIF type bottom and size 0
# (dt_node_diftype: the target fills it in).
ok('bottom-var-diftype', 'nosuchvmx:fbt::foo:entry { x = args[0]; }', flags=ET | fp.ZDEFS,
   check=lambda r, K: any(v['name'] == 'x' and v['tkind'] == K['DIF_TYPE_BOTTOM'] and v['tsize'] == 0
                          for s in r['stmts'] for a in s['acts'] for v in a['difo']['vars']))
# printa(@a) passes the aggregation without an aggregating function.
ok('tree-agg-nofunc', B + '{ @a = count(); } END { printa(@a); }', opts=['tree=2'],
   check=lambda r, K: re.search(r'FUNC printa .*\n\s+AGGREGATE @a attr=\S+ \[\n\s+\]\n', r['output']) is not None)
# Translators referenced by a provider are exported in the DOF in dynamic
# translation mode (dof_add_provider -> dt_xlator_lookup_id).
ok('xlate-export-dof', XL + 'provider pxex { probe ev(struct xin *p) : (struct xout *p); }; ' + B + '{ trace(1); }',
   opts=['xlate=dynamic'], dof=True,
   check=lambda r, K: r.get('doferror') == 'No probe sites found for declared provider')
# A translated (dynamic) value is not compatible with a subroutine's typed
# parameter (dt_node_is_ptrcompat rejects dynamic operands).
bad('proto-arg-dynamic', XL + B + '{ trace(strlen(xlate<struct xout>((struct xin *)arg0))); }', 'D_PROTO_ARG',
    'strlen( ) argument #1 is incompatible')
# A $n macro whose text starts with a quote but does not end with one is the
# literal text (dt_lex.l: only a fully quoted value is unquoted).
ok('macro-open-quote', B + '{ trace($1); }', args=['p', '"abc'],
   check=lambda r, K: '"abc' in r['stmts'][0]['acts'][0]['difo']['strtab'])
# The predicate's closing "/" is recognised before ";" and "/" as well.
bad('pred-close-semicolon', B + '/1/;', 'D_SYNTAX', 'near ";"')
bad('pred-close-slash', B + '/1//', 'D_SYNTAX')
# A type name followed by ++, --, = or [ in a clause is lexed as an
# identifier, so it names (or creates) a variable (dt_lex.l id_or_type).
ok('tname-as-var-assign', B + '{ uint8_t = 3; trace(uint8_t); }')
ok('tname-as-var-postinc', B + '{ int16_t = 1; int16_t++; }')
ok('tname-as-var-postdec', B + '{ int32_t = 1; int32_t--; }')
ok('tname-as-var-array', B + '{ uint16_t[1] = 2; trace(uint16_t[1]); }')
bad('tname-equality', B + '{ trace(uint8_t == 1); }', 'D_SYNTAX')
bad('tname-plus', B + '{ trace(uint8_t + 1); }', 'D_SYNTAX')
# More than one qualifier after a pointer.
ok('ptr-two-qualifiers', 'int * const volatile pq97; ' + B + '{ trace(sizeof (pq97)); }', check=const_action(8))
# A scoped tag keyword followed by white space but no tag name.
# ... is then not a type name but a symbol reference.
bad('scoped-struct-space', B + '{ trace(sizeof (D`struct )); }', 'D_IDENT_UNDEF', 'D`struct')
# In a type name, an identifier followed by "-" but no backquote is an
# expression operand (array dimension), not a module name.
CASES.append(dict(id='type-dash-expr-decl', src='enum dq97 { DQ97 = 4 }; BEGIN { }', expect='ok'))
CASES.append(dict(id='type-dash-expr', src='char [DQ97-1]', mode='type', keep=True, expect='ok',
                  check=lambda r, K: r['type']['nelems'] == 3))
# --- dt_decl.c branch completion.
ok('decl-void-ptr', 'void *vp97; ' + B + '{ trace(sizeof (vp97)); }', check=const_action(8))
bad('decl-proto-dyn-named', 'int pdn97[int x[int]]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_TYPE', ': x, parameter #1')
bad('decl-proto-void-named', 'int pvn97[void v]; ' + B + '{ trace(1); }', 'D_DECL_PROTO_TYPE', ': v, parameter #1')
ok('decl-func-void-sole', 'int fvs97(void); ' + B + '{ trace(1); }')
ok('decl-array-2d', 'int md97[2][3]; ' + B + '{ trace(sizeof (md97)); }', check=const_action(24))
bad('decl-member-empty-struct', 'struct ez97 { int : 0; }; struct eo97 { struct ez97 m; }; ' + B + '{ trace(1); }',
    'D_DECL_INCOMPLETE')
ok('decl-anon-bitfield-nonzero', 'struct ab98 { int a : 3; int : 5; }; ' + B + '{ trace(1); }')
ok('decl-enum-ref-other-enum', 'enum ea98 { EA98 = 6 }; enum eb98 { EB98 = EA98 + 1 }; ' + B + '{ trace(EB98); }',
   check=const_action(7))
ok('decl-unsigned-long-int', 'unsigned long int uli97; ' + B + '{ trace(sizeof (uli97)); }', check=const_action(8))
ok('decl-const-void-ptr', 'const void *cvp97; ' + B + '{ trace(sizeof (cvp97)); }', check=const_action(8))
# A missing inner dimension is an array of zero elements (dt_decl_type uses
# nelems 0 without a dimension node); the declaration is accepted, and its
# size is zero, so sizeof is rejected.
ok('decl-array-2d-nodim', 'int nd97[2][]; ' + B + '{ trace(1); }')
bad('decl-array-2d-nodim-size', 'int nd98[2][]; ' + B + '{ trace(sizeof (nd98)); }', 'D_SIZEOF_TYPE')
bad('decl-member-empty-union', 'union uz97 { int : 0; }; struct uo97 { union uz97 m; }; ' + B + '{ trace(1); }',
    'D_DECL_INCOMPLETE')
bad('decl-anon-bitfield-nonconst', 'struct anc97 { int : timestamp; }; ' + B + '{ trace(1); }', 'D_DECL_BFCONST')
# In a C header (include depth > 0) an enumerator named like a D global is
# added to the enum but not as a D identifier, so a later enumerator's
# initializer naming it is resolved inside the enum (value 5).
ok('include-enum-self-ref', '# 1 "h.h" 1\nenum eh97 { timestamp = 5, EH97 = timestamp };\n# 3 "p.d" 2\n'
   + B + '{ trace(EH97); }', check=const_action(5))
# An enum left without members by a failed definition is completed by a
# later definition in the same handle.
CASES.append(dict(id='enum-empty-first', src='enum ee97 { EE97X = timestamp }; ' + B + '{ }',
                  expect=('D_DECL_ENCONST', 'must be assigned to an integral constant')))
CASES.append(dict(id='enum-empty-then', src='enum ee97 { EE97Y = 4 }; ' + B + '{ trace(EE97Y); }', keep=True,
                  expect='ok', check=const_action(4)))

# --- Round 4: dt_parser.c branch outcomes (see A/parser-branches.txt).
CASES.append(dict(id='type-scope-l-not-lm', src='D`La`b`int', mode='type', expect=('*', 'syntax error')))
ok('ptr-to-typedef-of-struct', 'struct pts { int a; }; struct pts *ptsp; typedef struct pts pts_t; pts_t *ptp; '
   + B + '{ trace(sizeof (ptp)); }', check=const_action(8))
ok('ptr-in-header', '# 1 "h.h" 1\nstruct phd { int a; };\nstruct phd *phdp;\n# 3 "p.d" 2\n' + B + '{ trace(phdp->a); }')
ok('bitfield-24', 'struct b24 { int a : 24; }; struct b24 g; ' + B + '{ trace(g.a); }', opts=['tree=2'],
   check=out_has('BITF'))
bad('sizeof-bitfield-24', 'struct b24 { int a : 24; }; struct b24 g; ' + B + '{ trace(sizeof (g.a)); }',
    'D_SIZEOF_BITFIELD')
ok('deref-inline-ptr', 'inline int *ip97 = (int *)0; ' + B + '{ trace(*ip97); }')
ok('cast-to-float', B + '{ trace(sizeof ((float)arg0)); }', check=const_action(4))
ok('cast-to-long-double', B + '{ trace(sizeof ((long double)arg0)); }', check=const_action(16))
bad('cast-string-to-float', B + '{ trace((float)"a"); }', 'D_CAST_INVAL')
ok('lneg-enum', 'enum en97 { EN97 }; enum en97 ev97; ' + B + '{ trace(!ev97); }')
bad('cmp-dynamic-left', XL + B + '{ trace(xlate<struct xout>((struct xin *)arg0) == 0); }', 'D_OP_INCOMPAT')
bad('cmp-ptr-intvar', B + '{ trace((int *)arg0 == arg1); }', 'D_OP_INCOMPAT')
bad('cmp-struct-ptr', 'struct cs97 { int a; }; struct cs97 g; ' + B + '{ trace(g == (int *)arg0); }', 'D_OP_INCOMPAT')
bad('cmp-fwd-ptr-other', 'struct fa97; struct sb97 { int a; }; ' + B +
    '{ trace((struct fa97 *)arg0 == (struct sb97 *)arg1); }', 'D_OP_INCOMPAT')
ok('cond-void-ptr-right', B + '{ trace(timestamp ? (int *)arg0 : (void *)arg1); }')
bad('key-stack-then-int', B + '{ a[stack()] = 1; trace(a[1]); }', 'D_PROTO_ARG')
bad('key-immstack-then-int', B + '{ a[immstack()] = 1; trace(a[1]); }', 'D_PROTO_ARG')
bad('key-sym-then-int', B + '{ a[sym(arg0)] = 1; trace(a[1]); }', 'D_PROTO_ARG')
bad('key-usym-then-int', B + '{ a[usym(arg0)] = 1; trace(a[1]); }', 'D_PROTO_ARG')
ok('key-union', 'union ku97 { int x; long y; }; union ku97 g; ' + B + '{ a[g] = 1; trace(a[g]); }')
ok('array-dim-unsigned', 'int ad97[3u]; ' + B + '{ trace(sizeof (ad97)); }', check=const_action(12))
ok('decl-static-func', 'static int sf97(int); ' + B + '{ trace(1); }')
bad('decl-union-empty-var', 'union uz98 { int : 0; }; union uz98 uv98; ' + B + '{ trace(1); }', 'D_DECL_INCOMPLETE')
ok('offsetof-union', 'union ou97 { int a; long b; }; ' + B + '{ trace(offsetof(union ou97, b)); }', check=const_action(0))
bad('mod-zero', B + '{ trace(1 % 0); }', 'D_DIV_ZERO')
bad('mod-eq-zero', B + '{ x = 1; x %= 0; }', 'D_DIV_ZERO')
bad('div-eq-zero', B + '{ x = 1; x /= 0; }', 'D_DIV_ZERO')
ok('cast-userland-int-const', B + '{ trace((userland int)1); }')
bad('this-read-undef', B + '{ trace(this->u97); }', 'D_VAR_UNDEF', 'this->u97')
ok('deref-array-of-array', 'int aa99[2][3]; ' + B + '{ trace((*aa99)[1]); }')
ok('deref-array-of-string', 'char cs99[2][8]; ' + B + '{ trace(stringof(*cs99)); }')
ok('deref-ptr-minus', B + '{ trace(*((int *)arg0 - 1)); }')
ok('deref-userland-ptrptr', B + '{ trace(*(userland int **)arg0); }')
bad('array-self-ref-read', B + '{ y97[1] = y97[2]; }', 'D_VAR_UNDEF', 'y97 has not yet been declared')
bad('cmp-enum-scoped-rhs', 'enum ce97 { CE97A }; enum ce97 ev97; ' + B + '{ trace(ev97 == nosuchmod97`x); }', 'D_IDENT_UNDEF')
ok('cmp-enum-not-tag', 'enum ce98 { CE98A }; enum ce98 ev98; ' + B + '{ trace(ev98 == timestamp); }')
ok('cmp-string-charptr-left', B + '{ trace(execname == (char *)arg0); }')
ok('cmp-charptr-chararray', 'char ca97[4]; ' + B + '{ trace((char *)arg0 == ca97); }')
bad('cmp-string-int', B + '{ trace(execname == 1); }', 'D_OP_INCOMPAT')
bad('int-plus-voidptr', B + '{ trace(1 + (void *)arg0); }', 'D_OP_INCOMPAT')
bad('ptr-minus-incompat', B + '{ trace((int *)arg0 - (char *)arg1); }', 'D_OP_INCOMPAT')
bad('or-eq-string-rhs', B + '{ x = 1; x |= "a"; }', 'D_OP_INT', 'operator |=')
bad('mul-eq-string-rhs', B + '{ x = 1; x *= "a"; }', 'D_OP_ARITH', 'operator *=')
bad('agg-assign-subr', B + '{ @a = strlen("x"); }', 'D_AGG_FUNC')
bad('xlate-assign-incompat', XL + 'struct other98 { int z; }; struct other98 o98; ' + B +
    '{ o98 = xlate<struct xout>((struct xin *)arg0); }', 'D_OP_INCOMPAT')
bad('add-eq-string-rhs', B + '{ x = 1; x += "a"; }', 'D_OP_INCOMPAT')
bad('add-eq-int-ptr', B + '{ x = 1; x += (int *)arg0; }', 'D_OP_VFPTR')
bad('add-eq-ptr-ptr', B + '{ this->p = (int *)arg0; this->p += (int *)arg1; }', 'D_OP_INCOMPAT', '"int *" += "int *"')
bad('sub-eq-ptr-ptr', B + '{ this->p = (int *)arg0; this->p -= (int *)arg1; }', 'D_OP_INCOMPAT', '"int *" -= "int *"')
ok('dot-array-members', 'struct sa97 { int arr[2]; char nm[8]; }; struct sa97 g; ' + B +
   '{ trace(g.arr[1]); trace(stringof(g.nm)); }')
ok('userland-member-struct', 'struct in97 { int a; }; struct out97 { struct in97 inner; }; ' + B +
   '{ trace(((userland struct out97 *)arg0)->inner.a); }')
bad('cast-ptr-from-struct', 'struct cp97 { int a; }; struct cp97 g; ' + B + '{ trace((int *)g); }', 'D_CAST_INVAL')
bad('cast-string-from-struct', 'struct cq97 { int a; }; struct cq97 g; ' + B + '{ trace((string)g); }', 'D_CAST_INVAL')
ok('cast-string-from-ptr', B + '{ trace((string)(char *)arg0); }')
ok('cast-string-from-array', 'char ca98[4]; ' + B + '{ trace((string)ca98); }')
bad('cond-dynamic-right', XL + B + '{ trace(timestamp ? 1 : xlate<struct xout>((struct xin *)arg0)); }', 'D_OP_DYN')
bad('comma-dynamic-right', XL + B + '{ trace((1, xlate<struct xout>((struct xin *)arg0))); }', 'D_OP_DYN')
ok('cond-charptr-chararray', 'char ca99[4]; ' + B + '{ trace(timestamp ? (char *)arg0 : ca99); }')
ok('cond-charptr-string', B + '{ trace(timestamp ? (char *)arg0 : "a"); }')
bad('cond-charptr-int', B + '{ trace(timestamp ? (char *)arg0 : 1); }', 'D_OP_INCOMPAT')
bad('cond-action-right', B + '{ timestamp ? (void)1 : trace(1); }', 'D_OP_ACT')
bad('cond-action-incompat', B + '{ trace(timestamp ? 1 : trace(1)); }', 'D_OP_INCOMPAT')
ok('pred-retry-var-undef', B + '/(self->pr97 = 1)/ { trace(self->pr97); }')
bad('pred-retry-fails-again', B + '/(self->pr98 = 1)/ { trace(self->pz98); }', 'D_VAR_UNDEF', 'self->pz98')
ok('inline-xlate-struct', XL + 'inline struct xout xo97 = xlate<struct xout>((struct xin *)0); ' + B + '{ trace(xo97.b); }')
ok('prov-redecl-drop-xargs', 'provider pdxq { probe e(int x) : (int x); }; provider pdxq { probe e(int); }; '
    + B + '{ trace(1); }')
# The parse-tree dump shows the flags of uncooked nodes as well.
bad('tree-uncooked-flags', 'int gx97; ' + B + '{ trace((uintptr_t)&gx97); }', 'D_ADDROF_VAR', opts=['tree=1'],
   check=lambda r, K: re.search(r'IDENT gx97 \(type=<-1> attr=\S+ flags=(?!0\))', r['output']) is not None)
ok('tree-provider-redecl', 'provider prx { probe a(); }; provider prx { probe a(); }; ' + B + '{ trace(1); }',
   opts=['tree=1'], check=out_has('PROVIDER prx (decl)', 'PROVIDER prx (redecl)'))
ok('tree-if-no-else', B + '{ if (arg0) trace(1); }', opts=['tree=1'], check=out_has('IF BODY:'))
# A D extern lives in the D (user-model) container: a single backquote is a
# kernel reference.
bad('assign-extern-func', 'int f98(int); ' + B + '{ D`f98 = 1; }', 'D_SYM_BADREF', "user module 'D' symbol 'f98'")
bad('assign-extern-func-user', 'int f99(int); ' + B + '{ D``f99 = 1; }', 'D_OP_ARRFUN', 'userland function')
# Foreign-target operands on the right of every operator class (the type
# check of a bottom operand is deferred to the target).
for cid, body in [('bot-rhs-bits', 'trace(1 & args[0]); trace(1 ^ args[0]);'),
                  ('bot-rhs-shift', 'trace(1 << args[0]); trace(1 >> args[0]);'),
                  ('bot-rhs-mod', 'trace(1 % args[0]);'),
                  ('bot-rhs-mul', 'trace(2 * args[0]); trace(args[0] * args[1]);'),
                  ('bot-rhs-logic', 'trace(1 || args[0]);'),
                  ('bot-rhs-asgn', 'x = 1; x <<= args[0]; x %= args[0]; x /= args[0]; x -= args[0];'),
                  ]:
    bad(cid, 'nosuchvmx:fbt::foo:entry { ' + body + ' trace(nosuchvar97); }', 'D_IDENT_UNDEF', 'nosuchvar97',
        flags=ET | fp.NOLIBS | fp.ZDEFS)
ok('deref-string-array', 'string sa97[2]; ' + B + '{ trace(*sa97); }')
# A foreign args[] element passes the deferred type check of += and is then
# refused only because args[] is not writable.
bad('bot-lhs-asgn-ptr', 'nosuchvmx:fbt::foo:entry { args[0] += (int *)arg0; }', 'D_OP_WRITE', 'writable variable',
    flags=ET | fp.NOLIBS | fp.ZDEFS)
# --- Round 4: dt_pragma.c and dt_lex.l rule outcomes.
bad('line-no-args', '#line\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
ok('line-state-other', '# 5 "x.d" 3\n' + B + '{ trace(1); }')
bad('pragma-attr-noargs', '#pragma D attributes\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('pragma-attr-string-ident', '#pragma D attributes Evolving/Evolving/Common "str"\n' + B + '{ trace(1); }',
    'D_PRAGMA_MALFORM')
bad('pragma-binding-noident', '#pragma D binding "1.0"\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('pragma-binding-string-ident', '#pragma D binding "1.0" "x"\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('pragma-error-int', '#error 42 is the answer\n' + B + '{ trace(1); }', 'D_PRAGERR', 'is the answer')
ok('macro-string-unquoted', B + '{ trace($1); }', args=['p', 'a b'],
   check=lambda r, K: 'a b' in r['stmts'][0]['acts'][0]['difo']['strtab'])
ok('pspec-star', '* { trace(1); }', flags=ET | fp.ZDEFS)
bad('pred-nul-lookahead', B + '/1/\0{ trace(1); }', 'D_SYNTAX', mode='file')
CASES.append(dict(id='type-dash-eof', src='a-b', mode='type', expect=('*', 'syntax error')))
CASES.append(dict(id='type-dash-module-ptr', src='no-such-mod`int *', mode='type', expect=('*', '')))
CASES.append(dict(id='type-dash-long', src='a-' + 'm' * 300 + '`int', mode='type', expect=('*', '')))
CASES.append(dict(id='type-dash-long-after', src='a-b`' + 'i' * 300, mode='type', expect=('*', '')))
ok('scoped-union-tag', 'union su97 { int a; long b; }; ' + B + '{ trace(sizeof (D`union su97)); }', check=const_action(8))
ok('scoped-enum-tag', 'enum se97 { SE97 }; ' + B + '{ trace(sizeof (D`enum se97)); }', check=const_action(4))
bad('scoped-struct-paren', B + '{ trace(sizeof (D`struct)); }', 'D_IDENT_UNDEF')
ok('scoped-base-tabs', B + '{ trace(sizeof ((D`unsigned\t\vshort)arg0)); }', check=const_action(2))
# Any amount of blank space may separate the words of a scoped base type.
ok('scoped-base-long-space', B + '{ trace(sizeof ((D`unsigned' + ' ' * 300 + 'short)arg0)); }', check=const_action(2))
ok('scoped-struct-long-space', 'struct sl97 { int a; long b; }; ' + B + '{ trace(sizeof (D`struct' + ' ' * 300 + 'sl97)); }', check=const_action(16))
# Declarations whose specifier list is only "unsigned"/"signed"/"long"
# followed by a declarator (dt_decl_push/top turn the unnamed decl into int).
ok('decl-unsigned-ptr', 'unsigned *up97; ' + B + '{ trace(sizeof (*up97)); }', check=const_action(4))
ok('decl-long-array', 'long la97[2]; ' + B + '{ trace(sizeof (la97)); }', check=const_action(16))
ok('decl-signed-func-ptr', 'signed (*sfp97)(int); ' + B + '{ trace(sizeof (sfp97)); }', check=const_action(8))
ok('cast-unsigned-ptr', B + '{ trace(sizeof (*(unsigned *)arg0)); }', check=const_action(4))
ok('member-unsigned-bf', 'struct ub97 { unsigned a : 3; long b; }; ' + B + '{ trace(sizeof (struct ub97)); }')
ok('param-unsigned', 'int pu97[unsigned, long]; ' + B + '{ pu97[1, 2] = 3; }')
# A type name that is not yet a variable, followed by "--" or "++", creates
# a variable (id_or_type peeks only at names that are not yet variables).
ok('tname-first-postdec', B + '{ int8_t--; }')
ok('tname-first-postinc', B + '{ uint32_t++; }')
CASES.append(dict(id='type-dash-module-chars', src='a_b.c-d_e.f`int', mode='type', expect=('*', '')))
bad('scoped-struct-long-tag', B + '{ trace(sizeof (D`struct ' + 't' * 300 + ')); }', '*')
CASES.append(dict(id='type-dash-module-chars2', src='a-b_c.d`e_f.g`int', mode='type', expect=('*', '')))
# A cast from a function-typed operand (a D extern function referenced as a
# user symbol) is a scalar cast (K&R A6.6).
ok('cast-from-function', 'int fx97(int); ' + B + '{ trace((uintptr_t)D``fx97); }', flags=ET | fp.UNODEF)
# A cooking error in the actions of a clause with a predicate, other than an
# undefined identifier, is reported directly (no predicate-first retry).
bad('pred-act-cook-error', B + '/arg0/ { trace(timestamp[1]); }', 'D_DEREF_NONPTR')
bad('pragma-attr-string-first', '#pragma D attributes "Evolving" x97\n' + B + '{ trace(1); }', 'D_PRAGMA_MALFORM')
bad('bot-subr-arg', 'nosuchvmx:fbt::foo:entry { trace(strlen(args[0])); trace(nosuchvar97); }', 'D_IDENT_UNDEF',
    'nosuchvar97', flags=ET | fp.NOLIBS | fp.ZDEFS)
# A form feed between the words of a scoped base type (any C blank).
ok('scoped-base-formfeed', B + '{ trace(sizeof ((D`unsigned\fshort)arg0)); }', check=const_action(2))
# A struct member of the D string type is an lvalue string through both . and
# -> (dt_cook_op2: kind ARRAY but dt_node_is_string), so it can be assigned.
ok('string-member-dot', 'struct ss97 { string s; int a; }; struct ss97 g; ' + B + '{ g.s = "x"; trace(g.s); }')
ok('string-member-arrow', 'struct ss98 { string s; int a; }; ' + B +
   '{ this->p = (struct ss98 *)arg0; this->p->s = "y"; trace(this->p->s); }')
