#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Unit tests for gotemplate.py and fidlgen_natural.py's Go-compatible parts.

Expected strings are what Go's text/template and regexp produce for the same
input (the semantics fidlgen_cpp's output depends on).
"""
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fidlgen_natural as natural  # noqa: E402
import gotemplate  # noqa: E402


def run(source, data=None, funcs=None, name='T'):
    t = gotemplate.Templates(funcs)
    t.parse('test', '{{- define "T" }}' + source + '{{ end }}')
    return t.execute(name, data)


class Object:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def Method(self):
        return 'm:' + self.Name


class TemplateTest(unittest.TestCase):
    def test_trim_markers(self):
        self.assertEqual(run('a  {{- "b" -}}  \n c'), 'abc')
        self.assertEqual(run('a {{ "b" }} c'), 'a b c')
        # "{{-x" without the space is not a trim marker in Go; numbers are.
        self.assertEqual(run('a {{-3}} c'), 'a -3 c')

    def test_comments(self):
        self.assertEqual(run('a {{/* x */}} b'), 'a  b')
        self.assertEqual(run('a {{- /* x */ -}} b'), 'ab')

    def test_range_and_variables(self):
        self.assertEqual(
            run('{{ range $i, $v := . }}{{ if $i }}, {{ end }}{{ $i }}={{ $v }}'
                '{{ end }}', ['x', 'y']), '0=x, 1=y')
        self.assertEqual(run('{{ range . }}{{ . }}{{ else }}none{{ end }}', []),
                         'none')
        self.assertEqual(run('{{ $x := "a" }}{{ range . }}{{ $x }}{{ . }}{{ end }}',
                             [1, 2]), 'a1a2')

    def test_dollar_is_template_data(self):
        self.assertEqual(run('{{ range .Items }}{{ $.Name }}{{ end }}',
                             Object(Name='n', Items=[1, 2])), 'nn')

    def test_if_else_chain(self):
        source = '{{ if eq . 1 }}one{{ else if eq . 2 }}two{{ else }}many{{ end }}'
        self.assertEqual([run(source, n) for n in (1, 2, 3)],
                         ['one', 'two', 'many'])

    def test_truth_and_printing(self):
        self.assertEqual(run('{{ if .A }}y{{ else }}n{{ end }}', Object(A=[])), 'n')
        self.assertEqual(run('{{ if .A }}y{{ else }}n{{ end }}', Object(A=0)), 'n')
        self.assertEqual(run('{{ if .A }}y{{ end }}', Object(A=Object())), 'y')
        self.assertEqual(run('{{ .A }} {{ not .A }}', Object(A=True)),
                         'true false')

    def test_methods_pipelines_and_funcs(self):
        self.assertEqual(run('{{ .Method }}', Object(Name='q')), 'm:q')
        self.assertEqual(run('{{ .N | printf "%#x" }}', Object(N=255)), '0xff')
        self.assertEqual(run('{{ printf "%#x" -1 }}'), '-0x1')
        self.assertEqual(run('{{ Add 1 2 }} {{ len . }}', [0, 0],
                             {'Add': lambda a, b: a + b}), '3 2')
        self.assertEqual(run('{{ K.Struct }}', None, {'K': lambda: Object(Struct='s')}),
                         's')
        self.assertEqual(run('{{ (index . 1) }}', ['a', 'b']), 'b')

    def test_template_call(self):
        t = gotemplate.Templates()
        t.parse('x', '{{ define "A" }}[{{ . }}]{{ end }}'
                     '{{ define "B" }}{{ template "A" .X }}{{ end }}')
        self.assertEqual(t.execute('B', Object(X=7)), '[7]')

    def test_missing_field_is_an_error(self):
        with self.assertRaises(gotemplate.TemplateError):
            run('{{ .Nope }}', Object())


class NaturalTest(unittest.TestCase):
    def test_remove_empty_blocks(self):
        # Runs of blank lines collapse to one.  At the end of the text Go's
        # ReplaceAll also replaces the empty match after the last newline
        # (it abuts no earlier match), so fidlgen output ends in "\n\n".
        self.assertEqual(natural.remove_empty_blocks('a\n\n\n  \nb\n'),
                         'a\n\nb\n\n')
        self.assertEqual(natural.remove_empty_blocks('a\n\n'), 'a\n\n')
        self.assertEqual(natural.remove_empty_blocks(
            'namespace a {\n}  // namespace a\nx'), '\nx')

    def test_names(self):
        self.assertEqual(natural.to_snake_case('HTTPServer2Go'), 'http_server2_go')
        self.assertEqual(natural.to_upper_camel_case('get_protocol_info'),
                         'GetProtocolInfo')
        self.assertEqual(natural.const_name_to_k_camel_case('READ_ONLY'),
                         'kReadOnly')
        self.assertEqual(natural.member_names('struct', 'switch').Unified.Name(),
                         'switch_')


if __name__ == '__main__':
    unittest.main()
