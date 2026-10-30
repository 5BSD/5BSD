#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise maintained ATF Make linkage for dynamic and forced-static tests."""
from pathlib import Path
import subprocess
import tempfile
import unittest

class FrameworkMake(unittest.TestCase):
    def check_mode(self, assignment, static):
        include=Path(__file__).resolve().parents[3]/'share/mk/atf.test.mk'
        text='''__<bsd.test.mk>__:
ATF_TESTS_C= c_test
ATF_TESTS_CXX= cxx_test
LIBATF_C= /declared/libprivateatf-c.a
LIBATF_CXX= /declared/libprivateatf-c++.a
LDADD_atf_c= -lprivateatf-c
LDADD_atf_cxx= -lprivateatf-c++ -lprivateatf-c
'''+assignment+'\n.include "'+str(include)+'"\n'
        keys=['LDADD.c_test','LDADD.cxx_test','DPADD.c_test','DPADD.cxx_test','TEST_FRAMEWORK_LIBS.c_test','TEST_FRAMEWORK_LIBS.cxx_test']
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'Makefile';f.write_text(text)
            result=subprocess.check_output(['/usr/bin/make','-r','-f',str(f),*[v for k in keys for v in ('-v',k)]],text=True)
        values=[line.split() for line in result.splitlines()]
        self.assertEqual(values[0],['/declared/libprivateatf-c.a'] if static else ['-lprivateatf-c'])
        self.assertEqual(values[1],['/declared/libprivateatf-c++.a','/declared/libprivateatf-c.a'] if static else ['-lprivateatf-c++','-lprivateatf-c','-lprivateatf-c'])
        self.assertEqual(values[2],['/declared/libprivateatf-c.a'])
        self.assertEqual(values[3],['/declared/libprivateatf-c++.a','/declared/libprivateatf-c.a'])
        self.assertEqual(values[4:], [['atf_c'],['atf_cxx','atf_c']])
    def test_dynamic(self):self.check_mode('',False)
    def test_global_static(self):self.check_mode('LDFLAGS= -static',True)
    def test_per_program_static(self):self.check_mode('LDFLAGS.c_test= -static\nLDFLAGS.cxx_test= -static',True)

if __name__=='__main__':unittest.main()
