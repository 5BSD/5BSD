# SPDX-License-Identifier: BSD-2-Clause
import tempfile
from pathlib import Path
import unittest
import ntp_version


class VersionInputsTest(unittest.TestCase):
    def test_explicit_serial_and_revision_tokens(self):
        for serial in [1,7,2147483647]:ntp_version.validate(serial,'source.rev-1','ntpd')
        ntp_version.validate(1,'','ntp-keygen')

    def test_invalid_serial_rejected(self):
        for value in [0,-1,2147483648,True,1.5,'7']:
            with self.subTest(value=value),self.assertRaises(ValueError):ntp_version.validate(value,'','ntpd')

    def test_unsafe_revision_and_program_rejected(self):
        for value in ['revision with space','quote"','slash/','backslash'+chr(92),'line'+chr(10)]:
            with self.subTest(value=value),self.assertRaises(ValueError):ntp_version.validate(1,value,'ntpd')
            with self.subTest(program=value),self.assertRaises(ValueError):ntp_version.validate(1,'',value)

    def test_existing_counter_or_source_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            tools={name:root/name for name in ['cat','expr','rm']}
            script=root/'mkver';shell=root/'sh'
            for p in [*tools.values(),script,shell]:p.write_text('declared placeholder')
            output=root/'private/version.c';output.parent.mkdir();counter=output.parent/'.version'
            counter.write_text('existing input must survive')
            with self.assertRaisesRegex(ValueError,'fresh declared'):
                ntp_version.generate(serial=7,cset='',program='ntpd',script=script,shell=shell,
                    tools=tools,libraries=[],output=output,counter=counter,metadata=root/'metadata.json')
            self.assertEqual(counter.read_text(),'existing input must survive')
            self.assertFalse(output.exists())

    def test_no_undeclared_tool_channel(self):
        with self.assertRaisesRegex(ValueError,'exact declared'):
            ntp_version.generate(serial=1,cset='',program='ntpd',script='absent',shell='absent',
                tools={'cat':'absent'},libraries=[],output='absent',counter='absent',metadata='absent')


if __name__=='__main__':unittest.main()
