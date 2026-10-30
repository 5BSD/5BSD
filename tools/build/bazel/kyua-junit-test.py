# SPDX-License-Identifier: BSD-2-Clause
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import xml.etree.ElementTree as ET
from kyua_junit import reconcile

class Results(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.db, self.xml = root/'results.db', root/'test.xml'
        self.db.write_bytes(b'unchanged database fixture')
        self.xml.write_text('<testsuite><testcase classname="fixture" name="case"><system-err>Expected failure result details</system-err></testcase></testsuite>')

    def check(self, rows, version=None):
        with patch('kyua_junit.query', side_effect=[[[3]] if version is None else version, rows]):
            reconcile(self.db,self.xml,'fixture','declared-kyua')

    def test_typed_outcomes(self):
        for outcome, tag in [('passed',None),('failed','failure'),('broken','error'),('skipped','skipped'),('expected_failure','skipped')]:
            self.check([['fixture','case',outcome,'known issue']])
            case=ET.parse(self.xml).find('testcase')
            self.assertEqual(case.findtext('system-err'),'Expected failure result details')
            statuses=[n for n in case if n.tag in ('failure','error','skipped')]
            self.assertEqual([n.tag for n in statuses],[] if tag is None else [tag])
            if outcome=='expected_failure': self.assertEqual(statuses[0].get('message'),'expected_failure: known issue')

    def test_reject_bad_results_without_changing_report(self):
        for row in [['fixture','case','unknown','reason'],['fixture','case','failed',''],['other','case','passed',None],['fixture','other','passed',None]]:
            with self.subTest(row=row):
                before=self.xml.read_bytes()
                with self.assertRaises(ValueError): self.check([row])
                self.assertEqual(self.xml.read_bytes(),before)

    def test_schema(self):
        with self.assertRaisesRegex(ValueError,'schema'): self.check([],version=[[99]])

    def test_duplicate_result(self):
        row=['fixture','case','passed',None]
        with self.assertRaisesRegex(ValueError,'duplicate'): self.check([row,row])

if __name__=='__main__': unittest.main()
