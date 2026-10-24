# SPDX-License-Identifier: BSD-2-Clause
import unittest
from serial_timeline import SerialTimeline


class TimelineTest(unittest.TestCase):
    def test_partial_writes_and_repeated_poll(self):
        timeline = SerialTimeline()
        text = 'boot noise\r\nCONSTRUCTION_PHA'
        timeline.observe(text, 1)
        self.assertEqual(timeline.events, [])
        text += 'SE database-construction\r\n'
        timeline.observe(text, 2)
        timeline.observe(text, 3)
        self.assertEqual(timeline.events, [dict(observed_seconds=2,
            message='CONSTRUCTION_PHASE database-construction')])

    def test_duplicate_markers_are_evidence_not_deduplicated(self):
        timeline = SerialTimeline()
        text = 'RUNTIME_VM_PASS\n'
        timeline.observe(text, 1)
        timeline.observe(text * 2, 2)
        self.assertEqual([event['observed_seconds'] for event in timeline.events], [1, 2])

    def test_failure_and_unfinished_last_line(self):
        timeline = SerialTimeline()
        timeline.observe('RUNTIME_CASE_FAIL /tests/x:y timeout=3\nRUNTIME_VM_FAIL', 4)
        self.assertEqual(len(timeline.events), 1)
        self.assertIn('timeout=3', timeline.events[0]['message'])


if __name__ == '__main__':
    unittest.main()
