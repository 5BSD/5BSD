# SPDX-License-Identifier: BSD-2-Clause
"""Host-observed serial phase timings; diagnostic only, never a PASS oracle."""


class SerialTimeline:
    def __init__(self):
        self.offset = 0
        self.events = []

    def observe(self, text, elapsed):
        # Consume only complete lines so polling in the middle of a write does
        # not lose or duplicate a marker. Offsets refer to decoded serial text.
        end = text.rfind('\n') + 1
        for line in text[self.offset:end].splitlines():
            if line.startswith(('CONSTRUCTION_PHASE ', 'RUNTIME_CASE_',
                                'RUNTIME_CLEANUP_', 'RUNTIME_VM_')):
                self.events.append({'observed_seconds': round(elapsed, 3),
                                    'message': line})
        self.offset = max(self.offset, end)
