# SPDX-License-Identifier: BSD-2-Clause
"""Exercise runner startup/cleanup code without executing setup or any VM.

Some runners execute setup at module scope. Extract only their Popen-through-try
statements from the AST; substitute processes and force collector startup failure.
This is cleanup wiring coverage, not a complete runner or guest test.
"""
import ast
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call

RUNNERS = ('run-installed.py', 'boot-installed.py', 'run-installer.py',
           'run-vm.py', 'run-seed.py')


def startup_block(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    matches = []
    for node in ast.walk(tree):
        body = getattr(node, 'body', None)
        if not isinstance(body, list):
            continue
        for index, statement in enumerate(body):
            if not (isinstance(statement, ast.Assign) and
                    isinstance(statement.value, ast.Call) and
                    isinstance(statement.value.func, ast.Attribute) and
                    isinstance(statement.value.func.value, ast.Name) and
                    statement.value.func.value.id == 'subprocess' and
                    statement.value.func.attr == 'Popen'):
                continue
            end = next((n for n in range(index + 1, len(body))
                        if isinstance(body[n], ast.Try)), None)
            if end is None:
                raise AssertionError('Popen has no following cleanup try: ' + str(path))
            matches.append(ast.Module(body=body[index:end + 1], type_ignores=[]))
    if len(matches) != 1:
        raise AssertionError('expected one runner process block: ' + str(path))
    return compile(matches[0], str(path), 'exec')


class CollectorStartup(unittest.TestCase):
    def test_collector_start_failure_reaps_child(self):
        for name in RUNNERS:
            code = startup_block(Path(__file__).with_name(name))
            for kill_needed in (False, True):
                with self.subTest(runner=name, kill_needed=kill_needed):
                    process = Mock()
                    process.poll.return_value = None
                    process.wait.side_effect = ([subprocess.TimeoutExpired('mock', 10), 0]
                                                if kill_needed else [0])
                    shutdown = Mock()
                    shutdown.start.side_effect = RuntimeError('collector startup failed')
                    namespace = dict(subprocess=SimpleNamespace(
                        Popen=Mock(return_value=process), TimeoutExpired=subprocess.TimeoutExpired),
                        shutdown=shutdown, command=[], cmd=[], output=None,
                        stderr=None, log=None, args=SimpleNamespace(timeout=30),
                        time=SimpleNamespace(monotonic=lambda: 0))
                    with self.assertRaisesRegex(RuntimeError, 'collector startup failed'):
                        exec(code, namespace)
                    process.terminate.assert_called_once_with()
                    if kill_needed:
                        process.kill.assert_called_once_with()
                        self.assertEqual(process.wait.call_args_list,
                                         [call(timeout=10), call()])
                    else:
                        process.kill.assert_not_called()
                        process.wait.assert_called_once_with(timeout=10)


if __name__ == '__main__':
    unittest.main()
