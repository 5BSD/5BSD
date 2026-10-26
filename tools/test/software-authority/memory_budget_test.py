# SPDX-License-Identifier: BSD-2-Clause
"""Guard declared RAM arguments; does not measure memory or prove VM boot."""
import ast
from pathlib import Path
import unittest

class MemoryBudgetTests(unittest.TestCase):
    def test_vm_commands_fit_two_gib(self):
        checked = set()
        for path in Path(__file__).resolve().parent.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.List):
                    continue
                for index, item in enumerate(node.elts):
                    if not isinstance(item, ast.Constant) or item.value != '-m':
                        continue
                    with self.subTest(runner=path.name):
                        self.assertLess(index + 1, len(node.elts))
                        self.assertEqual(str(ast.literal_eval(node.elts[index + 1])), '2048')
                        checked.add(path.name)
        self.assertTrue({'boot-installed.py', 'run-installed.py',
            'run-installer.py', 'run-vm.py', 'run-seed.py'} <= checked)

if __name__ == '__main__':
    unittest.main()
