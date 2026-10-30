#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compatibility entrypoint for the maintained build backend inventory audit."""
import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / 'build/capimage/inventory_audit.py'
_spec = importlib.util.spec_from_file_location('inventory_audit_backend', _path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
backend = _module.backend
report = _module.report
state_inventory_review = _module.state_inventory_review
main = _module.main

if __name__ == '__main__':
    main()
