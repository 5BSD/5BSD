# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Bind original Make generator executables to passed native references."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
from install_reference_libraries import digest, reference_compiler, safe_path, verify
from install_reference_options import generator_command_variable


def load(config_path, execution_architecture, source_root):
    config_path = safe_path(str(config_path))
    before = digest(config_path)
    value = json.loads(config_path.read_text())
    if not isinstance(value, dict) or set(value) != {"format", "generators"} or type(value["format"]) is not int or value["format"] != 1:
        raise ValueError("exact original generator input format 1 required")
    if not isinstance(value["generators"], dict) or not value["generators"]:
        raise ValueError("nonempty generator inventory required")
    bindings = {str(config_path): before}
    records = {}
    execution_compiler_sha = None
    for variable, item in value["generators"].items():
        if not generator_command_variable(variable):
            raise ValueError("generator override must name an uppercase command variable, excluding compiler, path and configuration controls")
        if not isinstance(item, dict) or set(item) != {"receipt", "receipt_sha256", "artifact", "artifact_sha256"}:
            raise ValueError("exact original generator receipt/artifact binding required")
        reference = safe_path(item["receipt"], True)
        if digest(reference) != item["receipt_sha256"]:
            raise ValueError("generator receipt digest mismatch")
        receipt = json.loads(reference.read_text())
        if (type(receipt.get("format")) is not int or receipt.get("format") != 1 or receipt.get("status") != "passed" or
                receipt.get("scope") != "native-amd64-Make-installation-reference" or
                receipt.get("target_architecture") != execution_architecture):
            raise ValueError("generator must pass as an original native Make reference")
        component = safe_path(receipt.get("component"))
        if component == source_root or not component.is_relative_to(source_root):
            raise ValueError("generator component differs from source tree")
        environment = receipt.get("environment", {})
        # Execution tools bind their own compiler, independently of the target.
        selected, compiler_sha = reference_compiler(environment)
        if execution_compiler_sha is not None and compiler_sha != execution_compiler_sha:
            raise ValueError("generator execution compiler identities differ")
        execution_compiler_sha = compiler_sha
        relative = item["artifact"]
        if (not isinstance(relative, str) or not relative or PurePosixPath(relative).is_absolute() or
                ".." in relative.split("/") or str(PurePosixPath(relative)) != relative):
            raise ValueError("canonical relative generator artifact required")
        unresolved = reference.parent / relative
        artifact = safe_path(str(unresolved), True)
        if (artifact != unresolved or not artifact.is_relative_to(reference.parent / "objects" / str(component).lstrip("/")) or
                not stat.S_ISREG(artifact.lstat().st_mode) or not os.access(artifact, os.X_OK)):
            raise ValueError("regular executable in original component object tree required")
        if digest(artifact) != item["artifact_sha256"]:
            raise ValueError("generator artifact digest mismatch")
        with artifact.open("rb") as stream:
            header = stream.read(20)
        machine = {"amd64": 62, "aarch64": 183, "riscv64": 243}[execution_architecture]
        if (header[:6] != b"\x7fELF\x02\x01" or
                int.from_bytes(header[16:18], "little") not in (2, 3) or
                int.from_bytes(header[18:20], "little") != machine):
            raise ValueError("generator must be an execution-platform ELF executable")
        records[variable] = dict(receipt=str(reference), receipt_sha256=item["receipt_sha256"], artifact=str(artifact),
                                 artifact_sha256=item["artifact_sha256"], component=str(component),
                                 execution_compiler=str(selected), execution_compiler_sha256=compiler_sha)
        bindings.update({str(reference): item["receipt_sha256"], str(artifact): item["artifact_sha256"], str(selected): compiler_sha})
    verify(bindings)
    return records, bindings


def audit_recipes(objects, generators):
    """Require each bound executable as an actual original metadata recipe command.

    Metadata without filemon records recipes, not observed exec events. Only
    direct absolute executable commands are supported; wrappers are not guessed.
    """
    records = {name: [] for name in generators}
    for metadata in sorted(objects.rglob("*.meta")):
        lines = metadata.read_text().splitlines()
        for line in lines:
            if not line.startswith("CMD ") or not line[4:].strip():
                continue
            argv = shlex.split(line[4:])
            for name, item in generators.items():
                if argv[0] == item["artifact"]:
                    records[name].append(dict(metadata=str(metadata), metadata_sha256=digest(metadata), command=line[4:]))
    if any(not values for values in records.values()):
        raise ValueError("bound generator missing from completed original recipes")
    return records
