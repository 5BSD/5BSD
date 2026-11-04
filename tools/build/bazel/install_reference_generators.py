# SPDX-License-Identifier: BSD-2-Clause
"""Bind original Make generator executables to passed native references."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
from install_reference_libraries import digest, safe_path, verify


def load(config_path, execution_architecture, source_root, compiler):
    config_path = safe_path(str(config_path))
    before = digest(config_path)
    value = json.loads(config_path.read_text())
    if not isinstance(value, dict) or set(value) != {"format", "generators"} or type(value["format"]) is not int or value["format"] != 1:
        raise ValueError("exact original generator input format 1 required")
    if not isinstance(value["generators"], dict) or not value["generators"]:
        raise ValueError("nonempty generator inventory required")
    bindings = {str(config_path): before}
    records = {}
    for variable, item in value["generators"].items():
        if not re.fullmatch(r"MAKE_[A-Z][A-Z0-9_]*", variable):
            raise ValueError("generator override must name a MAKE_ command variable")
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
        selected = safe_path(environment.get("compiler_selected"), True)
        compiler_sha = digest(compiler)
        if digest(selected) != compiler_sha or not any(
                Path(name).is_file() and selected.samefile(name) and expected == compiler_sha
                for name, expected in environment.get("input_sha256", {}).items()):
            raise ValueError("generator compiler differs from selected native compiler")
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
        records[variable] = dict(receipt=str(reference), receipt_sha256=item["receipt_sha256"], artifact=str(artifact),
                                 artifact_sha256=item["artifact_sha256"], component=str(component))
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
