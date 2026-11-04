# SPDX-License-Identifier: BSD-2-Clause
"""Resolve a hash-verified immutable payload captured by native qualification."""
import hashlib
import json
from pathlib import Path
import re
import stat


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(value):
    if (not isinstance(value, str) or not value or value.startswith('/') or
            any(ord(c) < 32 or ord(c) == 127 for c in value) or
            any(p in ('', '.', '..') for p in value.split('/'))):
        raise ValueError('canonical relative artifact path required')
    return Path(value)


def resolve_many(qualification, selections):
    """Resolve a nonempty batch against one verified receipt/manifest snapshot.

    Every payload is still independently checked. Metadata is parsed once, and
    rechecked after selection so concurrent metadata changes cannot be rebound.
    No process-global cache or mutable bazel-bin lookup is used.
    """
    selections = list(selections)
    if not selections:
        raise ValueError('at least one artifact selection required')
    root = Path(qualification).resolve(strict=True)
    receipt_path = root / 'receipt.json'
    receipt_bytes = receipt_path.read_bytes()
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    receipt = json.loads(receipt_bytes)
    if receipt.get('status') != 'passed':
        raise ValueError('completed native qualification required')
    capture = root / 'artifacts'
    if capture.is_symlink() or not capture.is_dir():
        raise ValueError('regular qualification capture directory required')
    manifest_path = root / relative(receipt['artifacts']['manifest'])
    if (not manifest_path.resolve(strict=True).is_relative_to(capture) or
            manifest_path.is_symlink()):
        raise ValueError('qualification artifact manifest mismatch or escape')
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha256 != receipt['artifacts']['sha256']:
        raise ValueError('qualification artifact manifest mismatch or escape')
    manifest = json.loads(manifest_bytes)
    if type(manifest.get('format')) is not int or manifest['format'] != 1:
        raise ValueError('unsupported artifact manifest format')
    result = [_resolve_selection(root, capture, manifest, receipt_sha256,
              manifest_sha256, target, suffix) for target, suffix in selections]
    if (digest(receipt_path) != receipt_sha256 or
            digest(manifest_path) != manifest_sha256):
        raise ValueError('qualification capture metadata changed during resolution')
    return result


def resolve(qualification, target, output_suffix):
    """Resolve one captured output; preserve the same checks as batch inspection."""
    return resolve_many(qualification, [(target, output_suffix)])[0]


def _resolve_selection(root, capture, manifest, receipt_sha256, manifest_sha256, target, output_suffix):
    """Return the captured file and its receipt/manifest/content binding.

    Output selection is mandatory even for one-output targets. Duplicate target
    configurations and ambiguous suffixes are errors, never first-match choices.
    """
    if not target or not output_suffix:
        raise ValueError('explicit target and output suffix required')
    if any(ord(c) < 32 or ord(c) == 127 for c in target + output_suffix):
        raise ValueError('target/output selection contains a control character')
    selected = [entry for entry in manifest['targets']
                if entry['target']['label'] == target]
    if len(selected) != 1:
        raise ValueError('one target configuration required: ' + target)
    outputs = [entry for entry in selected[0]['outputs']
               if entry['name'].endswith(output_suffix)]
    if len(outputs) != 1:
        raise ValueError('one selected captured output required: ' + target)
    entry = outputs[0]
    source = capture / relative(entry['file'])
    if (not source.resolve(strict=True).is_relative_to(capture) or
            not stat.S_ISREG(source.lstat().st_mode)):
        raise ValueError('captured artifact is not a regular contained file')
    expected = entry['sha256']
    if (not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected) or
            type(entry['size']) is not int or entry['size'] < 0 or
            source.stat().st_size != entry['size'] or digest(source) != expected):
        raise ValueError('captured artifact content mismatch')
    return source, {'source': 'qualification-capture', 'qualification': str(root),
                    'receipt_sha256': receipt_sha256,
                    'manifest_sha256': manifest_sha256, 'target': target,
                    'output_name': entry['name'], 'sha256': expected}
