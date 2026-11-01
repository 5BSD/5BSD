# SPDX-License-Identifier: BSD-2-Clause
"""Explicit uniform emulation deadlines, separate from source ATF metadata."""


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'timeout_scale'} or
            type(value['timeout_scale']) is not int or not 1 <= value['timeout_scale'] <= 20):
        raise ValueError('checker profile requires only integer timeout_scale 1..20')
    return dict(value)


def deadline(source_timeout, profile):
    if type(source_timeout) is not int or not 1 <= source_timeout <= 3600:
        raise ValueError('source ATF timeout must be an integer 1..3600')
    return source_timeout * validate(profile)['timeout_scale']
