# SPDX-License-Identifier: BSD-2-Clause
"""Translate declared Make test policy without evaluating arbitrary Lua or shell."""
import json
import re
import shlex


def metadata(text):
    result={};decoder=json.JSONDecoder();offset=0
    while offset<len(text):
        match=re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*',text[offset:])
        if not match:
            if not text[offset:].strip():break
            raise ValueError('unsupported Kyua metadata assignment')
        key=match[1]
        if key=='name':raise ValueError('test metadata cannot override program identity')
        offset+=match.end()
        try:value,end=decoder.raw_decode(text,offset)
        except ValueError as error:raise ValueError('Kyua metadata requires a literal string, integer or boolean') from error
        literal=text[offset:end]
        if literal.startswith('"'):
            index=1
            while index<len(literal)-1:
                if literal[index]=='\\':
                    index+=1
                    if literal[index] not in '\"\\bfnrt':
                        raise ValueError('metadata escape requires explicit Lua support')
                index+=1
        if type(value) not in (str,int,bool):raise ValueError('unsupported Kyua metadata value type')
        if isinstance(value,str) and not value.isascii():raise ValueError('non-ASCII Kyua metadata requires explicit Lua encoding support')
        if end<len(text) and not text[end].isspace():raise ValueError('metadata assignments must be whitespace separated')
        # Like the generated Lua table, program-specific assignments override
        # earlier global assignments with the same property name.
        result[key]=value;offset=end
    return result


def translate(policy):
    keys={'metadata','environment','default_library_paths','kyuafile','suite'}
    if not isinstance(policy,dict) or set(policy)!=keys or any(not isinstance(v,str) for v in policy.values()):
        raise ValueError('complete exported test policy required; regenerate the plan')
    if policy['kyuafile'].lower()!='auto':raise ValueError('custom or disabled Kyuafile requires explicit runner support')
    if not policy['suite'] or not policy['suite'].isascii():raise ValueError('nonempty ASCII test suite required')
    env={}
    for token in shlex.split(policy['environment']):
        key,separator,value=token.partition('=')
        if not separator or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key):raise ValueError('literal test environment assignments required')
        if key.startswith('LD_') and key!='LD_LIBRARY_PATH':raise ValueError('loader override requires explicit native policy')
        env[key]=value
    defaults=shlex.split(policy['default_library_paths'])
    if not defaults or env.get('LD_LIBRARY_PATH','').split(':')!=defaults:
        raise ValueError('custom test library search requires declared runtime inputs')
    # The source framework's default installed-library lookup is represented by
    # native dependency artifacts and test-only RPATH, not host LD_LIBRARY_PATH.
    del env['LD_LIBRARY_PATH']
    properties=metadata(policy['metadata'])
    exclusive=properties.get('is_exclusive',False)
    if type(exclusive) is not bool:
        raise ValueError('is_exclusive requires a boolean')
    # Separate Kyua processes cannot coordinate across Bazel test targets.
    # Preserve Kyua policy and also use Bazel's scheduler-level exclusion.
    return dict(metadata=properties,environment=env,suite=policy['suite'],
        translated_library_paths=defaults,tags=['exclusive'] if exclusive else [])
