# SPDX-License-Identifier: BSD-2-Clause
"""Run the maintained NTP version generator with an explicit private counter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def validate(serial, cset, program):
    if type(serial) is not int or not 1 <= serial <= 2147483647:
        raise ValueError('NTP version serial must be an integer 1..2147483647')
    if not re.fullmatch(r'[A-Za-z0-9_.+-]*', cset):
        raise ValueError('NTP CSET must be an explicit version token')
    if not re.fullmatch(r'[A-Za-z0-9_.+-]+', program):
        raise ValueError('NTP program must be a version token')


def generate(*, serial, cset, program, script, shell, tools, libraries, output, counter, metadata):
    validate(serial, cset, program)
    if set(tools) != {'cat', 'expr', 'rm'}:
        raise ValueError('exact declared NTP generator tools required')
    script, shell = Path(script).resolve(strict=True), Path(shell).resolve(strict=True)
    tools = {name: Path(path).resolve(strict=True) for name, path in tools.items()}
    if any(path.name != name for name, path in tools.items()):
        raise ValueError('declared tool basename mismatch')
    output, counter, metadata = [Path(p).absolute() for p in [output, counter, metadata]]
    if output.name != 'version.c' or counter.name != '.version' or output.parent != counter.parent:
        raise ValueError('private version.c and .version sibling outputs required')
    if any(path.exists() or path.is_symlink() for path in [output, counter, metadata]):
        raise ValueError('fresh declared NTP version outputs required')
    output.parent.mkdir(parents=True, exist_ok=True)
    # Both seed and increment occur in this action's outputs, never source inputs.
    counter.write_text(str(serial - 1) + '\n')
    environment = {'LC_ALL':'C', 'PATH':os.pathsep.join(dict.fromkeys(str(p.parent) for p in tools.values())),
                   'CSET':cset, 'ECHO':'echo'}
    if libraries:
        environment['LD_LIBRARY_PATH']=os.pathsep.join(dict.fromkeys(str(Path(p).resolve(strict=True).parent) for p in libraries))
    subprocess.run([str(shell), '-e', str(script), program], cwd=output.parent,
                   env=environment, check=True)
    if counter.read_text() != str(serial) + '\n' or not output.is_file():
        raise ValueError('maintained generator failed declared counter/output contract')
    metadata.write_text(json.dumps({'format':1,'program':program,'serial':serial,'cset':cset,
        'generator_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
        'source_sha256':hashlib.sha256(output.read_bytes()).hexdigest()},sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial',type=int,required=True)
    parser.add_argument('--cset',default='')
    parser.add_argument('--program',required=True)
    for name in ['script','shell','output','counter','metadata']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--tool',action='append',default=[])
    parser.add_argument('--library',type=Path,action='append',default=[])
    args=parser.parse_args()
    tools={}
    for value in args.tool:
        name, separator, path=value.partition('=')
        if not separator or name in tools:parser.error('distinct explicit name=tool paths required')
        tools[name]=Path(path)
    generate(serial=args.serial,cset=args.cset,program=args.program,script=args.script,
        shell=args.shell,tools=tools,libraries=args.library,output=args.output,
        counter=args.counter,metadata=args.metadata)


if __name__=='__main__':main()
