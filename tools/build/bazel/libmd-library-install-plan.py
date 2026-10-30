#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Export bounded native library/program install policy and reconcile an actual Make stage.

Reads maintained metadata, never recipes. No compilation, installation or package
creation is performed. Unsupported payload classes fail before output creation.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex

import libmd_environment
import shared_link_script
import configuration_install
import file_install
import install_sources
from libmd_environment import BuildEnvironment, digest

INSTALL_CONFIG = ['NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes']
NAMES = '''PROG PROGS PROGNAME BINDIR BINOWN BINGRP BINMODE LINKOWN LINKGRP LINKMODE LINKTAGS
SCRIPTS INTERNALPROG PRECIOUSPROG _CAPIMAGE_INSTALL
LIB LIB_PRIVATE _STATICLIB_SUFFIX _LIBS SHLIB_NAME SHLIB_NAME_FULL SHLIB_LINK SONAME
_LIBDIR _SHLIBDIR MK_INSTALLLIB MK_DEBUG_FILES DEBUGFILE DEBUGFILEDIR DEBUGOWN DEBUGGRP DEBUGMODE
LIBOWN LIBGRP LIBMODE LIB_TAG_ARGS DEV_TAG_ARGS DBG_TAG_ARGS TAG_ARGS STRIP INSTALL_PIC_ARCHIVE
PCFILES .OBJDIR LIBDATADIR LINKS SYMLINKS INCSLINKS FILES CONFS NLS FILESGROUPS CONFGROUPS INCSGROUPS MANGROUPS
MANDIR MANSUBDIR MCOMPRESS_EXT MCOMPRESS_CMD MK_MANCOMPRESS MANFILTER MANBUILDCAT NO_MLINKS
MK_INCLUDES MK_MAN MK_CTF SHLIB_LDSCRIPT SHLIB_LDSCRIPT_LINKS STATIC_LDSCRIPT INTERNALLIB LIBRARIES_ONLY
_INSTALLFLAGS _SHLINSTALLFLAGS _SHLINSTALLSYMLINKFLAGS .PATH PACKAGE
_SYMLINKOWN _SYMLINKGRP _SYMLINKMODE RSYMLINK SYMLINK LSYMLINK INSTALL INSTALL_LIBSYMLINK INSTALL_SYMLINK MANHRDLINK MANOWN MANGRP MANMODE'''.split()


def path(value, existing=True):
    if not value.is_absolute() or any(ord(c) < 32 or c == '$' for c in str(value)):
        raise ValueError('absolute path without controls or Make expansion required')
    return value.resolve(strict=existing)


def query(env, names):
    rows = env.query([a for name in names for a in ['-V', name]], extra=INSTALL_CONFIG).splitlines()
    if len(rows) != len(names):
        raise ValueError('ambiguous Make metadata')
    return dict(zip(names, rows))


def query_many(env, names):
    # Bound command size while avoiding a new Make parse for every header.
    names = list(dict.fromkeys(names))
    values = {}
    for start in range(0, len(names), 128):
        values.update(query(env, names[start:start + 128]))
    return values


def tags(value):
    fields = shlex.split(value)
    if len(fields) != 2 or fields[0] != '-T':
        raise ValueError('unsupported package tag arguments: ' + value)
    return sorted(set(fields[1].split(',')))


def absolute(value):
    p = PurePosixPath(value)
    if not p.is_absolute() or '..' in p.parts or any(c.isspace() or c == '\\' for c in value):
        raise ValueError('unsupported destination: ' + value)
    return str(p)


def basename(value):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', value):
        raise ValueError('unsupported artifact name: ' + value)
    return value



def configured_symlinks(metadata):
    fields = shlex.split(metadata['SYMLINKS'])
    if len(fields) % 2:
        raise ValueError('odd symbolic link mapping')
    if not fields:
        return []
    options = ['-l', 's', '-o', metadata['_SYMLINKOWN'], '-g', metadata['_SYMLINKGRP'], '-m', metadata['_SYMLINKMODE']]
    if shlex.split(metadata['SYMLINK']) != options or shlex.split(metadata['INSTALL_SYMLINK']) != shlex.split(metadata['INSTALL']) + options:
        raise ValueError('unsupported symbolic link installation command')
    result = []
    for target, destination in zip(fields[::2], fields[1::2]):
        # Preserve the literal target: bsd.links.mk does not relativize it.
        if not target or any(ord(c) < 32 or c.isspace() or c in '$\\' for c in target):
            raise ValueError('unsupported symbolic link target')
        result.append((target, absolute(destination)))
    return result



def shared_script_aliases(metadata, link_script):
    aliases = shlex.split(metadata['SHLIB_LDSCRIPT_LINKS'])
    if not aliases:
        return []
    if not link_script or not metadata['SHLIB_NAME']:
        raise ValueError('shared linker-script aliases require an installed shared script')
    target = basename(metadata['SHLIB_LINK'])
    if len(aliases) != len(set(aliases)) or target in aliases:
        raise ValueError('duplicate or self-referencing linker-script alias')
    options = ['-l', 's', '-o', metadata['LIBOWN'], '-g', metadata['LIBGRP'], '-m', metadata['LIBMODE']]
    if (shlex.split(metadata['LSYMLINK']) != options or
            shlex.split(metadata['INSTALL_LIBSYMLINK']) != shlex.split(metadata['INSTALL']) + options):
        raise ValueError('unsupported library symlink installation command')
    return [(target, absolute(metadata['_LIBDIR'] + '/' + basename(name))) for name in aliases]


def shared_file_flags(value):
    options = shlex.split(value)
    if options == ['-S']:
        return None
    if options in (['-fschg', '-S'], ['-S', '-fschg']):
        return 'schg'
    raise ValueError('unqualified shared-library installation flags')


def installed_pic_archive(metadata, defined):
    if defined not in ('yes', 'no'):
        raise ValueError('explicit INSTALL_PIC_ARCHIVE definition state required')
    if defined == 'no' or not metadata['LIB']:
        return None
    # Match bsd.lib.mk's install recipe, including its identity check against
    # configured build outputs. MK_INSTALLLIB controls only the regular archive.
    name = 'lib' + basename(metadata['LIB']) + '_pic.a'
    if name not in shlex.split(metadata['_LIBS']):
        raise ValueError('installed PIC archive absent from configured outputs')
    return name


def read_metalog(file):
    result = {}
    for line in file.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        if '\\' in line:
            raise ValueError('escaped METALOG syntax requires explicit support')
        fields = shlex.split(line)
        if fields[0] != '.' and not fields[0].startswith('./'):
            raise ValueError('unsupported METALOG record')
        name = '/' if fields[0] == '.' else absolute('/' + fields[0][2:])
        attrs = dict(field.split('=', 1) for field in fields[1:])
        if name in result and attrs.get('type') != 'dir' and result[name] != attrs:
            raise ValueError('conflicting METALOG entry: ' + name)
        result[name] = attrs
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'profile', 'library-plan', 'reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--component', type=Path, default=Path('lib/libmd'))
    parser.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    args = parser.parse_args()
    src, objtop, profile, make, planfile, reference = [path(p) for p in
        (args.src, args.objtop, args.profile, args.make, args.library_plan, args.reference)]
    output = path(args.output, False)
    if (args.output.is_symlink() or output.exists() or output == Path('/usr/obj') or
            not output.is_relative_to('/usr/obj') or output.is_relative_to(src) or
            src.is_relative_to(output) or objtop.is_relative_to(output) or
            output.is_relative_to(objtop / 'tmp') or reference.is_relative_to(output)):
        parser.error('fresh private output below /usr/obj required')
    if args.component.is_absolute() or '..' in args.component.parts:
        raise ValueError('component must be source-relative')
    component = (src / args.component).resolve(strict=True)
    if not component.is_relative_to(src):
        raise ValueError('component escapes source')
    env = BuildEnvironment(src, objtop, profile, make, component)
    closure = env.capture_closure(extra=INSTALL_CONFIG)
    metadata = query(env, NAMES)
    pic_defined = env.query(['-V', '${INSTALL_PIC_ARCHIVE:Dyes:Uno}'], extra=INSTALL_CONFIG).strip()
    metadata['INSTALL_PIC_ARCHIVE_DEFINED'] = pic_defined
    plan = json.loads(planfile.read_text())
    component_inputs = {}
    if 'components' in plan:
        if plan.get('status') != 'configured':
            raise ValueError('configured component plan required')
        matches = [c for c in plan['components'] if c['component'] == str(args.component)]
        if len(matches) != 1 or not (matches[0]['metadata']['LIB'] or matches[0]['metadata']['PROG']):
            raise ValueError('exactly one library/program component required')
        selected = matches[0]
        if any(selected['metadata'][k] != metadata[k] for k in ('LIB','PROG')):
            raise ValueError('library identity changed')
        component_inputs = dict(plan['input_sha256'])
        for name, expected in component_inputs.items():
            if digest(Path(name)) != expected:
                raise ValueError('component plan input changed: '+name)
        plan = dict(plan, source_root=str(src),
            source_sha256={s['path']:s['sha256'] for s in selected['sources'] if s['resolution']=='source'},
            source_origins={s['path']:str(src/s['path']) for s in selected['sources'] if s['resolution']=='source'},
            generators=selected.get('generators', []), nls_generation=selected.get('nls_generation'), shared_link_script=selected.get('shared_link_script'))
    elif args.component != Path('lib/libmd'):
        raise ValueError('legacy library plan supports libmd only')
    if (plan['source_root'] != str(src) or plan['build_environment']['objtop'] != str(objtop) or
            plan['build_environment']['input_sha256'].get(str(profile)) != digest(profile)):
        raise ValueError('library plan does not match selected source/world/profile')
    inputs = {str(p): digest(p) for p in [Path(__file__).resolve(),
        Path(libmd_environment.__file__).resolve(), planfile, reference/'METALOG', reference/'receipt.json']}
    inputs.update(component_inputs)
    reference_receipt = json.loads((reference/'receipt.json').read_text())
    if (reference_receipt.get('status') != 'passed' or
            reference_receipt.get('metalog_sha256') != inputs[str(reference/'METALOG')] or
            reference_receipt.get('component') != str(component) or
            reference_receipt.get('environment',{}).get('objtop') != str(objtop) or
            reference_receipt.get('environment',{}).get('input_sha256',{}).get(str(profile)) != digest(profile)):
        raise ValueError('reference receipt does not authenticate selected METALOG/component')
    for relative, expected in plan['source_sha256'].items():
        origin = Path(plan['source_origins'][relative])
        if digest(origin) != expected:
            raise ValueError('library source changed since plan: ' + str(origin))
        inputs[str(origin)] = expected
    inputs[str(Path(shared_link_script.__file__).resolve())]=digest(Path(shared_link_script.__file__))
    link_script=shared_link_script.export(src,component,metadata,inputs)
    if link_script!=plan.get('shared_link_script'):
        raise ValueError('shared-library script differs from component plan')
    unsupported = ['INCSLINKS',
                'STATIC_LDSCRIPT','INTERNALLIB','LIBRARIES_ONLY',
                'MANFILTER','MANBUILDCAT','NO_MLINKS','PROGS','SCRIPTS','INTERNALPROG','PRECIOUSPROG','_CAPIMAGE_INSTALL']
    if metadata['LIB']:
        unsupported.append('LINKS')
    for key in unsupported:
        if metadata[key]:
            raise ValueError('unsupported installation policy: ' + key)
    if metadata['MK_CTF'] != 'no' or shlex.split(metadata['STRIP']) not in ([], ['-s']):
        raise ValueError('unsupported CTF/strip transformation')
    for key in ['MK_INSTALLLIB','MK_DEBUG_FILES','MK_INCLUDES','MK_MAN','MK_MANCOMPRESS']:
        if metadata[key] not in ('yes','no'):
            raise ValueError('unsupported boolean install policy: ' + key)
    expected_flags = [('_INSTALLFLAGS',['-C']),
                      ('_SHLINSTALLSYMLINKFLAGS',['-S'])] if metadata['LIB'] else [('_INSTALLFLAGS',[])]
    for key, expected in expected_flags:
        if shlex.split(metadata[key]) != expected:
            raise ValueError('unqualified install flags: ' + key)
    payloads = {}
    queried_groups = {}
    def add(destination, kind, owner, group, mode, tag_args, **details):
        destination = absolute(destination)
        if destination in payloads:
            raise ValueError('duplicate policy destination: ' + destination)
        if not re.fullmatch('[0-7]{3,4}', mode):
            raise ValueError('unsupported mode: ' + mode)
        payloads[destination] = {'type': kind, 'uname': owner, 'gname': group,
            'mode': int(mode,8), 'tags': tags(tag_args), **details}
    def library_file(name, directory, tag, role):
        add(directory+'/'+basename(name), 'file', metadata['LIBOWN'], metadata['LIBGRP'],
            metadata['LIBMODE'], metadata[tag], artifact=name, role=role)
    script_aliases=shared_script_aliases(metadata,link_script)
    if metadata['LIB']:
        archive = 'lib'+metadata['LIB_PRIVATE']+metadata['LIB']+metadata['_STATICLIB_SUFFIX']+'.a'
        if metadata['MK_INSTALLLIB'] == 'yes':
            if archive not in shlex.split(metadata['_LIBS']):
                raise ValueError('archive identity absent from maintained _LIBS')
            library_file(archive,metadata['_LIBDIR'],'DEV_TAG_ARGS','static_archive')
        pic_archive = installed_pic_archive(metadata, pic_defined)
        if pic_archive:
            library_file(pic_archive,metadata['_LIBDIR'],'DEV_TAG_ARGS','pic_archive')
        shared = metadata['SHLIB_NAME']
        if shared:
            shared_flags = shared_file_flags(metadata['_SHLINSTALLFLAGS'])
            library_file(shared,metadata['_SHLIBDIR'],'LIB_TAG_ARGS','shared_library')
            if shared_flags:payloads[absolute(metadata['_SHLIBDIR']+'/'+shared)]['flags']=shared_flags
            if metadata['MK_DEBUG_FILES'] == 'yes':
                add(metadata['DEBUGFILEDIR']+'/'+basename(metadata['DEBUGFILE']), 'file', metadata['DEBUGOWN'],
                    metadata['DEBUGGRP'],metadata['DEBUGMODE'],metadata['DBG_TAG_ARGS'],
                    artifact=metadata['DEBUGFILE'],role='shared_debug')
            if metadata['SHLIB_LINK']:
                if link_script:
                    library_file(metadata['SHLIB_LINK'],metadata['_LIBDIR'],'DEV_TAG_ARGS','shared_link_script')
                    payloads[link_script['install_path']]['script']=link_script
                    for target,destination in script_aliases:
                        add(destination,'link',metadata['LIBOWN'],metadata['LIBGRP'],metadata['LIBMODE'],
                            metadata['LIB_TAG_ARGS'],link=target,role='shared_symlink')
                else:
                    target = metadata['_SHLIBDIR']+'/'+shared
                    destination = metadata['_LIBDIR']+'/'+basename(metadata['SHLIB_LINK'])
                    expected_rs = ['-l','rs','-o',metadata['_SYMLINKOWN'],'-g',metadata['_SYMLINKGRP'],'-m',metadata['_SYMLINKMODE']]
                    if shlex.split(metadata['RSYMLINK']) != expected_rs:
                        raise ValueError('unsupported relative symlink policy')
                    add(destination,'link',metadata['_SYMLINKOWN'],metadata['_SYMLINKGRP'],metadata['_SYMLINKMODE'],
                        metadata['DEV_TAG_ARGS'] if metadata['SHLIB_LINK'].startswith('lib') else metadata['LIB_TAG_ARGS'],
                        link=os.path.relpath(target,str(PurePosixPath(destination).parent)),role='shared_symlink')
    else:
        if not metadata['PROG'] or metadata['PCFILES']:
            raise ValueError('unsupported program identity/pkg-config policy')
        program_path=metadata['BINDIR']+'/'+basename(metadata['PROGNAME'])
        add(program_path,'file',metadata['BINOWN'],metadata['BINGRP'],metadata['BINMODE'],
            metadata['TAG_ARGS'],role='program',artifact=metadata['PROG'])
        if metadata['MK_DEBUG_FILES']=='yes':
            add(metadata['DEBUGFILEDIR']+'/'+basename(metadata['DEBUGFILE']),'file',
                metadata['DEBUGOWN'],metadata['DEBUGGRP'],metadata['DEBUGMODE'],
                metadata['TAG_ARGS']+',dbg',role='program_debug',artifact=metadata['DEBUGFILE'])
        links=shlex.split(metadata['LINKS'])
        if len(links)%2:
            raise ValueError('odd program link mapping')
        for original,destination in zip(links[::2],links[1::2]):
            if original!=program_path:
                raise ValueError('program hardlink must reference selected program')
            # INSTALL_LINK preserves the source inode ownership and mode.
            tag_args=metadata['TAG_ARGS']+(','+metadata['LINKTAGS'] if metadata['LINKTAGS'] else '')
            add(destination,'file',metadata['BINOWN'],metadata['BINGRP'],metadata['BINMODE'],
                tag_args,role='program_hardlink',hardlink=original)
    for target,destination in configured_symlinks(metadata):
        tag_args=metadata['TAG_ARGS']+(','+metadata['LINKTAGS'] if metadata['LINKTAGS'] else '')
        add(destination,'link',metadata['_SYMLINKOWN'],metadata['_SYMLINKGRP'],metadata['_SYMLINKMODE'],
            tag_args,link=target,role='configured_symlink')
    search = [component]
    for value in shlex.split(metadata['.PATH']):
        if value != '.':
            search.append(Path(value))
    generated = {g['output']:g for g in plan['generators']}
    catalogues = {g['name']:g for g in (plan.get('nls_generation') or {}).get('outputs',[])}
    inputs[str(Path(install_sources.__file__).resolve())]=digest(Path(install_sources.__file__))
    def source_identity(name):
        return install_sources.identity(name,src,Path(metadata['.OBJDIR']),search,generated,catalogues,inputs)
    inputs[str(Path(configuration_install.__file__).resolve())]=digest(Path(configuration_install.__file__))
    queried_groups.update(configuration_install.export(metadata,lambda keys:query_many(env,keys),add,source_identity))
    inputs[str(Path(file_install.__file__).resolve())]=digest(Path(file_install.__file__))
    queried_groups.update(file_install.export(metadata,lambda keys:query_many(env,keys),add,source_identity))
    for pcfile in shlex.split(metadata['PCFILES']):
        basename(pcfile)
        if pcfile not in generated:
            raise ValueError('pkg-config output lacks declared generation: '+pcfile)
        add(metadata['LIBDATADIR']+'/pkgconfig/'+pcfile, 'file',
            metadata['LIBOWN'], metadata['LIBGRP'], metadata['LIBMODE'],
            metadata['DEV_TAG_ARGS'], role='pkg_config',
            generated_output=pcfile, generator=generated[pcfile])
    if metadata['MK_INCLUDES'] == 'yes':
        groups=shlex.split(metadata['INCSGROUPS'])
        group_keys={group:[group]+[group+s for s in ['OWN','GRP','MODE','DIR','NAME','TAG_ARGS']] for group in groups}
        group_values=query_many(env,[key for group in groups for key in group_keys[group]])
        for group in groups:
            values={key:group_values[key] for key in group_keys[group]}
            headers=shlex.split(values[group])
            override_keys={header:[group+s+'_'+Path(header).name for s in ['OWN','GRP','MODE','DIR','NAME']] for header in headers}
            overrides=query_many(env,[key for header in headers for key in override_keys[header]])
            queried_groups[group] = {'metadata': values, 'per_header': {}}
            for header in headers:
                name=Path(header).name
                override={key:overrides[key] for key in override_keys[header]}
                queried_groups[group]['per_header'][header] = override
                perfile=any(override.values())
                def value(suffix):
                    return override[group+suffix+'_'+name] if perfile else values[group+suffix]
                installed=value('NAME') or name
                add(value('DIR')+'/'+basename(installed),'file',value('OWN'),value('GRP'),value('MODE'),
                    metadata['TAG_ARGS']+',dev' if perfile else values[group+'TAG_ARGS'],
                    role='header',**source_identity(header))
    if metadata['MK_MAN'] == 'yes':
        for group in shlex.split(metadata['MANGROUPS']):
            values=query(env,[group]+[group+s for s in ['OWN','GRP','MODE','TAG_ARGS','LINKS']])
            queried_groups[group] = {'metadata': values}
            def manpath(name):
                basename(name)
                if '.' not in name:raise ValueError('manual requires section suffix')
                suffix=metadata['MCOMPRESS_EXT'] if metadata['MK_MANCOMPRESS']=='yes' else ''
                return metadata['MANDIR']+name.rsplit('.',1)[1]+metadata['MANSUBDIR']+'/'+name+suffix
            for name in shlex.split(values[group]):
                source=query(env,['MANSRC.'+name])['MANSRC.'+name] or name
                add(manpath(name),'file',values[group+'OWN'],values[group+'GRP'],values[group+'MODE'],
                    values[group+'TAG_ARGS'],role='manual',compression=metadata['MCOMPRESS_CMD'] if metadata['MK_MANCOMPRESS']=='yes' else None,
                    **source_identity(source))
            links=shlex.split(values[group+'LINKS'])
            if len(links)%2:raise ValueError('odd manual link mapping')
            for original,name in zip(links[::2],links[1::2]):
                add(manpath(name),'file',metadata['MANOWN'],metadata['MANGRP'],metadata['MANMODE'],values[group+'TAG_ARGS'],
                    role='manual_hardlink',hardlink=manpath(original))
    packages={tag for entry in payloads.values() for tag in entry['tags'] if tag.startswith('package=')}
    actual=read_metalog(reference/'METALOG')
    selected={name:entry for name,entry in actual.items() if entry.get('type')!='dir' and packages.intersection(entry.get('tags','').split(','))}
    if set(selected)!=set(payloads):
        raise ValueError('library payload coverage differs: unexpected='+str(sorted(set(selected)-set(payloads)))+' missing='+str(sorted(set(payloads)-set(selected))))
    stage=reference/'stage'
    for name,expected in payloads.items():
        got=selected[name]
        if (got.get('flags') or 'none') != (expected.get('flags') or 'none'):
            raise ValueError('reference file flags differ: '+name)
        for key in ['type','uname','gname']:
            if got.get(key)!=expected[key]:raise ValueError('METALOG '+key+' mismatch: '+name)
        if int(got.get('mode','0'),8)!=expected['mode'] or sorted(set(got.get('tags','').split(',')))!=expected['tags']:
            raise ValueError('METALOG mode/tags mismatch: '+name)
        file=stage/name.lstrip('/')
        if expected['type']=='link':
            if got.get('link')!=expected['link'] or not file.is_symlink() or str(file.readlink())!=expected['link']:
                raise ValueError('symlink mismatch: '+name)
        else:
            if file.is_symlink() or not file.is_file() or digest(file)!=got.get('sha256') or file.stat().st_size!=int(got['size']):
                raise ValueError('reference file differs from METALOG: '+name)
            if 'source_sha256' in expected and expected['role'] in ('header','configuration','file') and digest(file)!=expected['source_sha256']:
                raise ValueError('installed header differs from selected source: '+name)
            if expected['role']=='shared_link_script':
                script=expected['script']
                content=(src/script['template']['path']).read_bytes()
                for key,value in script['substitutions'].items():content=content.replace(key.encode(),value.encode())
                if file.read_bytes()!=content:raise ValueError('installed linker script differs from configured transformation')
            if 'hardlink' in expected and not file.samefile(stage/expected['hardlink'].lstrip('/')):
                raise ValueError('file is not the declared hardlink: '+name)
            expected['reference_sha256']=got['sha256']
    if env.query(['-V', '${INSTALL_PIC_ARCHIVE:Dyes:Uno}'], extra=INSTALL_CONFIG).strip()!=pic_defined:
        raise ValueError('PIC archive installation policy changed during export')
    env.verify()
    if env.capture_closure(extra=INSTALL_CONFIG)!=closure:
        raise ValueError('installation Make closure changed')
    for name,expected in inputs.items():
        if digest(Path(name))!=expected:raise ValueError('input changed during export: '+name)
    receipt={'format':1,'status':'reconciled','scope':'library-package install policy against existing actual Make stage; not Bazel install/package parity',
        'component':str(args.component),'metadata':metadata,'queried_groups':queried_groups,'payloads':payloads,'library_packages':sorted(packages),
        'excluded_nonlibrary_payloads':{name:entry for name,entry in actual.items() if entry.get('type')!='dir' and name not in selected},
        'input_sha256':inputs,'build_environment':env.receipt(),'installation_make_include_closure':closure,
        'install_configuration':INSTALL_CONFIG,'reference':str(reference),
        'limitations':['Directories from distrib-dirs and test packages are outside this library payload scope.',
            'Undeclared generated file payloads, generic hardlinks and unusual linker scripts are rejected.',
            'No native Bazel install actions or package archives executed by this exporter.']}
    output.mkdir(parents=True)
    (output/'inventory.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'inventory':str(output/'inventory.json'),'payloads':len(payloads),'library_packages':sorted(packages)}))

if __name__=='__main__':main()
