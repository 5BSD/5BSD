# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Read archive metadata through the system libarchive public C interface."""
import ctypes as C
import hashlib
import stat
from pathlib import Path

LIBRARY=Path('/usr/lib/libarchive.so')

def read(path, *, payload_digests=False, library=LIBRARY):
    """Read raw metadata and optionally hash regular payloads without extraction."""
    if type(payload_digests) is not bool:
        raise ValueError("payload_digests must be boolean")
    lib=C.CDLL(str(library))
    def bind(name,args,result):
        f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
    new=bind('archive_read_new',[],C.c_void_p)
    filters=bind('archive_read_support_filter_all',[C.c_void_p],C.c_int)
    formats=bind('archive_read_support_format_all',[C.c_void_p],C.c_int)
    openfile=bind('archive_read_open_filename',[C.c_void_p,C.c_char_p,C.c_size_t],C.c_int)
    next_header=bind('archive_read_next_header',[C.c_void_p,C.POINTER(C.c_void_p)],C.c_int)
    skip=bind('archive_read_data_skip',[C.c_void_p],C.c_int)
    read_data=bind('archive_read_data',[C.c_void_p,C.c_void_p,C.c_size_t],C.c_ssize_t)
    free=bind('archive_read_free',[C.c_void_p],C.c_int)
    error=bind('archive_error_string',[C.c_void_p],C.c_char_p)
    strings={k:bind('archive_entry_'+k,[C.c_void_p],C.c_char_p) for k in ('pathname','uname','gname','hardlink','symlink')}
    mode=bind('archive_entry_mode',[C.c_void_p],C.c_uint)
    uid=bind('archive_entry_uid',[C.c_void_p],C.c_int64)
    gid=bind('archive_entry_gid',[C.c_void_p],C.c_int64)
    size=bind('archive_entry_size',[C.c_void_p],C.c_int64)
    mtime=bind('archive_entry_mtime',[C.c_void_p],C.c_int64)
    mtime_nsec=bind('archive_entry_mtime_nsec',[C.c_void_p],C.c_long)
    mtime_set=bind('archive_entry_mtime_is_set',[C.c_void_p],C.c_int)
    clocks={name:(bind('archive_entry_'+name,[C.c_void_p],C.c_int64),
                  bind('archive_entry_'+name+'_nsec',[C.c_void_p],C.c_long),
                  bind('archive_entry_'+name+'_is_set',[C.c_void_p],C.c_int))
            for name in ('atime','ctime','birthtime')}
    acl_types=bind('archive_entry_acl_types',[C.c_void_p],C.c_int)
    xattr_count=bind('archive_entry_xattr_count',[C.c_void_p],C.c_int)
    fflags=bind('archive_entry_fflags',[C.c_void_p,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong)],None)
    handle=new()
    if not handle:raise RuntimeError('libarchive allocation failed')
    def check(status):
        if status!=0:raise ValueError('archive metadata read failed: '+repr(error(handle)))
    result=[]
    buffer=C.create_string_buffer(65536) if payload_digests else None
    try:
        check(filters(handle));check(formats(handle));check(openfile(handle,str(path).encode(),65536))
        entry=C.c_void_p()
        while True:
            status=next_header(handle,C.byref(entry))
            if status==1:break  # ARCHIVE_EOF
            check(status)
            record={}
            for key,get in strings.items():
                value=get(entry)
                record[key]=value.decode('utf-8') if value is not None else None
            record['mode']=mode(entry)
            record['uid']=uid(entry);record['gid']=gid(entry)
            record['size']=size(entry)
            record['mtime']=mtime(entry);record['mtime_nsec']=mtime_nsec(entry)
            record['mtime_is_set']=bool(mtime_set(entry))
            for name,(seconds,nanoseconds,present) in clocks.items():
                record[name]=seconds(entry);record[name+'_nsec']=nanoseconds(entry)
                record[name+'_is_set']=bool(present(entry))
            record['acl_types']=acl_types(entry);record['xattr_count']=xattr_count(entry)
            set_flags=C.c_ulong();clear_flags=C.c_ulong()
            fflags(entry,C.byref(set_flags),C.byref(clear_flags))
            record['fflags']=[set_flags.value,clear_flags.value]
            if payload_digests and stat.S_ISREG(record['mode']) and record['hardlink'] is None:
                checksum=hashlib.sha256();total=0
                while True:
                    count=read_data(handle,buffer,len(buffer))
                    if count<0:
                        raise ValueError('archive payload read failed: '+repr(error(handle)))
                    if count==0:break
                    checksum.update(buffer.raw[:count]);total+=count
                if total!=record['size']:
                    raise ValueError('archive payload size differs from header')
                record['data_sha256']=checksum.hexdigest()
            result.append(record)
            check(skip(handle))
    finally:
        free(handle)
    return result


def flag_bits(text, *, library=LIBRARY):
    """Use libarchive's flag vocabulary, including aliases, without numeric guesses."""
    if not text or text == 'none':return [0,0]
    lib=C.CDLL(str(library))
    lib.archive_entry_new.argtypes=[];lib.archive_entry_new.restype=C.c_void_p
    lib.archive_entry_copy_fflags_text.argtypes=[C.c_void_p,C.c_char_p]
    lib.archive_entry_copy_fflags_text.restype=C.c_char_p
    lib.archive_entry_fflags.argtypes=[C.c_void_p,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong)]
    lib.archive_entry_fflags.restype=None
    lib.archive_entry_free.argtypes=[C.c_void_p];lib.archive_entry_free.restype=None
    entry=lib.archive_entry_new()
    if not entry:raise RuntimeError('libarchive entry allocation failed')
    try:
        unknown=lib.archive_entry_copy_fflags_text(entry,text.encode())
        if unknown is not None:raise ValueError('unrecognized archive file flags: '+text)
        set_flags=C.c_ulong();clear_flags=C.c_ulong()
        lib.archive_entry_fflags(entry,C.byref(set_flags),C.byref(clear_flags))
        return [set_flags.value,clear_flags.value]
    finally:
        lib.archive_entry_free(entry)


def check_flags(header, expected, *, library=LIBRARY):
    if header['fflags'] != flag_bits(expected, library=library):
        raise ValueError('archive file flags differ')
