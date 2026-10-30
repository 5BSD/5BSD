# SPDX-License-Identifier: BSD-2-Clause
"""Read archive metadata through the system libarchive public C interface."""
import ctypes as C
from pathlib import Path

LIBRARY=Path('/usr/lib/libarchive.so')

def read(path):
    lib=C.CDLL(str(LIBRARY))
    def bind(name,args,result):
        f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
    new=bind('archive_read_new',[],C.c_void_p)
    filters=bind('archive_read_support_filter_all',[C.c_void_p],C.c_int)
    formats=bind('archive_read_support_format_all',[C.c_void_p],C.c_int)
    openfile=bind('archive_read_open_filename',[C.c_void_p,C.c_char_p,C.c_size_t],C.c_int)
    next_header=bind('archive_read_next_header',[C.c_void_p,C.POINTER(C.c_void_p)],C.c_int)
    skip=bind('archive_read_data_skip',[C.c_void_p],C.c_int)
    free=bind('archive_read_free',[C.c_void_p],C.c_int)
    error=bind('archive_error_string',[C.c_void_p],C.c_char_p)
    strings={k:bind('archive_entry_'+k,[C.c_void_p],C.c_char_p) for k in ('pathname','uname','gname','hardlink','symlink')}
    mode=bind('archive_entry_mode',[C.c_void_p],C.c_uint)
    fflags=bind('archive_entry_fflags',[C.c_void_p,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong)],None)
    handle=new()
    if not handle:raise RuntimeError('libarchive allocation failed')
    def check(status):
        if status!=0:raise ValueError('archive metadata read failed: '+repr(error(handle)))
    result=[]
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
            set_flags=C.c_ulong();clear_flags=C.c_ulong()
            fflags(entry,C.byref(set_flags),C.byref(clear_flags))
            record['fflags']=[set_flags.value,clear_flags.value]
            result.append(record)
            check(skip(handle))
    finally:
        free(handle)
    return result


def flag_bits(text):
    """Use libarchive's flag vocabulary, including aliases, without numeric guesses."""
    if not text or text == 'none':return [0,0]
    lib=C.CDLL(str(LIBRARY))
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


def check_flags(header, expected):
    if header['fflags'] != flag_bits(expected):
        raise ValueError('archive file flags differ')
