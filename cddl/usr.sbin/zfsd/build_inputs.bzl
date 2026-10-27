# SPDX-License-Identifier: BSD-2-Clause
# Shared native compilation inputs for the daemon and its maintained unit suite.
ZFSD_SOURCES = ['callout.cc', 'case_file.cc', 'zfsd_event.cc', 'vdev.cc', 'vdev_iterator.cc', 'zfsd.cc', 'zfsd_exception.cc', 'zpool_list.cc']
ZFSD_DEPS = ["//lib/libc++:cxx", "//lib/libcxxrt:cxxrt", "//lib/msun:m", '//lib/libdevdctl:devdctl', '//cddl/lib/libzfs:zfs', '//lib/libutil:util', '//lib/libgeom:geom', '//lib/libexpat:bsdxml', '//lib/libsbuf:sbuf', '//cddl/lib/libnvpair:nvpair', '//cddl/lib/libavl:avl', '//cddl/lib/libzutil:zutil', '//cddl/lib/libspl:spl'] + ["//sys/contrib/openzfs:zfsd_headers"]
ZFSD_DYNAMIC_DEPS = ["//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", '//lib/libdevdctl:devdctl_shared', '//cddl/lib/libzfs:zfs_shared', '//lib/libutil:util_shared', '//lib/libgeom:geom_shared', '//lib/libexpat:bsdxml_shared', '//lib/libsbuf:sbuf_shared', '//cddl/lib/libnvpair:nvpair_shared', '//cddl/lib/libavl:avl_shared', '//cddl/lib/libzutil:zutil_shared', '//cddl/lib/libspl:spl_shared']
ZFSD_DEFINES = ["IN_BASE", "HAVE_ISSETUGID", "HAVE_EXECVPE", "NEED_SOLARIS_BOOLEAN", "HAVE_STRLCAT", "HAVE_STRLCPY"]
ZFSD_COPTS = ["-fPIE", "-nostdinc++", "-include", "sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h"]
