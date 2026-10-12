# SPDX-License-Identifier: BSD-2-Clause
# The system.Filesystem client (bsd.filesystem.v1).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	filesystemcmp
SHLIB_MAJOR=	1
MAN=	libfilesystemcmp.3
MLINKS+=	libfilesystemcmp.3 service_storage_open.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_quota.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_cache.3
MLINKS+=	libfilesystemcmp.3 service_storage_destroy_cache.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_shared.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_shared_readonly.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_env.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_group.3
MLINKS+=	libfilesystemcmp.3 service_storage_destroy_shared.3
MLINKS+=	libfilesystemcmp.3 service_storage_destroy_group.3
MLINKS+=	libfilesystemcmp.3 service_storage_destroy.3
MLINKS+=	libfilesystemcmp.3 service_storage_list.3
MLINKS+=	libfilesystemcmp.3 service_storage_list_shared.3
MLINKS+=	libfilesystemcmp.3 service_storage_list_group.3
MLINKS+=	libfilesystemcmp.3 service_storage_stat.3
MLINKS+=	libfilesystemcmp.3 service_storage_set_quota.3
MLINKS+=	libfilesystemcmp.3 service_storage_snapshot.3
MLINKS+=	libfilesystemcmp.3 service_storage_list_versions.3
MLINKS+=	libfilesystemcmp.3 service_storage_rollback.3
MLINKS+=	libfilesystemcmp.3 service_storage_open_version.3
MLINKS+=	libfilesystemcmp.3 service_storage_txn_begin.3
MLINKS+=	libfilesystemcmp.3 service_storage_txn_commit.3
MLINKS+=	libfilesystemcmp.3 service_storage_txn_abort.3
MLINKS+=	libfilesystemcmp.3 service_storage_release.3
MLINKS+=	libfilesystemcmp.3 service_storage_release_cache.3
MLINKS+=	libfilesystemcmp.3 service_storage_release_shared.3
MLINKS+=	libfilesystemcmp.3 service_storage_release_group.3
MLINKS+=	libfilesystemcmp.3 service_open_config.3
MLINKS+=	libfilesystemcmp.3 service_open_isolated.3
SRCS=	filesystemcmp.c \
	${FIDLGEN_SRCS.filesystemcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.filesystemcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= FILESYSTEMCMP_SCHEMA
FILESYSTEMCMP_SCHEMA= filesystemcmp.fidl
FILESYSTEMCMP_SCHEMADIR= /usr/share/fidl
FILESYSTEMCMP_SCHEMAPACKAGE= libfilesystemcmp-dev
FILESGROUPS+= FILESYSTEMCMP_NOTICE
FILESYSTEMCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FILESYSTEMCMP_NOTICEDIR= /usr/share/licenses/libfilesystemcmp/fuchsia
INCS=	filesystemcmp.h
LIBADD=	pthread service trustedzfs fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
STATIC_CFLAGS+=	${PICFLAG}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	filesystemcmp
FIDL_SCHEMAS.filesystemcmp=	lib/libfidl/tests/zx.fidl \
	lib/libfilesystemcmp/filesystemcmp.fidl
FIDL_LIBRARY.filesystemcmp=	bsd.filesystem.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
