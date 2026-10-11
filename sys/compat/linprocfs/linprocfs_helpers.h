/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINPROCFS_HELPERS_H_
#define _LINPROCFS_HELPERS_H_

int linprocfs_common_doprocfile(PFS_FILL_ARGS);
int linprocfs_common_docurproc(PFS_FILL_ARGS);
int linprocfs_common_doprocmem(PFS_FILL_ARGS);
int linprocfs_common_attr_rw(PFS_ATTR_ARGS);
int linprocfs_common_notsystem(PFS_VIS_ARGS);
int linprocfs_common_candebug(PFS_VIS_ARGS);

#endif
