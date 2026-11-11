/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef RUN_CONTAINER_CLEANUP_H
#define RUN_CONTAINER_CLEANUP_H

/* Caller owns the parent namespace against concurrent mutation. Neither call
 * consumes parent. Do not follow symlinks or cross filesystem boundaries.
 * Missing entries are already clean; every other failure is returned in errno. */
int sb_run_container_remove_at(int parent, const char *name);
int sb_run_container_sweep_at(int parent);

#endif
