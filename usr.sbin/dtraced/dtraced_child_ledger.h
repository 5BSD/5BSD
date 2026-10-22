/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_CHILD_LEDGER_H
#define DTRACED_CHILD_LEDGER_H

#include <sys/types.h>

namespace dtraced {

/* The caller holds the child behind an exec gate until this is durable. */
bool record_guest_child(int directory, int procfd, pid_t pid);
/* Call only after a process descriptor proves that the child exited. */
bool retire_guest_child(int directory, pid_t pid);
/* Resolve every recorded child before accepting a pending CLEANUP. */
bool recover_guest_children(int directory, bool pending_cleanup);

}
#endif
