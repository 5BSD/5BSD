/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_LIFECYCLE_PRIVATE_H
#define SWITCHBOARD_LIFECYCLE_PRIVATE_H
#include "switchboard_lifecycle.h"
/* Internal allocation; never publish this interface to installer clients. */
struct sl_record *sl_append(struct sl_db *);
bool sl_history_strict(struct sl_db *);
bool sl_history_due(struct sl_db *);
bool sl_operation_issued(struct sl_db *, const char *);
#endif
