/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_RECLAMATION_H
#define SWITCHBOARD_RECLAMATION_H
#include "switchboard_lifecycle.h"
/* Experimental consumer of completed removal records; not installer APIs. */
int sl_cleanup_prepare(struct sl_db *, const char *, const uint8_t *);
int sl_register_provider(struct sl_db *, const char *);
int sl_track_holding(struct sl_db *, const char *, const char *, const uint8_t *);
int sl_ack(struct sl_db *, const char *, const char *, const uint8_t *);
#endif
