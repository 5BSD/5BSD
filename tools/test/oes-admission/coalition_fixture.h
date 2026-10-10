/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef COALITION_FIXTURE_H
#define COALITION_FIXTURE_H
#include <stdio.h>
int coalition_prepare(void);
int coalition_worker(const char *);
int coalition_exercise(FILE *);
#endif
