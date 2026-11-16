/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include "composition.h"
struct first { int value; };
struct first first_data = {17};
int support_value(void);
int first_value(void) { int value = support_value(); COMPOSITION_HIT(value); return value; }
