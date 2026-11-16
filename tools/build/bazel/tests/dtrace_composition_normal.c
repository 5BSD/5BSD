/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include "dtrace_composition.h"
int composition_normal(int value) { COMPOSITION_HIT(value); return value; }
