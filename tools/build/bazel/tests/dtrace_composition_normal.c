/* SPDX-License-Identifier: BSD-2-Clause */
#include "dtrace_composition.h"
int composition_normal(int value) { COMPOSITION_HIT(value); return value; }
