/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
int common_value(void);
__attribute__((weak)) int selected_value(void) { return (common_value() + CHOICE); }
