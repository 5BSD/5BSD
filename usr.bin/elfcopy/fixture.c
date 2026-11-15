/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
int fixture_value = 7;
int fixture_answer(void) { return fixture_value + 35; }
int main(void) { return fixture_answer() != 42; }
