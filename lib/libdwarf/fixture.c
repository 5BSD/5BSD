/* SPDX-License-Identifier: BSD-2-Clause */
#line 101 "dwarf_fixture.c"
int dwarf_fixture_value = 7;
int dwarf_fixture_answer(void) { return dwarf_fixture_value + 35; }
int main(void) { return dwarf_fixture_answer() != 42; }
