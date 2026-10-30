/* SPDX-License-Identifier: BSD-2-Clause */
struct second { int value; };
struct second second_data = {25};
int second_value(void) { return second_data.value; }
