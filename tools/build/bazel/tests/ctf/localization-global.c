/* SPDX-License-Identifier: BSD-2-Clause */
struct global_payload { int value; };
struct exported_payload { char value[16]; };
struct exported_payload exported_data = { "exported" };
struct exported_payload exported_function(void) { return exported_data; }
struct global_payload shared_data = { 7 };
struct global_payload shared_function(void) { return shared_data; }
