/* SPDX-License-Identifier: BSD-2-Clause */
struct local_payload { long value; };
static struct local_payload shared_data = { 9 };
static struct local_payload shared_function(void) { return shared_data; }
struct local_payload call_static(void) { return shared_function(); }
