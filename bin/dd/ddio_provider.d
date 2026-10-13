/* SPDX-License-Identifier: BSD-2-Clause */
provider ddio {
	probe read__start(int arg0, uint64_t arg1);
	probe read__done(int arg0, int64_t arg1, int arg2);
	probe write__start(int arg0, uint64_t arg1);
	probe write__done(int arg0, int64_t arg1, int arg2);
	probe sparse(int arg0, uint64_t arg1);
	probe sync__start(int, int);
	probe sync__done(int, int, int, int);
};
