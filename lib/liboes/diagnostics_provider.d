/* SPDX-License-Identifier: BSD-2-Clause */
provider oesclient {
	probe batch__read(int64_t a0, int a1);
	probe buffer__corrupt(uint64_t a0, uint64_t a1);
	probe auth__response(int a0, uint32_t a1, uint32_t a2, int a3);
};
