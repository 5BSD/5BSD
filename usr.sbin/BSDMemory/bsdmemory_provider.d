/* SPDX-License-Identifier: BSD-2-Clause */
provider bsdmemory {
	probe ready();
	probe sample__start();
	probe sample__done(int error, uint32_t free_pages, uint32_t minimum,
	    uint32_t target);
	probe pressure(uint32_t level, uint32_t effective, uint32_t recovery);
	probe publish__start(uint32_t level);
	probe publish__done(uint32_t requested, uint32_t published, int error);
	probe exit(int status);
};
