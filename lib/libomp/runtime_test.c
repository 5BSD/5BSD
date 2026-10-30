/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <omp.h>

int
main(int argc, char **argv)
{
	struct stat expected, actual;
	Dl_info info;
	int slots[4], chain[128], team;
	long sum;
	void *symbol;

	assert(argc == 2);
	assert(stat(argv[1], &expected) == 0);
	symbol = dlsym(RTLD_DEFAULT, "omp_get_num_threads");
	assert(symbol != NULL && dladdr(symbol, &info) != 0);
	assert(stat(info.dli_fname, &actual) == 0);
	assert(expected.st_dev == actual.st_dev &&
	    expected.st_ino == actual.st_ino);
	omp_set_dynamic(0);
	omp_set_num_threads(4);
	for (int round = 0; round < 16; round++) {
		sum = 0;
		team = 0;
		for (int i = 0; i < 4; i++)
			slots[i] = 0;
#pragma omp parallel shared(slots, team) reduction(+:sum)
		{
			int id = omp_get_thread_num();
			assert(id >= 0 && id < 4);
#pragma omp single
			team = omp_get_num_threads();
			slots[id] = id + round + 1;
#pragma omp barrier
			for (int i = 0; i < 4; i++)
				assert(slots[i] == i + round + 1);
#pragma omp for schedule(dynamic, 7)
			for (int i = 1; i <= 10000; i++)
				sum += i;
		}
		assert(team == 4 && sum == 50005000);
		for (int i = 0; i < 128; i++)
			chain[i] = 0;
		chain[0] = round + 1;
#pragma omp parallel shared(chain)
#pragma omp single
		{
#pragma omp taskgroup
			for (int i = 1; i < 128; i++) {
#pragma omp task firstprivate(i) depend(in:chain[i-1]) depend(out:chain[i])
				chain[i] = chain[i-1] + 1;
			}
		}
		for (int i = 0; i < 128; i++)
			assert(chain[i] == round + 1 + i);
	}
	puts("native libomp: 16 rounds, four-thread teams, barriers, reductions and task dependencies passed");
	return (0);
}
