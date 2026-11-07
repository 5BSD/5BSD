/* SPDX-License-Identifier: BSD-2-Clause */

provider threadwait {
	probe mutex__start(uintptr_t);
	probe mutex__done(uintptr_t, int);
	probe condition__start(uintptr_t, int);
	probe condition__done(uintptr_t, int);
	probe join__start(uintptr_t);
	probe join__done(uintptr_t, int);
	probe rwlock__start(uintptr_t, int);
	probe rwlock__done(uintptr_t, int, int);
};

provider plockstat {
	probe mutex__acquire(void *mutex, int rec, int spincount);
	probe mutex__release(void *mutex, int rec);
	probe mutex__block(void *mutex);
	probe mutex__spin(void *mutex);
	probe mutex__spun(void *mutex, int success, int spincount);
	probe mutex__blocked(void *mutex, int success);
	probe mutex__error(void *mutex, int err);

	probe rw__acquire(void *lock, int wr);
	probe rw__release(void *lock, int wr);
	probe rw__block(void *lock, int wr);
	probe rw__blocked(void *lock, int wr, int success);
	probe rw__error(void *lock, int wr, int err);
};
