/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider socketsnapshot {
	probe query__start(int, size_t);
	probe query__done(int, int, size_t);
};
