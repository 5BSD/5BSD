/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider fifocreate {
	probe operation__start(unsigned int);
	probe operation__done(unsigned int, int, int);
};
