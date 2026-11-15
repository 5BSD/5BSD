/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider rootchange {
	probe operation__start(int);
	probe operation__done(int, int, int);
};
