/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider diskwalk {
	probe operation__start(int);
	probe operation__done(int, int, int);
};
