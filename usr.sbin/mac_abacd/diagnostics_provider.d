/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider abacdaemon {
	probe policy__start(int a0);
	probe policy__done(int a0, int a1);
};
