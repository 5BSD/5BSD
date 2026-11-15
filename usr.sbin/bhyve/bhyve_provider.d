/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider netbe {
	probe tap__recv(char *, void *);
	probe tap__send(char *, void *);
	probe tap__recv__v2(char *, void *);
	probe tap__send__v2(char *, void *);
};
