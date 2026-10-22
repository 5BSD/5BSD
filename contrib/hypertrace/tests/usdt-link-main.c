/* SPDX-License-Identifier: BSD-2-Clause */
/* Links the USDT objects into an executable; never run. */
void ul_main(int, char *);
void ul_tail(int);
int ulb_go(int);

int
main(int argc, char **argv)
{
	ul_main(argc, argv[0]);
	ul_tail(argc);
	return (0);
}
