/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "config.h"

int
main(int argc, char **argv)
{
    struct capsule_config config;
    const char *path = NULL;
    bool validate = false, json = false;
    int ch;

    while ((ch = getopt(argc, argv, "njf:")) != -1) {
        switch (ch) {
        case 'n': validate = true; break;
        case 'j': json = true; break;
        case 'f': path = optarg; break;
        default: errx(1, "usage: bsd-capsule-validate -n [-j] -f configuration");
        }
    }
    if (!validate || path == NULL || optind != argc)
        errx(1, "usage: bsd-capsule-validate -n [-j] -f configuration");
    config_init_defaults(&config);
    if (config_load(&config, path) != 0 || !config.loaded_from_file)
        errx(1, "configuration error");
    if (json)
        config_validation_report(&config);
    else
        puts("configuration valid: syntax and static constraints only");
    config_free(&config);
    return (0);
}
