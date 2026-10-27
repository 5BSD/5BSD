/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib80211_regdomain.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #c); return (1); \
} } while (0)

int
main(int argc, char **argv)
{
    struct regdata data;
    const struct country *country;
    const struct regdomain *domain;
    FILE *file;
    char *xml;
    long length;
    unsigned countries = 0, domains = 0;

    CHECK(argc == 2);
    file = fopen(argv[1], "rb");
    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    CHECK(length > 0);
    rewind(file);
    xml = malloc((size_t)length);
    CHECK(xml != NULL);
    CHECK(fread(xml, 1, (size_t)length, file) == (size_t)length);
    CHECK(fclose(file) == 0);
    CHECK(lib80211_regdomain_readconfig(&data, xml, (size_t)length) == 0);
    free(xml);

    /* Resolve every declared entry by both public lookup keys. */
    LIST_FOREACH(country, &data.countries, next) {
        CHECK(country->rd != NULL);
        CHECK(lib80211_country_findbycc(&data, country->code) == country);
        CHECK(lib80211_country_findbyname(&data, country->isoname) == country);
        countries++;
    }
    LIST_FOREACH(domain, &data.domains, next) {
        CHECK(lib80211_regdomain_findbysku(&data, domain->sku) == domain);
        CHECK(lib80211_regdomain_findbyname(&data, domain->name) == domain);
        domains++;
    }
    CHECK(countries > 0 && domains > 0);
    CHECK(lib80211_country_findbyname(&data, "us") ==
        lib80211_country_findbyname(&data, "US"));
    CHECK(lib80211_country_findbyname(&data, "US") != NULL);
    CHECK(lib80211_country_findbyname(&data, "no-such-country") == NULL);
    CHECK(lib80211_regdomain_findbyname(&data, "no-such-domain") == NULL);
    lib80211_regdomain_cleanup(&data);
    return (0);
}
