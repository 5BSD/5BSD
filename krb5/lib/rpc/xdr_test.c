/* SPDX-License-Identifier: BSD-2-Clause */
#include <gssrpc/types.h>
#include <gssrpc/xdr.h>
#include <string.h>

int main(void)
{
    const unsigned char expected[] = {0xff, 0xff, 0xff, 0xf9, 0, 0, 0, 3, 'b', 's', 'd', 0};
    char buffer[sizeof(expected)];
    char *text = "bsd", *decoded = NULL;
    int value = -7, result = 0;
    XDR xdr;
    xdrmem_create(&xdr, buffer, sizeof(buffer), XDR_ENCODE);
    if (!xdr_int(&xdr, &value) || !xdr_string(&xdr, &text, 16) ||
        xdr_getpos(&xdr) != sizeof(expected) || memcmp(buffer, expected, sizeof(expected)))
        return 1;
    xdr_destroy(&xdr);
    xdrmem_create(&xdr, buffer, sizeof(buffer), XDR_DECODE);
    if (!xdr_int(&xdr, &result) || result != value ||
        !xdr_string(&xdr, &decoded, 16) || strcmp(decoded, text))
        return 2;
    xdr_destroy(&xdr);
    xdr_free((xdrproc_t)xdr_wrapstring, (char *)&decoded);
    if (decoded != NULL)
        return 4;
    xdrmem_create(&xdr, buffer, 3, XDR_DECODE);
    if (xdr_int(&xdr, &result))
        return 3;
    xdr_destroy(&xdr);
    return 0;
}
