# SPDX-License-Identifier: BSD-2-Clause
# Check public-only PEM framing before any input is embedded in the loader.
# Certificate decoding and trust validation remain the verifier's responsibility.
function reject() {
    print "invalid public trust input: " FILENAME > "/dev/stderr"
    failed = 1
    exit 1
}
FNR == 1 && inside { reject() }
{
    sub(/\r$/, "")
    if ($0 ~ /^[ \t]*$/) next
    if ($0 == "-----BEGIN CERTIFICATE-----") {
        if (inside) reject()
        inside = 1
        body = 0
    } else if ($0 == "-----END CERTIFICATE-----") {
        if (!inside || !body) reject()
        inside = 0
        certificates++
    } else {
        if (!inside || $0 !~ /^[A-Za-z0-9+\/=]+$/) reject()
        body++
    }
}
END {
    if (!failed && (inside || (required == "yes" && !certificates))) {
        print "public trust input requires complete certificate PEM" > "/dev/stderr"
        exit 1
    }
}
