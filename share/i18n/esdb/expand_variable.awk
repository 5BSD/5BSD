# SPDX-License-Identifier: BSD-2-Clause
# Literal substitution preserves punctuation in encoding variable values.
function replace(text, token, value,    position, result) {
    result = ""
    while ((position = index(text, token)) != 0) {
        result = result substr(text, 1, position - 1) value
        text = substr(text, position + length(token))
    }
    return result text
}
NR == FNR {
    if ($0 ~ /^#/ || NF == 0) next
    if ($1 == key) {
        if (found++) exit 1
        variable = $0
        sub(/^[^ \t]*[ \t]*/, "", variable)
    }
    next
}
{
    if (!found) exit 1
    print replace(replace($0, "encoding", encoding), "variable", variable) > output
}
END { if (!found) exit 1 }
