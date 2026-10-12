# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    tool=$(atf_config_get elfcache /usr/sbin/elfcache)
    [ -x "$tool" ] || atf_skip "elfcache not installed"
    mkdir -p root/lib root/usr/lib
    printf 'int state = 7; int value(void) { return state; }\n' > library.c
    atf_check -s exit:0 -o ignore -e ignore cc -fPIC -shared -nostdlib library.c -o root/lib/libdemo.so.1
    ln -s libdemo.so.1 root/lib/libdemo.so
    printf 'GROUP (libdemo.so.1)\n' > root/usr/lib/libscript.so
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in key -pubout -out public
}
atf_test_case aliases
aliases_head() { atf_set require.progs 'cc openssl'; }
aliases_body()
{
    setup
    atf_check -s exit:0 -o save:stats "$tool" build -r root -o cache -k key
    atf_check -s exit:0 -o match:'libdemo.so.1' "$tool" verify -p public cache
    atf_check -s exit:0 -o save:index "$tool" inspect cache
    awk 'NR == 1 { first=$2 } NR == 2 && $2 != first { exit 1 } END { if (NR != 2) exit 1 }' index || atf_fail 'aliases were not deduplicated'
}
atf_test_case tamper
tamper_head() { atf_set require.progs 'cc openssl'; }
tamper_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    chmod u+w cache
    printf x > byte
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=65540 conv=notrunc
    atf_check -s not-exit:0 -e ignore "$tool" verify -p public cache
    atf_check -s exit:0 -o ignore "$tool" inspect cache
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=0 conv=notrunc
    atf_check -s not-exit:0 -e ignore "$tool" inspect cache
}
atf_test_case wrong_key
wrong_key_head() { atf_set require.progs 'cc openssl'; }
wrong_key_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out other
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in other -pubout -out other-public
    atf_check -s not-exit:0 -e match:'invalid or untrusted' "$tool" verify -p other-public cache
}
atf_test_case escape
escape_head() { atf_set require.progs 'cc openssl'; }
escape_body()
{
    setup
    cp root/lib/libdemo.so.1 outside
    ln -s "$(pwd)/outside" root/usr/lib/libescape.so.1
    atf_check -s not-exit:0 -e match:'escapes staged root' "$tool" build -r root -o cache
    [ ! -e cache ] || atf_fail 'published an escaping library'
}
atf_test_case no_clobber
no_clobber_head() { atf_set require.progs 'cc openssl'; }
no_clobber_body()
{
    setup
    printf sentinel > cache
    atf_check -s not-exit:0 -e match:publish "$tool" build -r root -o cache
    atf_check -s exit:0 -o inline:sentinel cat cache
}
atf_test_case reproducible
reproducible_head() { atf_set require.progs 'cc openssl'; }
reproducible_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o one -k key
    atf_check -s exit:0 -o ignore "$tool" build -r root -o two -k key
    atf_check -s exit:0 cmp one two
    atf_check -s exit:0 cmp one.sig two.sig
}
atf_test_case extract
extract_head() { atf_set require.progs 'cc openssl'; }
extract_body()
{
    setup
    cp root/lib/libdemo.so.1 root/usr/lib/libother.so.2
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    atf_check -s exit:0 -o ignore "$tool" extract -p public -o extracted cache
    atf_check -s exit:0 cmp root/lib/libdemo.so.1 extracted/lib/libdemo.so.1
    atf_check -s exit:0 cmp root/lib/libdemo.so extracted/lib/libdemo.so
    atf_check -s exit:0 cmp root/usr/lib/libother.so.2 extracted/usr/lib/libother.so.2
    [ ! -e extracted/usr/lib/libscript.so ] || atf_fail 'extracted a linker script'
    atf_check -s exit:0 -o inline:'444\n' stat -f %Lp extracted/lib/libdemo.so.1
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" extract -p public -o extracted cache
    atf_check -s exit:0 cmp root/lib/libdemo.so.1 extracted/lib/libdemo.so.1
    ln -s extracted symlink
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" extract -p public -o symlink cache
}
atf_test_case extract_reject
extract_reject_head() { atf_set require.progs 'cc openssl'; }
extract_reject_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o unsigned
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" extract -p public -o unsigned-output unsigned
    [ ! -e unsigned-output ] || atf_fail 'unsigned input created output'
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    chmod u+w cache
    printf x > byte
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=65540 conv=notrunc
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" extract -p public -o bad-output cache
    [ ! -e bad-output ] || atf_fail 'tampered input created output'
}
atf_test_case selection
selection_head() { atf_set require.progs 'cc openssl'; }
selection_body()
{
    setup
    printf '/lib/libdemo.so.1\n' > selected
    atf_check -s exit:0 -o match:'entries=1 ' "$tool" build -r root -l selected -o selected.cache -k key
    atf_check -s exit:0 -o match:'entries=1 unique_images=1' "$tool" info selected.cache
    atf_check -s exit:0 -o ignore "$tool" extract -p public -o extracted selected.cache
    [ ! -e extracted/lib/libdemo.so ] || atf_fail 'included an unselected alias'
    printf '/usr/lib/missing.so.1\n' >> selected
    atf_check -s not-exit:0 -e match:'selected library missing' "$tool" build -r root -l selected -o missing.cache
    [ ! -e missing.cache ] || atf_fail 'published incomplete selection'
    printf '/lib/libdemo.so.1\n/lib/libdemo.so.1\n' > selected
    atf_check -s not-exit:0 -e match:'duplicate selection' "$tool" build -r root -l selected -o duplicate.cache
    printf '/lib/../outside.so\n' > selected
    atf_check -s not-exit:0 -e match:'invalid cache selection' "$tool" build -r root -l selected -o escape.cache
}
atf_test_case signed_inputs
signed_inputs_head() { atf_set require.progs 'cc openssl'; }
signed_inputs_body()
{
    setup
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip 'capsign not installed'
    cp root/lib/libdemo.so.1 original.so
    printf 'program = "cache_signature_only_marker";\n' > policy
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed.so original.so
    mv signed.so root/lib/libdemo.so.1
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    atf_check -s exit:0 -o ignore "$tool" verify -p public cache
    atf_check -s exit:1 grep -a -q 'cache_signature_only_marker' cache
    atf_check -s exit:1 grep -a -q '5BSDSIG' cache
    atf_check -s exit:1 grep -a -q '5BSDEND' cache
    atf_check -s exit:0 -o ignore "$tool" extract -p public -o extracted cache
    atf_check -s exit:0 cmp original.so extracted/lib/libdemo.so.1
    atf_check -s not-exit:0 -e ignore "$capsign" verify -p public extracted/lib/libdemo.so.1
    atf_check -s exit:0 -o ignore "$capsign" verify -p public root/lib/libdemo.so.1
}
atf_test_case json_images
json_images_head() { atf_set require.progs 'cc openssl sha256'; }
json_images_body()
{
    setup
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip 'capsign not installed'
    payload=$(stat -f %z root/lib/libdemo.so.1)
    digest=$(sha256 -q root/lib/libdemo.so.1)
    printf 'program = "library"; activation { exec = true; }\n' > policy
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed root/lib/libdemo.so.1
    mv signed root/lib/libdemo.so.1
    source=$(stat -f %z root/lib/libdemo.so.1)
    [ "$source" -gt "$payload" ] || atf_fail 'missing signature container'
    odd=$(printf 'libz"\\\n\t\377.so')
    ln -s libdemo.so.1 "root/lib/$odd"
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    {
        printf '%s' '{"schema":"org.5bsd.elfcache.images.v1","format_version":2,"authenticated":false,"payload_digests_verified":false,"path_encoding":"byte-values","images":['
        i=0
        for path in /lib/libdemo.so /lib/libdemo.so.1 '/lib/libz\"\\\u000a\u0009\u00ff.so'; do
            [ "$i" = 0 ] || printf ','
            printf '{"index":%s,"path":"%s","cache_offset":65536,"payload_bytes":%s,"source_bytes":%s,"canonical_index":0,"payload_sha256":"%s"}' "$i" "$path" "$payload" "$source" "$digest"
            i=$((i + 1))
        done
        printf ']}\n'
    } > expected
    atf_check -s exit:0 -o file:expected -e empty "$tool" map -j cache
    # Even an invalid final record must emit no partial JSON document.
    chmod u+w cache
    printf '\001' > byte
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=452 conv=notrunc
    atf_check -s not-exit:0 -o empty -e match:'invalid cache entry' "$tool" map -j cache
}
atf_test_case json_summary
json_summary_head() { atf_set require.progs 'cc openssl'; }
json_summary_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    payload=$(stat -f %z root/lib/libdemo.so.1)
    bytes=$(stat -f %z cache)
    input=$((payload * 2))
    overhead=$((bytes - payload))
    format='{"schema":"org.5bsd.elfcache.summary.v1","format_version":2,"authenticated":%s,"payload_digests_verified":%s,"verification_key_source":"%s","entries":2,"unique_images":1,"input_bytes":%s,"unique_bytes":%s,"cache_bytes":%s,"overhead_bytes":%s}\n'
    printf "$format" false false none "$input" "$payload" "$bytes" "$overhead" > expected
    atf_check -s exit:0 -o file:expected -e empty "$tool" info -j cache
    printf "$format" true true explicit "$input" "$payload" "$bytes" "$overhead" > expected
    atf_check -s exit:0 -o file:expected -e empty "$tool" verify -j -p public cache
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out wrong-key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in wrong-key -pubout -out wrong-public
    atf_check -s not-exit:0 -o empty -e ignore "$tool" verify -j -p wrong-public cache
    chmod u+w cache
    printf x > byte
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=65540 conv=notrunc
    # Structural inspection can succeed on unauthenticated payload bytes, but
    # its machine-readable result must never imply successful verification.
    printf "$format" false false none "$input" "$payload" "$bytes" "$overhead" > expected
    atf_check -s exit:0 -o file:expected -e empty "$tool" info -j cache
    atf_check -s not-exit:0 -o empty -e ignore "$tool" verify -j -p public cache
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=0 conv=notrunc
    atf_check -s not-exit:0 -o empty -e ignore "$tool" info -j cache
    for command in inspect list; do
        atf_check -s exit:64 -o empty -e match:usage "$tool" "$command" -j cache
    done
    atf_check -s exit:64 -o empty -e match:usage "$tool" build -j -r root -o ignored
    atf_check -s exit:64 -o empty -e match:usage "$tool" extract -j -p public -o ignored cache
    [ ! -e ignored ] || atf_fail 'invalid JSON option changed output'
}
atf_test_case strict_options
strict_options_head() { atf_set require.progs 'cc openssl'; }
strict_options_body()
{
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    # Structural inspection must not silently accept a trust-key argument.
    for command in inspect list map info; do
        atf_check -s exit:64 -o empty -e match:usage "$tool" "$command" -p public cache
        atf_check -s exit:64 -o empty -e match:usage "$tool" "$command" -k key cache
        atf_check -s exit:64 -o empty -e match:usage "$tool" "$command" -o ignored cache
    done
    atf_check -s exit:64 -o empty -e match:usage "$tool" build -r root -o ignored -p public
    atf_check -s exit:64 -o empty -e match:usage "$tool" verify -r root cache
    atf_check -s exit:64 -o empty -e match:usage "$tool" verify -k key cache
    atf_check -s exit:64 -o empty -e match:usage "$tool" extract -o ignored -l selection cache
    [ ! -e ignored ] || atf_fail 'invalid option combination changed output'
}

layout_setup()
{
    [ "$(uname -p)" = amd64 ] || atf_skip 'shared layouts currently support amd64'
    setup
    atf_check -s exit:0 -o ignore "$tool" build -r root -o cache -k key
    atf_check -s exit:0 -o ignore "$tool" layout -k key -p public -o layout cache
}
atf_test_case layout_roundtrip
layout_roundtrip_head() { atf_set require.progs 'cc openssl'; }
layout_roundtrip_body()
{
    layout_setup
    atf_check -s exit:0 -o match:'verified layout_entries=' "$tool" layout-verify -p public -l layout cache
    atf_check -s exit:0 -o ignore "$tool" layout -k key -p public -o second cache
    atf_check -s exit:0 cmp layout second
    atf_check -s exit:0 cmp layout.sig second.sig
    atf_check -s exit:64 -o empty -e match:usage "$tool" layout-verify -l layout cache
}
atf_test_case layout_reject
layout_reject_head() { atf_set require.progs 'cc openssl'; }
layout_reject_body()
{
    layout_setup
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out other
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in other -pubout -out other-public
    atf_check -s not-exit:0 -o empty -e match:signature "$tool" layout-verify -p other-public -l layout cache
    mv layout.sig good.sig
    atf_check -s not-exit:0 -o empty -e match:signature "$tool" layout-verify -p public -l layout cache
    cp cache.sig layout.sig
    atf_check -s not-exit:0 -o empty -e match:signature "$tool" layout-verify -p public -l layout cache
    mv good.sig layout.sig
    chmod u+w layout
    printf x >> layout
    atf_check -s not-exit:0 -o empty -e match:signature "$tool" layout-verify -p public -l layout cache
}
atf_test_case layout_generation
layout_generation_head() { atf_set require.progs 'cc openssl dd'; }
layout_generation_body()
{
    layout_setup
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip 'capsign not installed'
    # Change only cache padding and authenticate the new generation. ELF/index
    # correspondence still matches: rejection must depend on the full digest.
    chmod u+w cache
    printf x > byte
    atf_check -s exit:0 -o ignore -e ignore dd if=byte of=cache bs=1 seek=4096 conv=notrunc
    rm cache.sig
    atf_check -s exit:0 -o ignore "$capsign" seal -k key -d org.5bsd.elf-cache.v2 -o cache.sig cache
    atf_check -s exit:0 -o ignore "$tool" verify -p public cache
    atf_check -s not-exit:0 -o empty -e match:'generation mismatch' "$tool" layout-verify -p public -l layout cache
}

atf_test_case signed_input_tamper
signed_input_tamper_head() { atf_set require.progs 'cc openssl'; }
signed_input_tamper_body()
{
    setup
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip 'capsign not installed'
    printf 'program = "cache_integrity_test";\n' > policy
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed.so root/lib/libdemo.so.1
    mv signed.so root/lib/libdemo.so.1
    # Corrupt signed payload without removing the recognized signature footer.
    # Byte 64 is outside the ELF identity/type fields inspected during scanning.
    printf '\377' > changed-byte
    atf_check -s exit:0 -o ignore -e ignore dd if=changed-byte of=root/lib/libdemo.so.1 bs=1 seek=64 conv=notrunc
    atf_check -s not-exit:0 -o ignore -e match:'invalid image signature' "$tool" build -r root -o cache -k key
    [ ! -e cache ] && [ ! -e cache.sig ] || atf_fail 'published cache from invalid signed input'
}
atf_init_test_cases()
{
    atf_add_test_case signed_input_tamper
    atf_add_test_case layout_roundtrip
    atf_add_test_case layout_reject
    atf_add_test_case layout_generation
    atf_add_test_case json_images
    atf_add_test_case json_summary
    atf_add_test_case strict_options
    atf_add_test_case signed_inputs
    atf_add_test_case extract
    atf_add_test_case extract_reject
    atf_add_test_case selection
    atf_add_test_case aliases
    atf_add_test_case tamper
    atf_add_test_case wrong_key
    atf_add_test_case escape
    atf_add_test_case no_clobber
    atf_add_test_case reproducible
}
