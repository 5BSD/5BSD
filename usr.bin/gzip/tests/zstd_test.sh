# SPDX-License-Identifier: BSD-2-Clause
atf_test_case frame_completion
frame_completion_head()
{
    atf_set descr "zstd EOF requires a complete frame, including drained and concatenated frames"
    atf_set require.progs "gzip zstd"
}
frame_completion_body()
{
    dd if=/dev/zero of=input bs=65536 count=16 2>/dev/null
    atf_check -o save:frame zstd -q -c input
    atf_check -o file:input gzip -d -c frame
    cat frame frame > concatenated
    cat input input > expected
    atf_check -o file:expected gzip -d -c concatenated
    size=$(stat -f %z frame)
    dd if=frame of=truncated bs=1 count=$((size - 1)) 2>/dev/null
    atf_check -s not-exit:0 -e match:"unexpected end of zstd input" -o ignore gzip -d -c truncated
    cat frame truncated > concatenated_truncated
    atf_check -s not-exit:0 -e match:"unexpected end of zstd input" -o ignore gzip -d -c concatenated_truncated
}
atf_init_test_cases()
{
    atf_add_test_case frame_completion
}
