#!/usr/bin/env atf-sh

atf_test_case reject_ilp32
reject_ilp32_head()
{
	atf_set "descr" "OpenEndpointSecurity rejects 32-bit consumers"
}

reject_ilp32_body()
{
	cat > consumer.c <<'EOF'
#include <security/oes/oes.h>
int main(void) { return (0); }
EOF
	atf_check -s not-exit:0 \
	    -e match:"OpenEndpointSecurity requires a 64-bit kernel and userspace" \
	    cc -m32 -c consumer.c
}

atf_init_test_cases()
{
	atf_add_test_case reject_ilp32
}
