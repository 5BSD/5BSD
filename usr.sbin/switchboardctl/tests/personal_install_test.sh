# SPDX-License-Identifier: BSD-2-Clause
# Offline roots only: never changes host /Capabilities or its trust catalogue.

prepare_root()
{
	tool="$(atf_get_srcdir)/switchboardctl_test_bin"
	[ -x "$tool" ] || atf_fail "static switchboardctl test binary missing"
	mkdir -p root/etc/capability/keys root/Capabilities/Users/65534
	chmod 0755 root root/etc root/etc/capability root/etc/capability/keys \
	    root/Capabilities root/Capabilities/Users
	chown 65534:65534 root/Capabilities/Users/65534
	chmod 0755 root/Capabilities/Users/65534
	# Chroot uses a static real CLI; marker presence forces the global policy.
	cp "$tool" root/tool
	chmod 0555 root/tool
	: > root/etc/capability/require-signatures
	chmod 0444 root/etc/capability/require-signatures
	mkdir -p root/source.cap/Units/worker.unit/bin
	cat > root/source.cap/Bundle.ucl <<'BUNDLE'
schema = "org.5bsd.capability-bundle";
bundle_id = "org.test.personal.install";
version = "1.0";
sequence = 1;
author = "test";
publisher = "personal";
units = ["worker"];
BUNDLE
	printf '%s\n' 'control = "user"; domain = "user"; activation { ipc = ["org.test.personal.worker"]; }' \
	    > root/source.cap/Units/worker.unit/Unit.ucl
	cp /usr/bin/true root/source.cap/Units/worker.unit/bin/worker
	chmod 0644 root/source.cap/Bundle.ucl root/source.cap/Units/worker.unit/Unit.ucl
	chmod 0755 root/source.cap/Units/worker.unit/bin/worker
	dst=root/Capabilities/Users/65534/Agents/org.test.personal.install@00000000000000000001.cap
	personal="$(pwd)/personal-run"
	printf '#!/bin/sh\nexec chroot -u nobody -g nobody "%s" /tool "$@"\n' "$(pwd)/root" > "$personal"
	chmod 0755 "$personal"
}

sign_fixture()
{
	capsign="$(atf_config_get capsign /usr/sbin/capsign)"
	[ -x "$capsign" ] || atf_fail "capsign missing"
	openssl genpkey -algorithm ED25519 -out key.pem >/dev/null 2>&1 || atf_fail "keygen"
	"$capsign" sign -r -k key.pem -o root/signed.cap root/source.cap || atf_fail "sign fixture"
	chmod 0755 root/signed.cap
}

atf_test_case unsigned_signed_system
unsigned_signed_system_head()
{
	atf_set require.user root
	atf_set descr "Unsigned personal install works while global signatures remain mandatory"
}
unsigned_signed_system_body()
{
	prepare_root
	atf_check -s exit:0 -o match:'Verification: PASSED' "$personal" verify --personal /source.cap
	atf_check -s exit:1 -e match:'signed bundle inventory required' "$personal" verify /source.cap
	atf_check -s exit:0 -o match:'published /Capabilities/Users/65534/Agents/' "$personal" install --personal /source.cap
	atf_check -o inline:'65534\n' stat -f %u "$dst/Units/worker.unit/bin/worker"
	atf_check -s exit:0 -o match:'Verification: PASSED' "$personal" verify --personal \
	    /Capabilities/Users/65534/Agents/org.test.personal.install@00000000000000000001.cap
	atf_check -s exit:1 -e match:'File exists' "$personal" install --personal /source.cap
	atf_check -s exit:1 -e match:'signed bundle inventory required' chroot root /tool install /source.cap
	atf_check test -f root/etc/capability/require-signatures
}

atf_test_case personal_key
personal_key_head()
{
	atf_set require.user root
	atf_set require.progs openssl
	atf_set descr "Personal signatures verify without platform trust and preserve sealed modes"
}
personal_key_body()
{
	prepare_root
	sign_fixture
	atf_check -s exit:0 -o match:'Verification: PASSED' "$personal" verify --personal /signed.cap
	atf_check -s exit:1 -e not-empty "$personal" verify /signed.cap
	atf_check -s exit:0 -o match:published "$personal" install --personal /signed.cap
	atf_check -o inline:'755\n' stat -f %Lp "$dst/Units/worker.unit/bin/worker"
	atf_check -o inline:'644\n' stat -f %Lp "$dst/Bundle.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' "$personal" verify --personal \
	    /Capabilities/Users/65534/Agents/org.test.personal.install@00000000000000000001.cap
	printf X >> "$dst/Units/worker.unit/bin/worker"
	atf_check -s exit:1 -e not-empty "$personal" verify --personal \
	    /Capabilities/Users/65534/Agents/org.test.personal.install@00000000000000000001.cap
}

atf_test_case rejection
rejection_head()
{
	atf_set require.user root
	atf_set descr "Personal mode rejects malformed signatures, unsafe modes and restricted attributes"
}
rejection_body()
{
	prepare_root
	mkdir root/source.cap/Signature
	printf broken > root/source.cap/Signature/Seal
	atf_check -s exit:1 -e not-empty "$personal" verify --personal /source.cap
	atf_check -s exit:1 -e not-empty "$personal" install --personal /source.cap
	rm -r root/source.cap/Signature
	printf '%s\n' 'control = "core"; domain = "system"; activation { ipc = ["org.test.personal.worker"]; }' \
	    > root/source.cap/Units/worker.unit/Unit.ucl
	atf_check -s exit:1 -e match:'no platform grants' "$personal" verify --personal /source.cap
	atf_check -s exit:1 -e match:'no platform grants' "$personal" install --personal /source.cap
	printf '%s\n' 'control = "user"; domain = "user"; activation { ipc = ["org.test.personal.worker"]; }' \
	    > root/source.cap/Units/worker.unit/Unit.ucl
	chmod 0666 root/source.cap/Bundle.ucl
	atf_check -s exit:1 -e not-empty "$personal" install --personal /source.cap
	chmod 0644 root/source.cap/Bundle.ucl
	ln -s /etc/capability/require-signatures root/source.cap/Units/worker.unit/bin/escape
	atf_check -s exit:1 -e not-empty "$personal" install --personal /source.cap
	atf_check -o empty find root/Capabilities/Users/65534/Agents -mindepth 1 -print
}

atf_test_case signed_restricted
signed_restricted_head()
{
	atf_set require.user root
	atf_set require.progs openssl
	atf_set descr "A valid personal signature cannot authorize platform attributes"
}
signed_restricted_body()
{
	prepare_root
	printf '%s\n' 'control = "core"; domain = "system"; activation { ipc = ["org.test.personal.worker"]; }' \
	    > root/source.cap/Units/worker.unit/Unit.ucl
	sign_fixture
	atf_check -s exit:1 -e match:'no platform grants' "$personal" verify --personal /signed.cap
	atf_check -s exit:1 -e match:'no platform grants' "$personal" install --personal /signed.cap
}

atf_test_case destinations
destinations_head()
{
	atf_set require.user root
	atf_set descr "Personal installation cannot follow destination symlinks or enter another owner's root"
}
destinations_body()
{
	prepare_root
	mkdir root/escape
	chown 65534:65534 root/escape
	ln -s /escape root/Capabilities/Users/65534/Agents
	atf_check -s exit:1 -e not-empty "$personal" install --personal /source.cap
	rm root/Capabilities/Users/65534/Agents
	chown 0:0 root/Capabilities/Users/65534
	atf_check -s exit:1 -e match:provisioned "$personal" install --personal /source.cap
	chown 65534:65534 root/Capabilities/Users/65534
	chmod 0777 root/Capabilities/Users
	atf_check -s exit:1 -e not-empty "$personal" install --personal /source.cap
	atf_check -o empty find root/escape -mindepth 1 -print
}

atf_init_test_cases()
{
	atf_add_test_case unsigned_signed_system
	atf_add_test_case personal_key
	atf_add_test_case rejection
	atf_add_test_case signed_restricted
	atf_add_test_case destinations
}
