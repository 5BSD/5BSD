#!/usr/libexec/atf-sh

atf_test_case status
status_head()
{
	atf_set "descr" "mac_abac module and control utility expose their basic ABI"
}
status_body()
{
	atf_check -s exit:0 -o match:'security.mac.mac_abac.mode' \
		sysctl security.mac.mac_abac.mode
	atf_check -s exit:0 -o ignore /usr/sbin/mac_abac_ctl status
}

reset_policy()
{
	mac_abac_ctl mode permissive >/dev/null
	mac_abac_ctl default allow >/dev/null
	mac_abac_ctl rule clear >/dev/null
	mac_abac_ctl set enable all >/dev/null
}

atf_test_case mode_and_default cleanup
mode_and_default_head()
{
	atf_set "descr" "mode and default-policy controls validate and round trip"
}
mode_and_default_body()
{
	reset_policy
	atf_check -s exit:0 -o match:permissive mac_abac_ctl mode
	atf_check -s exit:0 -o ignore mac_abac_ctl mode enforcing
	atf_check -s exit:0 -o match:enforcing mac_abac_ctl mode
	atf_check -s exit:0 -o ignore mac_abac_ctl mode permissive
	atf_check -s exit:0 -o ignore mac_abac_ctl default deny
	atf_check -s exit:0 -o match:deny mac_abac_ctl default
	atf_check -s exit:0 -o ignore mac_abac_ctl default allow
	atf_check -s not-exit:0 -o ignore -e ignore \
	    mac_abac_ctl default invalid
	reset_policy
}
mode_and_default_cleanup()
{
	reset_policy
}

atf_test_case line_atomic_load
line_atomic_load_head()
{
	atf_set "descr" "line policies compile and replace rules atomically"
}
line_atomic_load_body()
{
	reset_policy
	printf '%s\n' 'deny exec type=user -> type=blocked' >policy.rules
	atf_check -s exit:0 -o match:'loaded 1 rules' \
	    mac_abac_ctl rule load policy.rules
	atf_check -s exit:1 -o match:'Result:.*DENY' \
	    mac_abac_ctl test exec type=user type=blocked
	atf_check -s exit:0 -o match:'Loaded rules: 1' mac_abac_ctl rule list
}

atf_test_case malformed_load_preserves
malformed_load_preserves_head()
{
	atf_set "descr" "a malformed replacement leaves the live policy unchanged"
}
malformed_load_preserves_body()
{
	reset_policy
	printf '%s\n' 'deny exec * -> type=blocked' >good.rules
	mac_abac_ctl rule load good.rules >/dev/null
	printf '%s\n' 'allow not-an-operation * -> *' >bad.rules
	atf_check -s exit:1 -e ignore mac_abac_ctl rule load bad.rules
	atf_check -s exit:1 -o match:'Result:.*DENY' \
	    mac_abac_ctl test exec type=user type=blocked
}

atf_test_case long_line_rejected
long_line_rejected_head()
{
	atf_set "descr" "overlong policy lines are rejected, never split into rules"
}
long_line_rejected_body()
{
	reset_policy
	jot -b x 5000 | tr -d '\n' >long.rules
	atf_check -s exit:1 -e match:'exceeds' mac_abac_ctl rule load long.rules
	atf_check -s exit:0 -o match:'no rules' mac_abac_ctl rule list
}

atf_test_case label_lifecycle
label_lifecycle_head()
{
	atf_set "descr" "atomic label set, replace, get, and idempotent remove"
}
label_lifecycle_body()
{
	touch object
	atf_check -s exit:0 -o ignore \
	    mac_abac_ctl label set object type=file,domain=test
	atf_check -s exit:0 -o inline:'type=file,domain=test\n' \
	    mac_abac_ctl label get object
	atf_check -s exit:0 -o ignore \
	    mac_abac_ctl label set object type=replaced
	atf_check -s exit:0 -o inline:'type=replaced\n' mac_abac_ctl label get object
	atf_check -s exit:0 -o ignore mac_abac_ctl label remove object
	atf_check -s exit:0 -o inline:'(no label)\n' mac_abac_ctl label get object
	atf_check -s exit:0 -o ignore mac_abac_ctl label remove object
}

atf_test_case invalid_label_preserves
invalid_label_preserves_head()
{
	atf_set "descr" "invalid labels cannot corrupt the persistent label"
}
invalid_label_preserves_body()
{
	touch object
	mac_abac_ctl label set object type=valid >/dev/null
	atf_check -s exit:65 -e match:'invalid label format' \
	    mac_abac_ctl label set object type=one,type=two
	atf_check -s exit:0 -o inline:'type=valid\n' mac_abac_ctl label get object
}

atf_test_case recursive_labels
recursive_labels_head()
{
	atf_set "descr" "recursive labeling honors file and directory selectors"
}
recursive_labels_body()
{
	mkdir -p tree/sub
	touch tree/a tree/sub/b
	atf_check -s exit:0 -o ignore \
	    mac_abac_ctl label setrecursive tree type=file -f
	atf_check -s exit:0 -o inline:'type=file\n' mac_abac_ctl label get tree/a
	atf_check -s exit:0 -o inline:'(no label)\n' mac_abac_ctl label get tree
	atf_check -s exit:0 -o ignore \
	    mac_abac_ctl label setrecursive tree type=dir -d
	atf_check -s exit:0 -o inline:'type=dir\n' mac_abac_ctl label get tree/sub
}

atf_test_case max_set
max_set_head()
{
	atf_set "descr" "set 65535 and the full set range do not wrap"
}
max_set_body()
{
	reset_policy
	atf_check -s exit:0 -o ignore mac_abac_ctl set disable 65535
	atf_check -s exit:0 -o match:'65535.*no' mac_abac_ctl set list 65535
	atf_check -s exit:0 -o ignore mac_abac_ctl set enable all
}

write_valid_ucl()
{
	cat >policy.ucl <<'EOF'
mode = "permissive";
default_policy = "deny";
rules = [{ action = "allow"; operations = ["exec", "wait", "audit"];
    subject = { type = "user"; }; object = { type = "program"; }; }];
EOF
}

atf_test_case ucl_compile
ucl_compile_head()
{
	atf_set "descr" "daemon and control tool compile a complete UCL policy"
}
ucl_compile_body()
{
	write_valid_ucl
	atf_check -s exit:0 -o match:'configuration OK' -e ignore \
	    mac_abacd -t -c policy.ucl
	atf_check -s exit:0 -o match:'1 valid' -e ignore \
	    mac_abac_ctl rule validate -f policy.ucl
}

define_invalid_ucl_case()
{
	name=$1
	description=$2
	body=$3
	eval "
	atf_test_case ucl_reject_${name}
	ucl_reject_${name}_head() { atf_set 'descr' '${description}'; }
	ucl_reject_${name}_body() {
		cat >bad.ucl <<'EOF'
${body}
EOF
		atf_check -s exit:1 -e ignore mac_abacd -t -c bad.ucl
	}
	"
}

define_invalid_ucl_case unknown_root "unknown policy keys are rejected" \
    'surprise = true; rules = [];'
define_invalid_ucl_case unknown_operation "unknown operations are rejected" \
    'rules = [{ action="allow"; operations=["warp"]; }];'
define_invalid_ucl_case unknown_rule_key "unknown rule keys are rejected" \
    'rules = [{ action="allow"; mystery=true; }];'
define_invalid_ucl_case bad_context "invalid context types are rejected" \
    'rules = [{ action="allow"; subj_ctx={ uid="root"; }; }];'
define_invalid_ucl_case removed_transition "transition actions are unsupported" \
    'rules = [{ action="transition"; operations=["read"]; newlabel="type=x"; }];'
define_invalid_ucl_case append "non-atomic append policies are rejected" \
    'append = true; rules = [];'

atf_init_test_cases()
{
	atf_add_test_case status
	atf_add_test_case mode_and_default
	atf_add_test_case line_atomic_load
	atf_add_test_case malformed_load_preserves
	atf_add_test_case long_line_rejected
	atf_add_test_case label_lifecycle
	atf_add_test_case invalid_label_preserves
	atf_add_test_case recursive_labels
	atf_add_test_case max_set
	atf_add_test_case ucl_compile
	atf_add_test_case ucl_reject_unknown_root
	atf_add_test_case ucl_reject_unknown_operation
	atf_add_test_case ucl_reject_unknown_rule_key
	atf_add_test_case ucl_reject_bad_context
	atf_add_test_case ucl_reject_removed_transition
	atf_add_test_case ucl_reject_append
}
