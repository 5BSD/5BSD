# SPDX-License-Identifier: BSD-2-Clause
#
# The dq(4) test option and publication (design D346, D352).
#
# Everything here is sh: the cases run where no Python exists.  The
# publication recipe is exercised from a private copy of
# release/Makefile.hardware and its check scripts installed beside this
# test, never from /usr/src and never towards /usr/obj/usr/src/repo.

setup()
{
    tool=$(atf_config_get bsd_build /usr/sbin/build-bsd)
    [ -f "$tool" ] || atf_fail 'build-bsd not installed'
    [ -f /usr/src/Makefile ] || atf_fail 'the build frontend requires /usr/src/Makefile'
    here=$(atf_get_srcdir)
}

# A private source tree holding only the publication recipe.
private_tree()
{
    mkdir -p src/release/scripts
    cp "$here/Makefile.hardware" src/release/Makefile.hardware
    for script in "$here"/check-*.sh; do
        cp "$script" src/release/scripts/
    done
}

publish()
{
    make -C "$PWD/src" -f release/Makefile.hardware "$@" \
        PKG_CMD=/usr/bin/true HARDWARE_PYTHON=/usr/bin/false \
        BASE_REPOSITORY="$PWD/base" HARDWARE_REPO="$PWD/hardware" \
        COMPLETE_REPOSITORY="$PWD/published/complete" publish-packages
}

option_configuration()
{
    mkdir -p conf
    cat > conf/LG2OPTION <<'CONF'
include GENERIC
ident LG2OPTION
options 	DQ_TEST_OPEN
CONF
}

atf_test_case plan_option_configuration
plan_option_configuration_head()
{
    atf_set descr 'A package plan for a configuration carrying the dq test option'
}
plan_option_configuration_body()
{
    setup
    option_configuration
    # Pin (before the option exists): the frontend does not read kernel
    # configurations, so the plan is accepted and says nothing about it.
    atf_check -s exit:0 -o save:plan -e empty "$tool" plan packages \
        --kernel LG2OPTION --kernel-dir "$PWD/conf"
    atf_check -s exit:0 -o ignore grep '^system-packages:.*KERNCONF=LG2OPTION' plan
    atf_check -s exit:1 -o empty grep 'kernel-test-option' plan
}

atf_test_case publish_recipe
publish_recipe_head()
{
    atf_set descr 'The order of the publication recipe'
}
publish_recipe_body()
{
    setup
    private_tree
    atf_check -s exit:0 -o save:recipe -e ignore publish -n
    # Pin (before the option exists): the destination parent is created
    # first, then the malloc(3) check; no kernel check.
    atf_check -s exit:0 -o match:'^mkdir -p ' sed -n 1p recipe
    atf_check -s exit:0 -o match:'check-malloc-production.sh  *-r ' sed -n 2p recipe
    atf_check -s exit:1 -o empty grep 'check-kernel-no-dq-test' recipe
    [ ! -e published ] || atf_fail 'a dry run created the destination'
}

atf_init_test_cases()
{
    atf_add_test_case plan_option_configuration
    atf_add_test_case publish_recipe
}
