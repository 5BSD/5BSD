# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
def _config(ctx):
    lines = ["/* Generated from explicit SSH build settings. */", '#include "ssh_namespace.h"']
    if ctx.attr.kerberos[BuildSettingInfo].value:
        lines.append('#include "krb5_config.h"')
        if not ctx.attr.mit[BuildSettingInfo].value:
            lines.append("#define HEIMDAL 1")
    if ctx.attr.usb[BuildSettingInfo].value:
        lines.append('#include "sk_config.h"')
    for setting, macro in [(ctx.attr.xauth, "XAUTH_PATH"), (ctx.attr.askpass, "_PATH_SSH_ASKPASS_DEFAULT")]:
        value = setting[BuildSettingInfo].value
        if value:
            if not value.startswith("/") or "\n" in value or "\r" in value:
                fail("SSH helper path must be absolute and contain no line breaks")
            lines.append("#define " + macro + " " + json.encode(value))
    output = ctx.actions.declare_file(ctx.label.name + ".h")
    ctx.actions.write(output, "\n".join(lines) + "\n")
    return [DefaultInfo(files = depset([output]))]
ssh_configuration = rule(implementation = _config, attrs = {
    name: attr.label(providers = [BuildSettingInfo], mandatory = True)
    for name in ["kerberos", "mit", "usb", "xauth", "askpass"]
})
