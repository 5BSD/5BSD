# Discovery and software authority

This page previously tracked the transition from authenticated-user grants to
software attributes. That design diary contained intermediate implementation
states and is no longer the specification or a release checklist.

The current design is documented in:

- [The authority model](book/src/capability/authority-model.md): inherited discovery,
  executable identity, issuance, revocation, and resource isolation.
- [Software Attributes](book/src/plane/attributes.md): client attributes and
  endpoint requirements.
- [UNIX Authentication and Software Authority](book/src/providers/auth.md):
  ordinary UNIX authentication and removal of the user-grant model.
- [Software Policy and Service Management](book/src/plane/management-policy.md):
  software admission and management policy.

Discovery is a kernel-held route, not an administrative credential. Software
attributes govern capability admission; login accounts retain their ordinary
UNIX permissions. Responsible-process attribution and coalitions remain separate
from authorization. BSDAuth provisioning and the old principal-grant policy are
retired.

The implementation does not by itself prove that all executable code, libraries,
loaders, or mutable configuration are signature-verified. See the authority
model's integrity limits. Source cleanup also does not uninstall old packages;
upgrade behavior requires separate validation.

Historical component-test results in earlier revisions are not acceptance
results for newer builds. Fresh world/kernel/modules builds, installed-system
checks, boot-environment tests, and artifact qualification must identify the
source revision and artifacts they actually exercised.
