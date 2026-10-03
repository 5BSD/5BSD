# Attribute policy for service management

SwitchBoard can authorize explicit service-control requests using attributes
without changing UNIX program execution, file modes, process credentials, rc
startup, or the kernel's mac_abac enforcement mode. This is an opt-in first
stage of attribute policy, limited to `start`, `stop`, and global `reload`.
`restart` uses the existing stop/start client sequence; both operations must
be permitted. It is not an atomic single-operation restart grant.

## Compatibility and activation

Without the boot variable `switchboard_management_policy`, or with its value
`NO`, the existing anointment/operator authorization remains in effect.
To enable the policy for a test image, install a root-owned, non-group/world-
writable regular file at
`/Capabilities/Config/switchboard/management-policy.ucl`, and add:

```sh
switchboard_management_policy="YES"
```

to `/boot/loader.conf`. The setting is read once when SwitchBoard starts.
It is not taken from a requesting process's environment. An enabled policy
with a missing, unreadable, malformed, or untrusted file denies managed
operations; it never falls back to the old administrative bypass.
Boot and internal supervisor recovery do not consult this policy, so a bad
management rule does not prevent services from starting or users logging in.
Recovery can repair the file or disable the boot setting.

Existing status/inventory queries and a user's control of their own USER
agents remain available. CORE services cannot be started or stopped by any
runtime operator, even when a rule would allow it. In policy mode, a broad
anointment, the administrative bit, and uid 0 do not bypass service-control
rules. This policy does not yet replace the authorization for machine-wide
lifecycle operations such as reboot, other providers' admin bits, package
installation, or direct filesystem modifications.

## Trusted inputs and rules

The control connection already carries the session identity minted by
BSDAuth; a request cannot supply or change that uid. SwitchBoard resolves the
target against its registry before authorization. The policy can assign
site attributes to those exact identities. It cannot assign or override the
runtime facts `uid` (subject) or `label` and `class` (target).
The built-in target for global reload is `system.switchboard`, class
`manager`. User agents have class `user`; ordinary system services have
class `system`.

The installed example is
`/usr/share/examples/switchboard/management-policy.ucl`. Its `subjects` array
assigns attributes by numeric uid, and `targets` assigns attributes by exact
service label. Account deletion/reuse and service replacement therefore
require a review of these assignments. No publisher or executable-integrity
attribute is inferred from a path or a bundle's self-declaration.

Version 1 accepts these rule fields:

| Field | Meaning |
|---|---|
| `id` | Unique rule name, reported in the authorization audit |
| `effect` | `allow` or `deny` |
| `operations` | Nonempty array drawn from `start`, `stop`, `reload` |
| `subject` | Optional exact attribute matches for the authenticated principal |
| `target` | Optional exact attribute matches for the resolved target |
| `equal` | Optional array of `{ subject = "key"; target = "key"; }` comparisons |

Attributes are nonempty bounded strings. There are no wildcard expansions,
implicit conversions, role definitions, scripts, includes, or environment
substitutions. Missing attributes do not match, including when both sides
of an equality are missing. Every condition in a rule must match. A matched
deny wins over all allows regardless of order; otherwise any matched allow
permits exactly the requested operation. With no allow, the decision is deny.
The entire document is validated before any rule can authorize a request.
Unknown keys/operations, duplicates, unsupported versions, and invalid types
are rejected. The file is limited to 64 KiB, arrays to 128 entries, and
attribute maps and equality lists to 16 entries.

## Updates and enforcement

Publish a complete candidate by atomic rename; do not rewrite the live file
in place. Each control operation opens it with `O_VERIFY` and reads one
bounded snapshot. Once the new file is published, the next request uses the
new policy, including on a control connection opened before the change.
Removing an allow therefore removes authorization for subsequent requests.
An operation already authorized and in progress is not undone.

There is no new bearer token or protocol ABI in this stage. The authenticated
capability channel provides identity and transport; its target operation is
authorized immediately before dispatch. A scoped allow is never installed as
a general ADMIN bit on the connection. This also means the policy provides
continuous authorization for these management requests, not general
revocation of other providers' descriptors.

File ownership remains the integrity boundary on compatible images where
verified execution is inactive. A root process able to edit policy, account
credentials, or bundle files can still affect authority indirectly. This
feature is not a claim that an unrestricted UNIX root is fully confined.
Protected deployments need protected policy/identity storage, trusted boot
configuration, and verified execution as described in
[Verified Execution](../capability/veriexec.md).

## Follow-on work

Fresh authentication, application identity conditions, bundle grant approval,
policy compilation/preview, constrained delegation, and revocation of
long-lived provider grants are separate stages. Unsupported conditions are
rejected rather than accepted without enforcement. BSDAuth's login and
`anoint` behavior are unchanged by this first management-only stage.

## Compatibility verification

The reproducible harness in `tools/test/management-policy/` builds SwitchBoard
inside QEMU using all virtual CPUs and `/usr/obj`. It tests ordinary UNIX file
permissions and process execution alongside actual management requests, SSH
public-key/password sessions, password login(1), SFTP, endpoint anointments, and
password-authenticated elevation without a uid change. See the harness README
for setup, acceptance checks, and evidence export. This is targeted compatibility
coverage, not a claim that every existing UNIX application has been qualified.

## Agreed protected-mode direction

The system owner has selected an optional Protected mode while retaining
Compatible mode. Owner-controlled recovery is the default: the machine owner
must have an explicit recovery path to replace the builder's maximum authority.
A builder-controlled appliance profile is a separate deployment choice.
These are design decisions, not protections implemented by this policy patch.

Protected mode must bind boot configuration, policy, trusted identity storage,
and executable integrity to an enforced trust boundary. Runtime root must not
be able to modify those inputs, impersonate an authorized policy updater, or
silently turn enforcement off. Policy updates need bounded authorization,
validation before publication, atomic activation, and an audit trail. Recovery
must require explicit owner authorization outside ordinary runtime root authority
and must leave the system in a recoverable state after interrupted updates.
No signing keys, recovery credentials, or production defaults are changed by the
current test harness.

Acceptance tests for that future mode must include tampered policy/identity
files, unauthorized policy updates, forged or replayed update authorization,
policy expansion beyond delegated limits, interrupted publication, boot-setting
tampering, recovery with the correct owner credential, rejection of an incorrect
credential, and successful login after recovery. These cases must be implemented
and exercised before Protected mode is described as available.
