# cap_rt Isolation Expansion Plan

This plan maps the existing `cap_rt_isolation` service to a richer
resource policy model for oracled and serviced.

The current implementation is nonce and token based:

- oracled claims resources through `cap_rt_isolation`
- serviced requests tokens from oracled
- child services authorize token fds after exec
- MACF hooks allow the owning nonce or an authorized token holder

That model is the right foundation.  The missing piece is token
narrowing: claims establish ownership of a resource, while tokens
should express the subset of access delegated to a service.

## Existing State

Kernel isolation protocol:

- `FI_OP_CLAIM` claims a vnode by fd.
- `FI_OP_RELEASE` releases a vnode claim.
- `FI_OP_QUERY` queries a vnode claim.
- `FI_OP_CLAIM_NET` claims a network endpoint.
- `FI_OP_RELEASE_NET` releases a network endpoint.
- `FI_OP_QUERY_NET` queries a network endpoint claim.
- `FI_OP_MINT` mints a full vnode access token.
- `FI_OP_MINT_NET` mints a full network access token.
- `FI_OP_AUTHORIZE` activates a token for the caller nonce.

Kernel enforcement:

- Vnode claims are keyed by vnode identity, not path.
- Directory claims gate traversal through `mpo_vnode_check_lookup`.
- Vnode authorization supports narrowed action masks through
  `FI_OP_MINT`; callers supply a valid `FI_FS_*` mask to scope
  the minted token.
- Network claims already support domain, protocol, port, direction,
  address, CIDR prefix, and port ranges.
- Network wildcards are represented as zero values except port
  wildcard, which is the explicit range `0..65535`.

Userland policy:

- oracled config has global `claim_paths[]`, `claim_net[]`, and
  `claim_system`.
- serviced manifests have `cap_paths[]`, `cap_net[]`, and
  `cap_system`.
- The oracled-to-serviced mint protocol carries filesystem action
  masks and ranged network tuples.

Implementation checkpoint:

- `FI_OP_QUERY_NET` is implemented in the kernel and oracled status
  uses it to mark network claims that are not held.
- `FI_OP_CLAIM_NET`, `FI_OP_RELEASE_NET`, and `FI_OP_MINT_NET` carry
  `port_min`/`port_max`; there is no separate `NET2` API.
- Network parser forms include `ports = "*"`, `ports = "A-B"`,
  `ports = ".N"`/`ports = "<N"`, and wildcard protocol/domain/
  direction values.
- DTrace has a generic denial probe and a network-specific denial
  probe with owner nonce, caller nonce, claim id, domain, packed
  protocol/direction, and host-order port.
- DTrace oracled probes for claim-net and mint-net carry port_min
  and port_max for range visibility.  The redundant `port` field
  was removed from `oracled_net_claim` and `serviced_net_claim`.
- Jail mint probes (mint-jail) are declared and fired.
- Directory namespace MACF hooks (unlink, link, rename_from,
  rename_to) check both the directory vnode and the file vnode,
  matching the create hook pattern.
- Port/jail UCL parsers are shared between oracled and serviced
  via claim_parse.c / claim_parse.h.
- Jail MACF enforcement releases fi_jail_lock before acquiring
  fi_auth_lock, matching the vnode and net lock ordering patterns.
- Jail claim matching requires both JID and name to match when
  both are specified in the claim.  Single-key claims match on
  that key alone.  This prevents a token for "oracled.net" JID 5
  from authorizing operations on a different jail reusing JID 5.
- `fi_check_prison_create` bounds the jail name from `vfs_getopt`
  into a NUL-terminated stack buffer before matching.
- Invalid action bits in jail claim requests are now rejected
  even when actions are optional (claim/release paths).
- Jail claim conflict fires a DTrace deny probe.

## Naming

Use resource nouns consistently:

- `claim_file`: vnode-backed file, directory, device, FIFO, or Unix
  socket claim.
- `claim_net`: network endpoint claim.
- `claim_system`: system gate claim.
- `claim_jail`: jail identity or JID claim.

The existing code often says `claim_path`.  That is useful in
oracled userland because the oracle opens a path to obtain the vnode
fd, but the kernel claim is not actually path based.  New external
interfaces should prefer `claim_file` to avoid implying path-glob
enforcement in `cap_rt_isolation`.

Suggested transition:

- Keep old ABI names such as `FI_OP_CLAIM` until a protocol bump.
- Rename userland helpers from `claim_path()` toward `claim_file()`
  where the function actually claims a vnode-backed resource.
- Keep manifest keys readable:
  - `files = [...]` or `claim_files = [...]` for oracle-owned claims
  - `cap_files = [...]` for service-delegated file capabilities
  - `claim_net = [...]`
  - `cap_net = [...]`

## Core Design

Claims should be broad ownership records.  Tokens should be narrowed
delegations.

Example:

```ucl
claims {
    claim_files = [
        "/dev/cap_rt",
        "/var/lib/oracled",
    ];
    claim_net = [
        { protocol = "*"; address = "*"; ports = "*"; direction = "bind"; },
    ];
}
```

Service manifest:

```ucl
capabilities {
    cap_files = [
        { path = "/var/lib/oracled/state.db"; actions = ["read", "write"]; },
        { path = "/var/lib/oracled/run"; actions = ["lookup", "create"]; },
    ];
    cap_net = [
        { protocol = "tcp"; address = "10.0.0.0/8"; ports = "443"; direction = "connect"; },
    ];
}
```

oracled validates that each requested capability is covered by an
oracle-owned claim, then asks `cap_rt_isolation` to mint a narrowed
token.  The kernel stores the narrowed token policy and MACF hooks
check the requested action against that policy.

Token activation must be multi-consumer and idempotent:

- Multiple processes may receive the same token fd and call
  `FI_OP_AUTHORIZE`.
- Each distinct caller nonce should be added to the authorization set
  for that token's owner/claim.
- Repeated `FI_OP_AUTHORIZE` calls by the same nonce on the same token
  must not create duplicate authorization entries.
- `dup()` creates multiple fd references to the same token file
  instance; all references share one token lifetime.
- Authorization entries should be removed when the token instance is
  revoked, which happens when the final fd reference to that token
  instance is closed.

## Filesystem Actions

Add filesystem action bits to the isolation protocol.

Recommended action names:

- `FI_FS_LOOKUP`: traverse a directory during path resolution.
- `FI_FS_STAT`: inspect metadata.
- `FI_FS_READ`: read file data or symlink target.
- `FI_FS_WRITE`: write existing file data.
- `FI_FS_APPEND`: append-only write if the hook path can enforce it.
- `FI_FS_CREATE`: create a directory entry.
- `FI_FS_DELETE`: unlink a file or remove a directory.
- `FI_FS_RENAME_FROM`: move a name out of a directory.
- `FI_FS_RENAME_TO`: move a name into a directory.
- `FI_FS_LINK`: create a hard link.
- `FI_FS_SYMLINK`: create a symlink if a MACF hook is available.
- `FI_FS_EXEC`: execute a file.
- `FI_FS_SETATTR`: chmod, chown, chflags, utimes, or similar metadata
  mutation.
- `FI_FS_TRUNCATE`: truncate file content.
- `FI_FS_UIPC_CONNECT`: connect to a Unix domain socket vnode.

Practical groups:

- `read_only`: `LOOKUP`, `STAT`, `READ`
- `read_write`: `read_only`, `WRITE`, `APPEND`, `TRUNCATE`
- `mutate_dir`: `LOOKUP`, `STAT`, `CREATE`, `DELETE`,
  `RENAME_FROM`, `RENAME_TO`, `LINK`, `SYMLINK`
- `admin`: `mutate_dir`, `SETATTR`
- `execute`: `LOOKUP`, `STAT`, `READ`, `EXEC`

Do not advertise an action until there is a concrete MACF hook mapping
for it.

## Filesystem Hook Mapping

Each vnode MACF hook should pass an action mask into the common
authorization path.

Expected mapping:

```text
mpo_vnode_check_open         -> READ, WRITE, APPEND, CREATE, TRUNCATE
mpo_vnode_check_exec         -> EXEC
mpo_vnode_check_unlink       -> DELETE
mpo_vnode_check_link         -> LINK
mpo_vnode_check_rename_from  -> RENAME_FROM
mpo_vnode_check_rename_to    -> RENAME_TO
mpo_vnode_check_setmode      -> SETATTR
mpo_vnode_check_setowner     -> SETATTR
mpo_vnode_check_setflags     -> SETATTR
mpo_vnode_check_setutimes    -> SETATTR
mpo_vnode_check_truncate     -> TRUNCATE
mpo_vnode_check_stat         -> STAT
mpo_vnode_check_access       -> READ, WRITE, EXEC based on accmode
mpo_vnode_check_readlink     -> READ
mpo_vnode_check_lookup       -> LOOKUP
mpo_vnode_check_create       -> CREATE
mpo_vnode_check_uipc_connect -> UIPC_CONNECT
```

Rename requires checks on both sides:

- source parent needs `RENAME_FROM`
- destination parent needs `RENAME_TO`
- replacing an existing destination may also require `DELETE` on the
  destination object

Directory semantics:

- `LOOKUP` lets a process traverse a directory.
- `STAT` lets a process inspect the directory metadata.
- `LIST` should be added only if a directory enumeration hook exists
  or lands later.
- `CREATE`, `DELETE`, `RENAME_FROM`, and `RENAME_TO` control names
  inside the directory.

## Protocol Changes

Prefer v2 operations for filesystem actions because the old file
request shape cannot carry an action mask.  Network never reached a
stable 1.0 API, so use the normal network request shape with range
fields instead of carrying separate `*_NET2` operations.

Keep the oracled-to-serviced pair protocol identity at 0.0.1 while
these additions land.  New requests may be added as compatible opcodes,
but `ORACLE_PROTO_VERSION` should not be bumped until the existing
0.0.1 message meanings or required startup negotiation actually change.

The vnode request struct (`struct fi_request`) now carries an `actions`
field used by `FI_OP_MINT` and `FI_OP_QUERY`:

```c
struct fi_request {
    uint32_t op;
    uint32_t flags;
    uint64_t actions;   /* FI_FS_* mask */
};
```

The target is still passed as an fd.  `actions` is required for
minting (scopes the token) and query filtering.  Claim and release
operations ignore the field.

Network request:

```c
struct fi_net_request {
    uint32_t op;
    uint32_t flags;
    int32_t domain;
    int32_t protocol;
    uint16_t port_min;
    uint16_t port_max;
    uint8_t direction;
    uint8_t prefix;
    uint8_t addr[16];
};
```

Port forms compile as:

- `*` -> `0..65535`
- `443` -> `443..443`
- `8000-8999` -> `8000..8999`
- `<1024` -> `1..1023`
- `<=1024` -> `1..1024`
- `>49151` -> `49152..65535`

Avoid using `.` as a port operator.  It is compact but unclear in
configuration and logs.

## Kernel Data Changes

Extend token/auth state:

- add `fa_fs_actions` to `struct fi_auth`
- add `fip_token_fs_actions` to `struct fi_priv`
- keep `fa_net` for network tokens, using the ranged
  `struct fi_net_request`

Change common authorization:

- `fi_check_vp_common()` should take a requested filesystem action
  mask.
- owner nonce still allows all actions on its own claim.
- token authorization allows only if `(token_actions & requested) ==
  requested`.
- DTrace denial probes should include the requested action mask and,
  if available, the claim id.

Network authorization:

- existing exact-port matching should be generalized to range matching.
- conflict detection should treat overlapping port ranges as
  conflicts for foreign nonces.
- token coverage should require requested tuple to be a subset of the
  claimed tuple.

## oracled Changes

oracled needs to become the policy compiler between config/manifests
and kernel claims/tokens.

Tasks:

- Rename internal helpers toward `claim_file()` and `release_file()`
  where they claim a vnode-backed resource.
- Preserve old config parsing temporarily for `paths = [...]`, but add
  `claim_files = [...]`.
- Extend global network claims to include address/prefix and port
  ranges.
- Extend the oracle pair protocol:
  - `ORACLE_OP_MINT_PATH` (uses `FI_OP_MINT` with actions mask)
  - `ORACLE_OP_MINT_NET` carries port ranges
- Validate requested service capabilities against oracle-owned claims.
- Keep `FI_OP_QUERY_NET` status verification covered by tests.
- Include action/range information in status output.

Suggested oracle structs:

```c
struct oracled_file_claim {
    char path[PATH_MAX];
};

struct oracled_file_cap {
    char path[PATH_MAX];
    uint64_t actions;
};

struct oracled_net_claim {
    int domain;
    int protocol;
    uint16_t port_min;
    uint16_t port_max;
    uint8_t direction;
    uint8_t prefix;
    uint8_t addr[16];
};
```

## serviced Changes

serviced manifests should request capabilities, not claims.

Tasks:

- Replace plain `cap_paths[]` with structured `cap_files[]`.
- Keep compatibility for old `cap_paths = [...]` by treating each path
  as a full-access file token during transition.
- Replace `serviced_net_claim` with `serviced_net_cap` using the same
  range/address shape as oracled.
- Request `ORACLE_OP_MINT_PATH` and ranged `ORACLE_OP_MINT_NET`.
- Pass token fds to children and authorize after exec as today.

Suggested manifest form:

```ucl
capabilities {
    files = [
        { path = "/etc/resolv.conf"; actions = ["read"] },
        { path = "/var/run/myapp"; actions = ["lookup", "create", "delete"] },
    ];
    network = [
        { protocol = "tcp"; direction = "connect"; address = "10.0.0.0/8"; ports = "443" },
    ];
}
```

## Jail Claims

Jail authority should follow the same claim/token pattern, but it
should probably live in a dedicated `cap_rt_jail` service instead of
overloading file/network isolation.

Reasoning:

- Jails are not vnodes or sockets.
- JID allocation is a namespace/resource operation.
- Jail creation has policy-heavy parameters: name, path, host,
  IPs, allow flags, Linux compatibility, mount setup, and cleanup.
- The repo already notes that jail creation is currently a raw
  `jail_set()` path and needs a cap_rt service.

The kernel already has MACF prison hooks that can enforce this:

- `mpo_prison_check_create(cred, opts, flags)` runs before a new jail
  is allocated and receives the raw `vfsoptlist`.
- `mpo_prison_check_get(cred, pr, opts, flags)` runs before jail
  metadata is exposed.
- `mpo_prison_check_set(cred, pr, opts, flags)` runs before updates.
- `mpo_prison_check_attach(cred, pr)` runs before attach.
- `mpo_prison_check_remove(cred, pr)` runs before removal.
- `mpo_prison_created(cred, pr)` runs after successful creation.
- `mpo_prison_attached(cred, pr, p, ...)` runs after attach.

`kern_jail_set()` reads the requested `jid` option before the create
hook runs.  That means `cap_rt_jail` can deny a specific-JID create
unless the caller owns a matching `claim_jid`.  The create hook can
also inspect requested jail name and other options before the jail is
visible.

Jail descriptor operations resolve to a `struct prison` before attach
or remove.  `jail_attach_jd(2)` still reaches
`mpo_prison_check_attach`, and jail descriptor cleanup/removal should
be treated as the same authority question as numeric JID removal.

Important enforcement constraint: MACF prison check hooks run through
`MAC_POLICY_CHECK_NOSLEEP`.  They must consult already-loaded in-memory
state only.  Do not perform blocking cap_rt calls, pathname lookups,
allocation-heavy parsing, or service RPC from the hook.

Proposed names:

- `claim_jail_name`: reserve a jail name.
- `claim_jid`: reserve a specific JID.
- `create_jail`: create a jail under a claimed name/JID.
- `mint_jail`: delegate authority over an existing jail.
- `query_jail`: query claim/create state.
- `release_jail`: release a claim or remove a created jail.

Suggested protocol:

```c
#define JAIL_OP_CLAIM_NAME      1
#define JAIL_OP_CLAIM_JID       2
#define JAIL_OP_RELEASE_NAME    3
#define JAIL_OP_RELEASE_JID     4
#define JAIL_OP_CREATE          5
#define JAIL_OP_REMOVE          6
#define JAIL_OP_QUERY           7
#define JAIL_OP_MINT            8
#define JAIL_OP_AUTHORIZE       9
```

Policy:

- If a service wants a specific JID, it must request a `claim_jid`.
- JIDs 0-2 remain reserved for oracle/system infrastructure unless
  explicitly claimed by oracled at boot.
- Normal agents should request names, not numeric JIDs.
- oracled should own the name-to-JID assignment and expose the result
  through status/query.
- Names should be canonical and scoped, for example
  `oracled.<agent>` or `oracled.<domain>.<service>`.

Suggested config:

```ucl
claims {
    claim_jails = [
        { name = "oracled.sys", jid = 1 },
        { name = "oracled.linux", jid = 2 },
        { name = "oracled.net" },
    ];
}
```

Suggested manifest:

```ucl
jail {
    name = "net";
    require_jid = false;
    params = {
        path = "/var/jails/net";
        host.hostname = "net";
    };
}
```

Specific-JID requests should be rare and auditable.  Most manifests
should use names and let oracled allocate JIDs.

## DTrace and Audit

Add DTrace probes for every new authorization boundary.  These probes
are not debug logs; they are the operational interface for observing
capability flow and policy decisions.

File probes:

- `claim-file`, `release-file`, `mint-file`, `authorize-file`
- `check-file-allow`, `check-file-deny`
- `file-token-narrow`

Network probes:

- `claim-net`, `release-net`, `mint-net`, `authorize-net`
- `check-net-allow`, `check-net-deny`
- `net-token-narrow`
- `query-net`

Jail probes:

- `claim-jail-name`, `claim-jid`, `create-jail`, `remove-jail`
- `set-jail`, `attach-jail`, `query-jail`
- `mint-jail`, `authorize-jail`
- `check-jail-allow`, `check-jail-deny`

Probe arguments should include stable, safe context:

- resource type: file, net, jail
- operation/action mask
- claim id
- token id if available
- owner nonce
- caller nonce
- result or errno
- requested JID or actual JID
- jail name when safe and bounded
- network domain, protocol, port range, direction, prefix
- filesystem vnode type if cheaply available

Avoid:

- bearer token contents
- raw unbounded user strings
- secrets
- blocking formatting work
- allocations solely to build probe arguments

Denial probes must include enough context to answer "which service was
denied what and why" without requiring logs.

Add audit events for durable security decisions:

- denied file action
- denied network action
- denied jail claim/create/remove
- policy load/reload
- minting broad tokens such as full filesystem mutation, wildcard
  network, or specific-JID jail authority

## Tests

Tests should prove the policy model, not only happy-path behavior.
Every new action/filter should have at least one test that would fail
if the implementation accidentally grants a broader right.

Kernel isolation tests:

- read token allows read and denies write
- write token denies execute
- create token permits creating inside claimed directory
- create token does not imply delete
- rename requires source and destination authority
- stat-only token denies open
- Unix socket connect requires `FI_FS_UIPC_CONNECT`
- net range token permits included port and denies excluded port
- net CIDR token permits included address and denies excluded address
- wildcard protocol token covers TCP and UDP if configured
- `FI_OP_QUERY_NET` reports kernel state
- exact file token does not authorize sibling files
- directory `LOOKUP` does not imply `CREATE`
- directory `CREATE` does not imply `DELETE`
- `STAT` does not imply `READ`
- `READ` does not imply `EXEC`
- replacing a file via rename requires destination-side authority
- token authorization is revoked when the token fd closes
- repeated authorization by the same nonce is idempotent
- two different nonces can authorize the same token and both gain
  access
- duplicated token fds share one token lifetime, and authorization
  remains active until the final duplicate is closed
- overlapping foreign network claims return `EBUSY`
- same-nonce overlapping network claims do not create duplicate
  denial state
- invalid network ranges are rejected before insertion
- malformed file action masks are rejected
- DTrace provider declarations match fired probes
- DTrace scripts or syntax checks cover new probes where supported

oracled tests:

- old `paths` config still loads during transition
- `claim_files` config loads
- service file cap request must be covered by an oracle claim
- service net cap request must be covered by an oracle claim
- broad manifest request is denied when oracle owns only a narrow claim
- status reports file actions and network ranges
- config parser rejects unknown file actions
- config parser rejects impossible network ranges
- config parser normalizes `*`, single ports, ranges, and comparison
  forms into deterministic internal state
- reload failure does not leave half-applied claim state when batch
  support lands
- mint request denial is logged/audited/probed with the requested
  action/range

serviced tests:

- manifest parser accepts action lists
- manifest parser rejects unknown actions
- manifest parser rejects invalid port ranges
- launched service receives only requested tokens
- compatibility `cap_paths` still maps to full-access tokens during
  transition
- service cannot use a read-only token to mutate a claimed path
- service cannot use a connect-only network token to bind
- service cannot request a capability outside oracled's claim set
- malformed oracle replies do not grant implicit authority

Jail tests:

- claiming reserved JID without oracle authority is denied
- claiming an already claimed JID returns `EBUSY`
- name claim allocates a JID
- duplicate name claim by foreign nonce returns `EBUSY`
- jail create requires a matching name or JID claim
- jail removal requires owner nonce or token authorization
- `mpo_prison_check_create` denies a specific-JID create without
  `claim_jid`
- name claim does not authorize a different jail name
- `claim_jid` does not authorize a different JID
- attach token allows attach but not remove
- remove token allows remove but not set/update
- set/update token allows only approved mutable parameters
- failed jail creation releases any pending claim state
- `mpo_prison_created` records owner metadata for later checks
- jail descriptor remove path is checked the same as numeric JID remove
- jail descriptor attach path is checked the same as numeric JID attach
- DTrace denial probes fire for unauthorized create, attach, set, and
  remove

Fuzz and property tests:

- fuzz file action parser with random action strings, duplicate
  actions, empty lists, huge lists, and mixed valid/invalid values
- fuzz network parser with random ports, comparison forms, CIDR
  prefixes, IPv4/IPv6 literals, wildcards, and malformed addresses
- fuzz jail name parser with empty names, long names, dotted names,
  duplicate separators, numeric-looking names, and reserved prefixes
- property-test network range coverage:
  - a token can never cover a port outside its parent claim
  - overlapping foreign claims are always rejected
  - non-overlapping claims are allowed
  - wildcard claims cover concrete requests
  - concrete claims do not cover wildcards unless explicitly intended
- property-test filesystem action coverage:
  - a token authorizes only subsets of its action mask
  - no single action implies mutation unless named as mutation
  - directory namespace actions do not imply file content actions
- property-test jail authority:
  - name and JID claims are independent unless explicitly linked
  - reserved JIDs require oracle ownership
  - update/remove/attach rights are independent action bits

Run fuzzers in-process where possible against parser and matching
helpers.  Kernel enforcement fuzzing should use small deterministic
generators and avoid long sleeps, global namespace pollution, or
leaking claimed resources between test cases.

## Ordering

Recommended implementation order:

1. Add protocol constants and action/range structs.
2. Add filesystem action-aware token storage and MACF checks.
3. Add network port range support and `FI_OP_QUERY_NET`.  Done.
4. Update oracled config structs and parser.
5. Update oracle pair protocol for file mint requests and ranged net
   mint requests.
6. Update serviced manifest structs and parser.
7. Add focused kernel tests.
8. Add oracled/serviced parser and delegation tests.
9. Design `cap_rt_jail` as a separate service.
10. Implement jail name/JID claims and creation after file/net
    narrowing is stable.

Do not add path glob enforcement to `cap_rt_isolation` unless the
kernel claim model changes.  Today it is vnode identity based, and
that property keeps enforcement concrete and cheap.
