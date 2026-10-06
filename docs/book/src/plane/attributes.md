# Software attributes

Attributes describe what approved software may access in the capability plane.
They do not describe a UNIX user's privileges. UNIX login, SSH, su, file
permissions, and UID changes retain their ordinary UNIX meaning.

## Client and server declarations

An ordinary client declares its executable and attributes:

```ucl
program = "trace-client";
activation { exec = true; }
attributes = ["system.trace.client"];
```

A provider publishes an endpoint with the attributes it requires:

```ucl
activation {
    ipc = [{ name = "system.Trace";
             requires = ["system.trace.client"]; }];
}
```

SwitchBoard admits a connection only when the kernel-attributed software has
all the required attributes. Names are case-sensitive, bounded dotted names;
wildcards are prohibited in application manifests. Missing attributes produce
a discovery denial. An endpoint with no requirements remains public subject
to the existing discovery visibility rules.

The program name resolves below the unit bundle’s `bin/` directory, as it does
for service units. An exec entry is software policy, not a supervised daemon. It cannot specify
another activation source, a UNIX user change, launch arguments, or inherited
privileged resources. The caller executes the program normally; the manifest
does not turn exec into a SwitchBoard launch.

`attributes` replaces the old `holds` spelling. The parser accepts `holds` as
an upgrade alias and rejects declarations containing both keys, even when one
is empty. Public library accessors are `capbundle_svc_nattributes()` and
`capbundle_svc_attribute()`; old accessor symbols remain ABI-compatible.

## Identity and discovery are separate

The process-held discovery channel tells a process where to request services.
Fork and exec inherit that route. Possession of the route grants no attributes.
The kernel stamps requests with the actual software authority; supplying a
bundle name, changing UID, or being root cannot manufacture that stamp.

Approved software can run for any UNIX user who can execute it. Its attributes
remain the software's attributes. The client must expose deliberately chosen
operations and validate its inputs: approving a general-purpose interpreter
or a client that accepts arbitrary privileged commands would grant those
operations to every user allowed to run it.

Fork preserves the application's context. Exec into unrelated software removes
its use. Registered approved images can establish a new software context on
ordinary exec. The kernel catalogue is bounded, keyed by pinned executable
vnode identity and prison, and controlled by an issuer capability. Registration
pins executable contents against in-place writes. Removing an issuer or
revoking a registration invalidates its contexts and authority-bound handles.
Secure exec rejects privilege acquisition through tracing or `no_new_privs`
and enables secure loader behavior without changing UNIX credentials.

This is not a claim that filesystem ownership or a vnode pin substitutes for
signature verification. Trusted manifests, executable registration, dynamic
libraries, loaders, configuration, and verifier enforcement form part of the
code-integrity boundary. Their complete integration still needs verification.

## Resource ownership

An attributed server can isolate a resource such as `/dev/pf` from ordinary
UNIX access. Clients reach it through the server interface. Root retains its
ordinary UNIX powers over resources still in the UNIX plane, but UID zero does
not bypass isolated-resource ownership or endpoint attribute requirements.

The decision to make authority depend on software is deliberate: anyone who
can execute an approved control client can request the operations it exposes,
including UNIX root. Attributes block direct access by unapproved code; they do
not prohibit root from using approved tools. UNIX execution permissions are not
a strong barrier against root. An additional per-operation user-authorization
layer would be a separate design choice, and is not part of this model.

The server enforces its operation semantics. SwitchBoard need not understand
network interfaces, firewall rules, or each daemon's configuration language.
If connecting to an endpoint grants more operations than intended, expose a
narrower endpoint or constrain the operation in the server.

Responsible-process attribution and coalitions record process relationships;
they do not add software attributes.

## Implementation status

The manifest parser, managed executable constraints, inherited discovery route,
kernel ordinary-exec catalogue, secure-loader boundary, and authority-bound
handle checks have component tests. The kernel catalogue has passed isolated
QEMU tests, including root and non-root execution, fork, unrelated exec,
revocation, issuer cleanup, and loader injection attempts. SwitchBoard loading
and updating that catalogue is integrated and has development-VM coverage,
including cached-handle revocation. Fresh installer acceptance is still pending.

Shipped PAM stacks no longer issue grants, and BSDInstall no longer assigns
capability permissions to accounts. The old login-principal policy, elevation
APIs, and remaining related tools and documentation are being removed; they
are not the intended authorization model. Fresh installer, stock login/SSH/su,
service recovery, DTrace, and release-artifact acceptance remain outstanding.
