# Per-process lookup channels (the Darwin model)

Status: design. 2026-09-07. This is the FINAL design for unsharing the ambient
discovery channel — not the per-launch-mint stop-gap.

## Problem (confirmed race)

serviced mints ONE SYSTEM ambient lookup channel and advertises it via
`SERVICE_LOOKUP_FD`, so rc and every descendant **inherit one shared channel
endpoint** (one `struct file`, one kernel receive queue). Lookups are async,
token-correlated request/reply. `libchannel` (`channel.c` ~845-878) matches a
received reply to a pending request by token and **DISCARDS a reply whose token
matches no pending request in this process**. So on the shared endpoint, if A
sends a lookup (`T_A`) and sibling B pumps the queue first, B finds no pending
`T_A` and throws A's reply away; A hangs until timeout. Worst at boot, when many
daemons look up at once.

Not affected: native capability providers (own per-unit bootstrap channel),
logins/su (re-provision a fresh per-uid channel and close the inherited one).

## What Darwin actually does (the model we port)

Mach's bootstrap port (a send right to launchd) is **inherited/shared** too —
Mach does NOT mint a per-process bootstrap channel. It stays race-free because:

1. **Per-caller reply routing** — every RPC carries a caller-owned reply port;
   the server replies *to that port*, so a reply lands only in the requester's
   own queue, never a shared one.
2. **Ungated endpoint creation** — any task can allocate its own port
   (`mach_port_allocate`) with a plain, ungated primitive. No privileged device
   to make your *own* mailbox.

Our gap is exactly (2): today creating a channel endpoint routes through the
authority (`AUTHORITY_OP_CREATE_CHANNEL`) / the isolated `/dev/mac_capability`.
The nonce is **not** the obstacle: it is a MAC *credential* label assigned by
`mac_capability_label.c` (`mpo_cred_init_label`/`_create_init`, copied on fork,
rotated on `execve` relabel) to **every** process independent of device access —
so a process already carries its unforgeable nonce, and any endpoint it creates
by any means is nonce-attested by the kernel on send.

## Design: a CAPENABLED channel-create syscall + per-process private lookup channel

### Piece 1 — ungated channel-create syscall

A new syscall creates a fresh, **unconnected, self-owned** `mac_capability`
channel PAIR and returns both fds:

```c
int mac_capability_channel_create(int fds[2]);   /* SYF_CAPENABLED */
```

- **Ungated** — like `socketpair(2)` / `mach_port_allocate`: creating two
  connected endpoints you own grants NO authority (no service connect, no gate
  claim, no mint). Identity stays on the cred (nonce); the endpoints are just
  mailboxes. The kernel channel-pair-creation function already exists (used by
  `AUTHORITY_OP_CREATE_CHANNEL` and serviced) — the syscall exposes it without
  the authority wrapper.
- **`SYF_CAPENABLED`** — MUST work inside `cap_enter()`, because a born-in-
  capmode process cannot `open("/dev/…")` by path. This is the decisive reason
  it is a syscall and not a device op: a device node is unreachable in the
  sandbox; a capability-enabled syscall is not. (Rationale recorded so nobody
  "simplifies" it back to a device.)
- Nonce attestation unchanged: messages sent on either end carry the sender's
  cred nonce, stamped by the kernel exactly as today.

### Piece 2 — a process registers its OWN private lookup channel

With Piece 1, a process no longer needs the shared channel for replies:

1. Create a pair `(a, b)` via the syscall.
2. Send `b` to serviced **once** over the inherited shared bootstrap channel
   (a new `SVC_OP_REGISTER_LOOKUP` message carrying the fd `b`). This send is
   **send-only** from the client — no reply is awaited on the shared channel —
   so it cannot hit the reply-discard race.
3. serviced receives `b` with the client's **kernel-attested nonce**, derives
   the domain from that nonce (root/wheel → SYSTEM, else USER — never a wire
   arg), and **adopts `b` into `serviced_kq`** as this client's private lookup
   channel (the existing `svc_lookup_channel` / `lookup_channel_request`
   dispatch, unchanged except it now serves a per-client endpoint).
4. The client uses `a` — its **private** channel — for all subsequent lookups.
   Replies come back on `a`, which only this process holds → **no shared
   receive, no race, ever.**

The shared bootstrap channel is thereafter used by a client only for the
one-time registration send. (login/su already mint their own per-session
channel; native providers already have a per-unit bootstrap — both unaffected.)

### Piece 3 — libservice

`libservice` performs registration **lazily and memoized per process**: on first
ambient lookup, create the pair, register `b`, install `a` as this process's
lookup channel, use it thereafter. **Fail-soft:** if the syscall is unavailable
(old kernel) or registration fails, fall back to the inherited
`SERVICE_LOOKUP_FD` shared channel (today's behavior) so nothing regresses during
rollout. The registration is idempotent per process.

## Security

- **Syscall grants no authority.** Creating an unconnected pair is inert (a
  `socketpair`-equivalent). Verify the exposed kernel path cannot yield a
  connected-to-a-service or authority-bearing endpoint.
- **Domain scope from the attested nonce only** on `SVC_OP_REGISTER_LOOKUP` —
  a client cannot register a SYSTEM channel it isn't entitled to; serviced
  derives the domain from `cred`, never from the wire.
- **serviced validates the registered fd is a channel** (GETINFO) before
  adopting it, and confines it appropriately.
- **No new ambient authority:** a process gets exactly the discovery scope its
  inherited channel would have granted — just privately, not shared.
- Direct `SVC_OP_MINT_DOMAIN` over the ambient channel stays retired.

## Phases

- **P1 — kernel syscall. DONE (58c6e69638a), VM-verified 16/16.** Added
  `mac_capability_channel_create(fds[2])` via SYSCALL_MODULE in the
  mac_capability_channel module (dynamic number, SYF_CAPENABLED honored — no
  base syscalls.master/buildkernel needed). Ungated, no authority (bearer
  endpoints, cp pre-linked so the privileged branch is unreachable). libchannel
  helper resolves the number via modfind/modstat, fail-soft ENOSYS. Full
  adversarial/negative/stress/lifecycle suite passes under CAPLANE_OFF.
- **P2 — registration + libservice.** `SVC_OP_REGISTER_LOOKUP` in serviced
  (adopt per-client endpoint, nonce-scoped); libservice lazy/memoized
  registration with fail-soft fallback. Unit tests for the nonce-scope decision
  and the fail-soft path.
- **P3 — VM.** Production plane: each process's lookup channel is DISTINCT (not
  the shared one); a concurrent-lookup stress (many units at once) shows no lost
  replies / hangs; boot clean, crashloop 0. Confirm a born-in-capmode provider
  can create + register its own channel.
- **P4 — later.** Once proven, the single startup shared channel can be reduced
  to a pure registration bootstrap; and per-thread reply reuse (Mach parity) is
  an optional refinement.

## Invariants / checklist

- The create syscall is `SYF_CAPENABLED` and grants no authority.
- Registration domain derived from the attested nonce only.
- Fail-soft everywhere: syscall-missing / registration failure → inherited
  shared channel; never block boot/login/lookup.
- `/dev/mac_capability` stays authority-isolated; the syscall is the only new
  surface and it is inert-by-construction.
