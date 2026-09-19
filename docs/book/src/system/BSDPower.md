# BSDPower: the power broker

`BSDPower` exposes `system.Power` and lets a capability-mode component query the
machine's supported ACPI sleep states and — policy permitting — put the machine
to sleep, without driving `/dev/acpi` directly. A client holds a `system.Power`
channel; the broker performs the `ioctl(2)` on its behalf after a per-label
policy check. Reboot and halt stay with [Capsule](capsule.md); `BSDPower` owns
sleep.

Like `BSDTime`, `BSDPower` is an **ambient-authority provider**: its per-client
workers do *not* enter capability mode, because `ACPIIO_REQSLPSTATE` on
`/dev/acpi` needs a privilege the Capsicum sandbox strips. It runs outside the
sandbox as the trusted concentration point for sleep, and its security boundary
is the per-label policy. It opens `/dev/acpi` once at startup and fails soft if
it is absent (state queries still work via sysctl; suspend returns `ENODEV`).
Each accepted client is served on its own `pdfork(2)`'d worker that drops
inherited authority.

## The verbs

- **states** — the supported sleep states as a bitmask (e.g. S3/S4/S5), read
  from `hw.acpi.supported_sleep_state`. Unprivileged: allowed to every holder.
- **suspend** — request the machine enter sleep state S1–S5
  (`ioctl(ACPIIO_REQSLPSTATE)`). Default-deny: refused with `EPERM` unless the
  caller's label is granted, and `EINVAL` for a state the range rejects.

## Policy

Access is scoped per label by `power.conf` in the provider's bundle `Config/`
directory, delivered as a directory descriptor. The `default` block applies to
any label without its own `clients` entry; a label may suspend the machine only
if granted `suspend = true`. Querying states is always allowed. A missing or
malformed file fails soft to the compiled-in default — query-only, no suspend.
An unexpected suspend is a denial of service, so grant `suspend` only to a
trusted power manager.

## Client API

Components link `libpowercmp(3)`: `powercmp_client_open()` acquires the channel,
and `powercmp_states` and `powercmp_suspend` map to the two verbs. `BSDPowerctl(8)`
is the operator front end from the command line.
