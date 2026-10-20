# PF tracing

PF is OpenBSD's packet filter (contrib/openbsd-pf). It exposes static
DTrace probes through the `pf` provider; dtrace_pf(4) lists every probe
and its arguments. Load `dtraceall` and inspect the running kernel with
`dtrace -lv -P pf`. The probes cost nothing until enabled and do not
change filtering policy or enable packet logging.

## Where the probes are

The vendor sources fire probes through hooks marked `5BSD: DTrace`
(`PF_SDTn()` at the entry of the traced functions and a hook inside
`REASON_SET`); sys/netpfil/openbsd-pf/pf_sdt.c defines them and
pf_freebsd.c fires the packet (`pf:ip:test:*`) and ioctl probes around the
calls into pf. `pf::reason:set` carries the reason code, the source file
and the line, so every drop site is distinguishable.

## Scripts

- `/usr/share/dtrace/pf-observe`: verdicts and latency per direction,
  reasons, state lifecycle, fragments, NAT, tables, pflog, pfsync, pflow
  and ioctl errors, printed on Ctrl-C or command completion.
- `/usr/share/bsdinstruments/profiles/pf-*.d`: pf-latency, pf-audit,
  pf-drops, pf-states, pf-frags, pf-nat, pf-tables, pf-rules, pf-pfsync,
  pf-queues.

```sh
dtrace -s /usr/share/dtrace/pf-observe -c 'sleep 30'
bsdinstruments watch pf-drops --duration 60
```

## Validation

In a disposable guest with pf loaded, `dtrace -l -P pf` must list every
probe of dtrace_pf(4), and the `pf_profiles_compile` case of
`bsdinstruments_test` compiles the profiles and pf-observe without `-Z`.
The OpenBSD regress runner (tools/test/pf-parity/openbsd-regress) can run
pf-observe while a suite executes to check that the scripts produce
output under real traffic.
