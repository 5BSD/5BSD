# System Hardening with OracleD

## Principle

OracleD secures the system by claiming resources at boot.
Claims are forward-looking — they control all FUTURE access.
Anything that started before OracleD retains whatever it
already has (open fds, bound sockets, loaded modules).

If you don't want a service to have unrestricted access,
start it after the Oracle.

The goal is: after OracleD finishes initialization, the
system is locked.  Root is no longer sufficient to modify
critical system state.  Authority flows through capabilities
— file descriptors minted by the Oracle and passed to the
processes that need them.

```
kernel boots
  → init
    → minimal rc (filesystems, syslog)
      → OracleD starts
        → claims resources (system is now locked)
          → agents start (with only what they need)
            → services start (via agents, with tokens)
```

Everything before OracleD is trusted infrastructure.
Everything after OracleD receives only the capabilities
it was granted.  PID 2nd to none.

## Default Hardened Configuration

This ships as `/etc/oracled.conf` and provides a reasonable
secure default.  Operators can add or remove claims based on
their deployment.

```ucl
# /etc/oracled.conf — 5BSD default hardened configuration

integrity {
    ptrace = true;
    signal = true;
    visible = true;
    wait = true;
    sched = true;
    core = true;
    ktrace = true;
}

claims {
    # --- Kernel memory ---
    # Prevent reading kernel addresses and secrets.
    paths = [
        "/dev/mem",
        "/dev/kmem",

        # --- Boot ---
        # Prevent kernel, bootloader, and module replacement.
        "/boot",

        # --- System binaries ---
        # Prevent trojan replacement of system programs.
        "/sbin",
        "/usr/sbin",
        "/usr/bin",
        "/usr/lib",
        "/usr/libexec",

        # --- Credentials and configuration ---
        # Prevent password, auth, and boot config tampering.
        "/etc/master.passwd",
        "/etc/passwd",
        "/etc/group",
        "/etc/login.conf",
        "/etc/rc.conf",
        "/etc/rc.d",
        "/etc/ssh",
        "/etc/pam.d",
        "/etc/oracled.conf",
        "/etc/oracled.d",

        # --- Audit trail ---
        # Prevent log deletion or truncation.
        "/var/log",

        # --- Root home ---
        # Prevent SSH key injection.
        "/root",
    ];

    # --- Privileged ports ---
    # Prevent port hijacking after the legitimate service binds.
    network = [
        { port = 22;  protocol = "tcp"; direction = "bind"; },
        { port = 53;  protocol = "tcp"; direction = "bind"; },
        { port = 53;  protocol = "udp"; direction = "bind"; },
        { port = 80;  protocol = "tcp"; direction = "bind"; },
        { port = 443; protocol = "tcp"; direction = "bind"; },
    ];

    # --- System operations ---
    # Prevent privileged syscalls from any process except
    # OracleD or token holders.
    system = [
        "kldload",
        "kldunload",
        "reboot",
        "kenv",
        "sysctl",
        "audit",
        "acct",
        "swapon",
        "swapoff",
    ];
}
```

## What This Protects Against

### Compromised root process

A service running as root is exploited.  The attacker has
uid 0 but cannot:

- Load a kernel module (rootkit installation)
- Read `/dev/mem` (kernel memory inspection)
- Replace `/usr/bin/su` (trojan binary)
- Modify `/etc/master.passwd` (create backdoor account)
- Delete `/var/log` (destroy evidence)
- Reboot (clear volatile evidence)
- Lower `kern.securelevel` (weaken kernel protections)
- Set `kenv init_path=/tmp/evil` (poison next boot)
- Bind port 22 (impersonate sshd after killing it)
- Inject SSH keys into `/root/.ssh/authorized_keys`

### Insider with root shell

An administrator with legitimate root access cannot
perform destructive or unauthorized operations without
going through the Oracle's control interface.

### Malware persistence

Malware that achieves root cannot:

- Install itself in `/usr/sbin` or `/usr/libexec`
- Modify rc scripts to start at boot
- Load a kernel module to hide itself
- Tamper with audit logs

## What This Does NOT Protect Against

### Pre-OracleD state

Anything that happened before OracleD started is not
controlled.  If an attacker modified `/etc/passwd` while
the system was offline (booted from USB), OracleD cannot
detect or prevent it.  Filesystem integrity verification
(like `mtree` or IMA) is complementary.

### Already-open file descriptors

If a process opened `/dev/mem` before OracleD claimed it,
that fd continues to work.  The claim prevents NEW opens,
not existing ones.  This is why minimizing what starts
before OracleD matters.

### Already-bound sockets

If a rogue process bound port 22 before OracleD claimed it,
the bind persists.  The claim prevents future binds.

### Kernel exploits

OracleD's protections are MACF-based.  A kernel exploit that
bypasses the MAC framework bypasses all claims.  The kldload
claim helps here — it prevents loading exploit modules — but
a direct kernel memory corruption attack is not gated.

### Physical access

DMA attacks, cold boot attacks, and offline disk modification
are outside OracleD's threat model.  These require hardware
security (IOMMU, full disk encryption, secure boot).

## Startup Order

The order matters.  Services that start before OracleD have
unrestricted access.  Services that start after are subject
to claims.

### Must start before OracleD

- `init` — PID 1, required
- `FILESYSTEMS` — OracleD needs `/etc`, `/var/run`
- `syslogd` — OracleD logs to syslog
- `devd` — if cap_rt is a loadable module (not built-in)

### Should start after OracleD

Everything else.  Once OracleD is running:

- sshd starts → port 22 is already claimed, sshd binds it
  before claim (via rc ordering) or receives a token
- nginx starts → port 80/443 claimed, needs a token
- cron starts → no special capabilities needed
- custom daemons → receive only what their manifest grants

### Boot sequence with agents (future)

```
init → rc → filesystems → syslogd → OracleD
  OracleD:
    1. Claims resources (system locked)
    2. Starts system-agent (jid0, holds system tokens)
    3. Starts net-agent (jail, holds port tokens)
    4. Starts app-agent (jail, holds app tokens)
    5. Agents start their services with delegated tokens
```

## Tuning

### Relaxing claims for development

Comment out claims that interfere with your workflow:

```ucl
claims {
    paths = [
        "/dev/mem",
        "/dev/kmem",
        # "/boot",              # need kldload during dev
        # "/usr/sbin",          # need to install builds
    ];
    system = [
        # "kldload",            # need during development
        # "kldunload",
        "reboot",
        "kenv",
        "sysctl",
    ];
}
```

### Adding claims for specific deployments

A database server might add:

```ucl
claims {
    paths = [
        "/var/db/postgres",     # protect data directory
    ];
    network = [
        { port = 5432; protocol = "tcp"; direction = "bind"; },
    ];
}
```

### Verifying claims

Use DTrace to see what OracleD claimed at boot:

```sh
dtrace -n 'oracled*:::claim-path { printf("%s", copyinstr(arg0)); }'
dtrace -n 'oracled*:::claim-net { printf("port %d", arg0); }'
```

Or check syslog:

```sh
grep "isolation: claimed" /var/log/daemon.log
grep "system: claimed" /var/log/daemon.log
```
