/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC DTrace Probe Definitions
 *
 * DTrace provider: abac
 *
 * Probe naming convention:
 *   abac:<module>:<function>:<name>
 *
 * Example usage:
 *   dtrace -n 'abac:::check-deny { printf("%s -> %s op=%x",
 *       stringof(arg0), stringof(arg1), arg2); }'
 *
 *   dtrace -n 'abac:::rule-match { @[arg0] = count(); }'
 *
 *   dtrace -n 'abac:::check-entry { self->ts = timestamp; }
 *              abac:::check-return { @["ns"] = quantize(timestamp - self->ts); }'
 */

#ifndef _ABAC_DTRACE_H_
#define _ABAC_DTRACE_H_

#include <sys/sdt.h>

/*
 * Provider declaration
 */
SDT_PROVIDER_DECLARE(abac);

/*
 * Access check probes
 *
 * check-entry: Fired at start of access check
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *
 * check-return: Fired at end of access check
 *   arg0: result (0=allow, EACCES=deny)
 *   arg1: operation bitmask (uint32_t)
 *
 * check-allow: Fired when access is allowed
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *   arg3: matching rule ID (0=default policy)
 *
 * check-deny: Fired when access is denied
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *   arg3: matching rule ID (0=default policy)
 */
SDT_PROBE_DECLARE(abac, rules, check, entry);
SDT_PROBE_DECLARE(abac, rules, check, return);
SDT_PROBE_DECLARE(abac, rules, check, allow);
SDT_PROBE_DECLARE(abac, rules, check, deny);

/*
 * Rule matching probes
 *
 * rule-match: Fired when a rule matches (before action applied)
 *   arg0: rule ID (uint32_t)
 *   arg1: action (0=allow, 1=deny, 2=transition)
 *   arg2: operation bitmask (uint32_t)
 *
 * rule-nomatch: Fired when no rule matches (default policy used)
 *   arg0: default policy (0=allow, 1=deny)
 *   arg1: operation bitmask (uint32_t)
 */
SDT_PROBE_DECLARE(abac, rules, rule, match);
SDT_PROBE_DECLARE(abac, rules, rule, nomatch);

/*
 * Label transition probes
 *
 * transition: Fired when a process label changes on exec
 *   arg0: old label string (char *)
 *   arg1: new label string (char *)
 *   arg2: executable label string (char *)
 *   arg3: pid (pid_t)
 */
SDT_PROBE_DECLARE(abac, cred, transition, exec);

/*
 * Label read probes
 *
 * label-read: Fired when a label is read from extattr
 *   arg0: label string (char *)
 *   arg1: vnode pointer (struct vnode *)
 *
 * label-default: Fired when a default label is assigned
 *   arg0: is_subject (1=process, 0=file)
 */
SDT_PROBE_DECLARE(abac, label, extattr, read);
SDT_PROBE_DECLARE(abac, label, extattr, default);

/*
 * Rule management probes
 *
 * rule-add: Fired when a rule is added
 *   arg0: rule ID (uint32_t)
 *   arg1: action (uint8_t)
 *   arg2: operations bitmask (uint32_t)
 *
 * rule-remove: Fired when a rule is removed
 *   arg0: rule ID (uint32_t)
 *
 * rule-clear: Fired when all rules are cleared
 *   arg0: count of rules cleared (uint32_t)
 */
SDT_PROBE_DECLARE(abac, rules, rule, add);
SDT_PROBE_DECLARE(abac, rules, rule, remove);
SDT_PROBE_DECLARE(abac, rules, rule, clear);

/*
 * Mode change probes
 *
 * mode-change: Fired when enforcement mode changes
 *   arg0: old mode (int)
 *   arg1: new mode (int)
 */
SDT_PROBE_DECLARE(abac, policy, mode, change);

#endif /* !_ABAC_DTRACE_H_ */
