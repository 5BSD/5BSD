blued / bluedctl Integration Review

Verify that the blued daemon and the bluedctl CLI tool are fully in sync
and that every Bluetooth operation a user would want to perform works
end-to-end through the CLI.

CODEBASE LOCATIONS:
  Daemon:     /usr/src/usr.sbin/bluetooth/blued/
  CLI tool:   /usr/src/usr.sbin/bluetooth/bluedctl/
  Tests:      /usr/src/tests/usr.sbin/bluetooth/blued/
  rc.d:       /usr/src/libexec/rc/rc.d/blued
  Man pages:  blued.8, bluedctl.8

REVIEW STRUCTURE:

1. COMMAND PARITY
   For every command in blued's ctl.c dispatch table (blued_ctl_process),
   verify that bluedctl has a corresponding CLI mapping in build_command().
   Produce a table:

     blued protocol cmd | bluedctl CLI cmd | Args match? | Response handled?

   Flag any commands in blued that bluedctl doesn't map, or vice versa.
   Check that argument counts and formats are consistent.

2. RESPONSE HANDLING
   For each command, verify bluedctl handles the response correctly:
   - Does it know when the response is complete? (OK/ERROR/END terminator)
   - For streaming commands (SCAN, SUBSCRIBE), does it use poll() correctly?
   - Are multi-line responses (DISCOVER, SERVICES, BONDS) fully captured?
   - Are EVENT lines (NOTIFY, PASSKEY_DISPLAY, PASSKEY_INPUT,
     NUMCMP_REQUEST) handled in interactive mode?
   - Does the exit code reflect success (0) vs error (1)?

3. END-TO-END WORKFLOWS
   Verify these complete workflows are possible through bluedctl:

   a. Device discovery and connection:
      bluedctl scan → bluedctl connect <addr> random → bluedctl list

   b. Service discovery and GATT operations:
      bluedctl discover <addr> → bluedctl read <addr> <handle>
      → bluedctl write <addr> <handle> <hex>

   c. Pairing:
      bluedctl pair <addr> → (if passkey needed) bluedctl passkey <addr> 123456
      → (if numcmp needed) bluedctl confirm <addr> yes
      → bluedctl bonds

   d. Notifications:
      bluedctl subscribe <addr> <handle> → (receive EVENT NOTIFY lines)
      → bluedctl unsubscribe <addr> <handle>

   e. Peripheral mode GATT server:
      bluedctl add-service 0xFFE0 → bluedctl add-char <h> 0xFFE1 read,notify read
      → bluedctl set-value <h> 48656C6C6F → bluedctl services
      → bluedctl remove-service <h>

   f. Management:
      bluedctl adapters → bluedctl status → bluedctl loglevel 2
      → bluedctl phy → bluedctl disconnect <addr> → bluedctl unbond <addr>

   g. HOGP (HID over GATT):
      bluedctl hogp-read <addr> <report_id>
      bluedctl hogp-write <addr> <report_id> <hex>

   h. ECBFC:
      bluedctl ecbfc-connect <addr> <psm> <count>
      bluedctl ecbfc-reconfig <addr> <mtu> <mps>

   For each workflow, check: Does the CLI send the right protocol command?
   Does it handle the response format? Are error cases reported clearly?

4. MAN PAGE CONSISTENCY
   Compare blued.8 and bluedctl.8:
   - Every command in blued.8 CONTROL SOCKET should appear in bluedctl.8
   - Every command in bluedctl.8 should reference the correct blued behavior
   - Argument names and descriptions should be consistent
   - Examples in bluedctl.8 should use realistic values

5. BUILD AND PACKAGING
   - Both binaries build under /usr/src/usr.sbin/bluetooth/
   - Both have PACKAGE=bluetooth for pkgbase
   - bluedctl is in the SUBDIR list
   - Both man pages are installed
   - blued.conf.sample is installed to /usr/share/examples/blued/
   - /var/db/blued is in BSD.var.dist
   - rc.d script exists and references correct paths
   - serviced integration: register/deregister calls present

6. INTERACTIVE MODE
   Review bluedctl's interactive mode (-i):
   - Does it use poll() to multiplex stdin and socket?
   - Are EVENT lines printed asynchronously (not just on command)?
   - Is Ctrl-D handled for clean exit?
   - Is the prompt redisplayed after async events?
   - Can all commands be used in interactive mode?

7. ERROR HANDLING
   - What happens when blued is not running? (connect to socket fails)
   - What happens when blued disconnects mid-session?
   - What happens with malformed arguments?
   - What happens with unknown commands?
   - Are error messages user-friendly (not raw protocol errors)?

8. MISSING FEATURES
   What BLE operations would a user reasonably want to do that neither
   blued nor bluedctl currently support? Consider:
   - Advertising data inspection (AD fields parsed and displayed?)
   - Device name resolution during scan
   - Battery level monitoring
   - Firmware version reading (DIS characteristics)
   - Connection parameter display/update
   - Security level display per connection
   - Bond import/export
   - Whitelist/blocklist management

OUTPUT FORMAT:
  Tables where possible. Be specific with file names and line numbers.
  Focus on gaps, mismatches, and missing functionality.
  Target ~2000 words.
