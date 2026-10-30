# Package administration checks

Run `python3.12 removal.py --pkg /absolute/path/to/pkg-static --output /absolute/result.json`
as an unprivileged user. The check creates only temporary payloads and package
databases, disables scripts/plugins/triggers and selects an empty repository
configuration. It requires denied deletion to fail and retain its package record,
and ordinary and already-missing-file deletion to succeed. A local upgrade whose
obsolete file cannot be removed must fail and retain the old package version.

This is not a BIP, script rollback or complete transaction test. The upgrade
fixture adds no new payload; recovery after partial extraction remains untested.
It does not install the selected package manager or touch the host package DB.
The selected bootstrap pkg must be rebuilt through the custom ports workflow;
pass its archive and hash explicitly to build-bsd when refreshing publication.
