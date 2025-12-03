# Previous Versions

* [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)
* [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)
* [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)
* [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)
* [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)
* [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)
* [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)
* [Version 2.7.0 to 2.8.0](./docs/changes/2.8.0.md)
* [Version 2.8.0 to 2.9.0](./docs/changes/2.9.0.md)
* [Version 2.9.0 to 2.9.1](./docs/changes/2.9.1.md)
* [Version 2.9.1 to 2.9.2](./docs/changes/2.9.2.md)
* [Version 2.9.2 to 2.10.0](./docs/changes/2.10.0.md)
* [Version 2.10.0 to 2.11.0](./docs/changes/2.11.0.md)
* [Version 2.11.0 to 2.12.0](./docs/changes/2.12.0.md)
* [Version 2.12.0 to 2.12.1](./docs/changes/2.12.1.md)
* [Version 2.12.1 to 2.13.0](./docs/changes/2.13.0.md)
* [Version 2.13.0 to 2.13.1](./docs/changes/2.13.1.md)
* [Version 2.13.1 to 2.13.2](./docs/changes/2.13.2.md)
* [Version 2.13.2 to 2.14.0](./docs/changes/2.14.0.md)
* [Version 2.14.0 to 2.15.0](./docs/changes/2.15.0.md)

# Latest Released Version

* **[Version 2.15.0 to 2.16.0](./docs/changes/2.16.0.md)**

# Planned for Next Version

## Bug Fixes

* [GH-807](https://github.com/apache/mina-sshd/issues/807) Handle "verified" flag for sk-* keys
* [GH-809](https://github.com/apache/mina-sshd/pull/809) Fix server-side authentication for FIDO/U2F sk-* keys with flags in `authorized_keys`
* [GH-827](https://github.com/apache/mina-sshd/issues/827) Don't fail on invalid `known_hosts` lines; log and skip them
* [GH-830](https://github.com/apache/mina-sshd/issues/830) EC public keys: let Bouncy Castle generate X.509 encodings with the curve OID as algorithm parameter
* [GH-856](https://github.com/apache/mina-sshd/issues/856) FIX using ed25519 with BC-FIPS

## New Features

* [GH-814](https://github.com/apache/mina-sshd/pull/814) Include a fix for CVE-2020-36843 in optional dependency net.i2p.crypto:eddsa:0.3.0: perform the missing range check in Apache MINA SSHD before delegating to the signature verification in net.i2p.crypto:eddsa:0.3.0. This means that using net.i2p.crypto:eddsa:0.3.0 in Apache MINA SSHD is
safe despite that CVE in the dependency.

## Potential Compatibility Issues

## Major Code Re-factoring

