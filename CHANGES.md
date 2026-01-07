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

* [GH-721](https://github.com/apache/mina-sshd/issues/721) SSH client: schedule session timeout checks on demand only
* [GH-807](https://github.com/apache/mina-sshd/issues/807) Handle "verified" flag for sk-* keys
* [GH-809](https://github.com/apache/mina-sshd/pull/809) Fix server-side authentication for FIDO/U2F sk-* keys with flags in `authorized_keys`
* [GH-827](https://github.com/apache/mina-sshd/issues/827) Don't fail on invalid `known_hosts` lines; log and skip them
* [GH-830](https://github.com/apache/mina-sshd/issues/830) EC public keys: let Bouncy Castle generate X.509 encodings with the curve OID as algorithm parameter
* [GH-855](https://github.com/apache/mina-sshd/issues/855) SFTP: use a single `SftpClient` per `SftpFileSystem`
* [GH-856](https://github.com/apache/mina-sshd/issues/856) Fix using ed25519 with BC-FIPS
* [GH-861](https://github.com/apache/mina-sshd/issues/861) SFTP client: prevent sending zero-length writes in `SftpOutputStreamAsync`

* [SSHD-1348](https://issues.apache.org/jira/browse/SSHD-1348) Fix zero-length SFTP reads

## New Features

* [GH-814](https://github.com/apache/mina-sshd/pull/814) Include a fix for CVE-2020-36843 in optional dependency net.i2p.crypto:eddsa:0.3.0: perform the missing range check in Apache MINA SSHD before delegating to the signature verification in net.i2p.crypto:eddsa:0.3.0. This means that using net.i2p.crypto:eddsa:0.3.0 in Apache MINA SSHD is
safe despite that CVE in the dependency.
* [GH-865](https://github.com/apache/mina-sshd/issues/865) replace `%h` in `HostName` SSH config

## Potential Compatibility Issues

[GH-855](https://github.com/apache/mina-sshd/issues/855) changes the way `SftpFileSystem` deals with multiple threads. It newly uses a single SSH channel via a single thread-safe `SftpClient`, serializing writes at the channel level. The properties relating to the previously used pool of `SftpClient`s have been deprecated and have no effect anymore. User applications using the library should not see any changes.

A beneficial side-effect of this change is that an `SftpFileSystem` creates the SSH session and SFTP channel only when the first SFTP operation is performed. Previously the session and channel were opened right away when an `SftpFileSystem` was instantiated.

## Major Code Re-factoring

