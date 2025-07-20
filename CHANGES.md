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

# Latest Released Version

* **[Version 2.14.0 to 2.15.0](./docs/changes/2.15.0.md)**

# Planned for Next Version

## Bug Fixes

* [GH-516](https://github.com/apache/mina-sshd/issues/516) SFTP: allow file system URIs without password
* [GH-650](https://github.com/apache/mina-sshd/issues/650) Use the correct key from a user certificate in server-side pubkey auth
* [GH-663](https://github.com/apache/mina-sshd/issues/663) Fix racy `IoSession` creation
* [GH-664](https://github.com/apache/mina-sshd/issues/664) Skip MAC negotiation if an AEAD cipher was negotiated
* [GH-677](https://github.com/apache/mina-sshd/issues/677) Fix current directory handling in `ScpShell` for WinSCP
* [GH-678](https://github.com/apache/mina-sshd/issues/678) `ScpShell`: write month names in English for WinSCP
* [GH-690](https://github.com/apache/mina-sshd/issues/690) Handle append mode for buggy SFTP v3 servers
* [GH-700](https://github.com/apache/mina-sshd/issues/700) Fix race in `AbstractCloseable.doCloseImmediately()`
* [GH-709](https://github.com/apache/mina-sshd/issues/709) `AbstractChannel`: Handle keep-alive channel messages sent by an old OpenSSH server
* [GH-727](https://github.com/apache/mina-sshd/issues/727) Supply default port 22 for proxy jump hosts for which there is no `HostConfigEntry`
* [GH-733](https://github.com/apache/mina-sshd/issues/733) Fix `SftpRemotePathChannel.transferTo()` (avoid NPE)
* [GH-751](https://github.com/apache/mina-sshd/issues/751) Fix SFTP v3 "long name" if SFTP server uses an `SftpFileSystem` to another server
* [GH-754](https://github.com/apache/mina-sshd/issues/754) `DefaultFowarder` must not be closed after a bind error
* [GH-767](https://github.com/apache/mina-sshd/issues/767) Remove dependency on net.i2p.crypto in `SkED25519PublicKey`
* [GH-771](https://github.com/apache/mina-sshd/issues/771) Remove dependency on net.i2p.crypto in `EdDSAPuttyKeyDecoder`
* [GH-774](https://github.com/apache/mina-sshd/issues/774) Fix `WritePendingException` in SFTP file copy


* [SSHD-1343](https://issues.apache.org/jira/projects/SSHD/issues/SSHD-1343) Correct documentation in `ChannelDataReceiver`

## New Features

* [GH-705](https://github.com/apache/mina-sshd/issues/705) New method `TcpipServerChannel.getPort()` returning the `ChannelToPortHandler`


* [SSHD-1161](https://issues.apache.org/jira/projects/SSHD/issues/SSHD-1161) Support pubkey auth with user certificates (server-side)
    * Client-side support was introduced in version 2.8.0 already 
* [SSHD-1167](https://issues.apache.org/jira/projects/SSHD/issues/SSHD-1167) Check host certificates against known_hosts file (implements @<!-- -->cert-authority)

## Potential Compatibility Issues

* Client-side KEX: we've changed the default of the setting `CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE` from `false` to `true`. A client will newly abort an SSH connection if the server presents an invalid OpenSSH host certificate as host key.
* [GH-767](https://github.com/apache/mina-sshd/issues/767) and [GH-771](https://github.com/apache/mina-sshd/issues/771) cause API changes in classes `SkED25519PublicKey` and `EdDSAPuttyKeyDecoder`. Both changes are unlikely to be noticed in user code since user code normally doesn't need to use either class.

## Major Code Re-factoring

