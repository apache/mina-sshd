# Apache MINA SSHD 2.20.0

Changes since [version 2.19.0](./docs/changes/2.19.0.md):

## Bug Fixes

* [GH-656](https://github.com/apache/mina-sshd/issues/656) `ChannelPipedInputStream`: shrink buffer when emptied
* [GH-906](https://github.com/apache/mina-sshd/issues/906) Fix finding a signature factory for BC ed25519 keys
* [GH-911](https://github.com/apache/mina-sshd/issues/911) Fix server-side SOCKS5 proxy for fragmented and pipelined CONNECT requests
* Allow asynchronous authentication only for password and keyboard-interactive authentication schemes
* Fix authentication requiring multiple public keys (server-side)
* Better argument handling in sshd-git
* More checks in authentication (server-side)
* Better SCP command handling
* SFTP client: simplify response message handling
* Fix check-file-name/check-file-handle SFTP v6 extension (server-side)
* Improve LDAP authentication (sshd-ldap)

## New Features

* [GH-905](https://github.com/apache/mina-sshd/issues/905) Implement the "from" and "expiry-time" options in `authorized_keys` handling in public key authentication (server side)

## Potential Compatibility Issues

None.

## Major Code Re-factoring

None.

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
* [Version 2.15.0 to 2.16.0](./docs/changes/2.16.0.md)
* [Version 2.16.0 to 2.17.0](./docs/changes/2.17.0.md)
* [Version 2.17.0 to 2.17.1](./docs/changes/2.17.1.md)
* [Version 2.17.1 to 2.18.0](./docs/changes/2.18.0.md)
* [Version 2.18.0 to 2.19.0](./docs/changes/2.19.0.md)
