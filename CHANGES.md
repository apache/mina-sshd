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

# Latest Version

* **[Version 2.17.0 to 2.17.1](./docs/changes/2.17.1.md)**

# Planned for Next Version

## Bug Fixes

* [GH-879](https://github.com/apache/mina-sshd/issues/879) Close SSH channel gracefully on exception in port forwarding

## New Features

## Potential Compatibility Issues

* [GH-892](https://github.com/apache/mina-sshd/issues/892) Align handling certificates without principals with OpenSSH 10.3

OpenSSH 10.3 changed the way such certificates are handled; see the [OpenSSH 10.3 release notes](https://www.openssh.org/txt/release-10.3).
In Apache MINA SSHD, there is a new flag `CoreModuleProperties.ALLOW_EMPTY_CERTIFICATE_PRINCIPALS` (by default `false`)
that can be set on an `SshClient` or `SshServer` or also on a `Session` directly. If the value is `false`, certificates
without principals are rejected as in OpenSSH 10.3; if it is `true`, such certificates are considered to match any
user or host name as in OpenSSH &lt; 10.3.

Set the flag on an `SshClient` or `ClientSession` to determine the handling of host certificates. Set it on an
`SshServer` or `ServerSession` to govern the handling of user certificates.

## Major Code Re-factoring

