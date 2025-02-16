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

* [GH-650](https://github.com/apache/mina-sshd/issues/650) Use the correct key from a user certificate in server-side pubkey auth

## New Features

* [SSHD-1161](https://issues.apache.org/jira/projects/SSHD/issues/SSHD-1161) Support pubkey auth with user certificates (server-side)
    * Client-side support was introduced in version 2.8.0 already 
* [SSHD-1167](https://issues.apache.org/jira/projects/SSHD/issues/SSHD-1167) Check host certificates against known_hosts file (implements @<!-- -->cert-authority)

## Potential Compatibility Issues

Client-side KEX: we've changed the default of the setting `CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE` from `false` to `true`.
A client will newly abort an SSH connection if the server presents an invalid OpenSSH host certificate as host key.

## Major Code Re-factoring

