# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)

# [Version 2.7.0 to 2.8.0](./docs/changes/2.8.0.md)

# [Version 2.8.0 to 2.9.0](./docs/changes/2.9.0.md)

# [Version 2.9.0 to 2.9.1](./docs/changes/2.9.1.md)

# [Version 2.9.1 to 2.9.2](./docs/changes/2.9.2.md)

# [Version 2.9.2 to 2.10.0](./docs/changes/2.10.0.md)

# [Version 2.10.0 to 2.11.0](./docs/changes/2.11.0.md)

# Planned for next version

## Bug Fixes

* [GH-428/GH-392](https://github.com/apache/mina-sshd/issues/428) SCP client fails silently when error signalled due to missing file or lacking permissions

## New Features

* [GH-429](https://github.com/apache/mina-sshd/issues/429) Support GIT protocol-v2
* [GH-445](https://github.com/apache/mina-sshd/issues/445) OpenSSH "strict key exchange" protocol extension ([CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) mitigation)

## Behavioral changes and enhancements

### New `ScpTransferEventListener` callback method

Following [GH-428/GH-392](https://github.com/apache/mina-sshd/issues/428) a new `handleReceiveCommandAckInfo` method has been added to enable users to inspect
acknowledgements of a `receive` related command. The user is free to inspect the command that was attempted as well as the response code and decide how
to handle it - including even throwing an exception if OK status (if this makes sense for whatever reason). The default implementation checks for ERROR code and throws
an exception if so.

### OpenSSH protocol extension: strict key exchange

[GH-445](https://github.com/apache/mina-sshd/issues/445) implements an extension to the SSH protocol introduced
in OpenSSH 9.6. This ["strict key exchange" extension](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
hardens the SSH key exchange against the ["Terrapin attack"](https://www.terrapin-attack.com/)
([CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795)). The extension is active if both parties
announce their support for it at the start of the initial key exchange. If only one party announces support,
it is not activated to ensure compatibility with SSH implementations that do not implement it. Apache MINA sshd
clients and servers always announce their support for strict key exchange.

## Potential compatibility issues

## Major Code Re-factoring

