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

# [Version 2.11.0 to 2.12.0](./docs/changes/2.12.0.md)

# [Version 2.12.0 to 2.12.1](./docs/changes/2.12.1.md)

# [Version 2.12.1 to 2.13.0](./docs/changes/2.13.0.md)

# [Version 2.13.0 to 2.13.1](./docs/changes/2.13.1.md)

# [Version 2.13.1 to 2.13.2](./docs/changes/2.13.2.md)

# Planned for next version

## Bug Fixes

* [GH-524](https://github.com/apache/mina-sshd/issues/524) Performance improvements

## New Features

* New utility methods `SftpClient.put(Path localFile, String remoteFileName)` and `SftpClient.put(InputStream in, String remoteFileName)` facilitate SFTP file uploading.

## Potential compatibility issues

There is a new `SecurityProviderRegistrar` that is registered by default
if there is a `SunJCE` security provider and that uses the AES and
HmacSHA* implementations from `SunJCE` even if Bouncy Castle is also
registered. `SunJCE` has native implementation, whereas Bouncy Castle
may not.

The new registrar has the name "SunJCEWrapper" and can be configured
like any other registrar. It can be disabled via the system property
`org.apache.sshd.security.provider.SunJCEWrapper.enabled=false`.

## Major Code Re-factoring

### JDK requirements

The project now requires JDK 17 at build time 
[GH-536](https://github.com/apache/mina-sshd/issues/536), while the target runtime
still remains unchanged to support JDK 8.
