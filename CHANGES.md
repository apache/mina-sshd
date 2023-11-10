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

# Behavioral changes and enhancements

## New `ScpTransferEventListener` callback method

Following [GH-428/GH-392](https://github.com/apache/mina-sshd/issues/428) a new `handleReceiveCommandAckInfo` method has been added to enable users to inspect
acknowledgements of a `receive` related command. The user is free to inspect the command that was attempted as well as the response code and decide how
to handle it - including even throwing an exception if OK status (if this makes sense for whatever reason). The default implementation checks for ERROR code and throws
an exception if so.

## Potential compatibility issues

### Server-side SFTP file handle encoding

### Major Code Re-factoring

