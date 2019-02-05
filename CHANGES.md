# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# Planned for next version

## Major code re-factoring

* The `ChannelSession` provides a mechanism for supporting non-standard extended data (a.k.a. STDERR data)
in a similar manner as the "regular" data. Please read the relevant section in the main documentation page.

## Behavioral changes and enhancements

* [SSHD-882](https://issues.apache.org/jira/browse/SSHD-882) - Provide hooks to allow users to register a consumer
for STDERR data sent via the `ChannelSession` - especially for the SFTP subsystem.
