# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# Planned for next version

## Major code re-factoring

## Minor code helpers

* [SSHD-1085](https://issues.apache.org/jira/browse/SSHD-1085) Added `CliLogger` + more verbosity on `SshClientMain`
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Route tests JUL logging via SLF4JBridgeHandler
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Provide full slf4j logger capabilities to CliLogger + use it in all CLI classes
* [SSHD-1110](https://issues.apache.org/jira/browse/SSHD-1110) Replace `Class#newInstance()` calls with `Class#getDefaultConstructor().newInstance()`
* [SSHD-1111](https://issues.apache.org/jira/browse/SSHD-1111) Fixed SshClientCliSupport compression option detection

## Behavioral changes and enhancements

* [SSHD-1085](https://issues.apache.org/jira/browse/SSHD-1085) Added more notifications related to channel state change for detecting channel closing or closed earlier.
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Replace log4j with logback as the slf4j logger implementation for tests
