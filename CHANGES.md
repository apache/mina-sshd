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
* [SSHD-525](https://issues.apache.org/jira/browse/SSHD-525) Added support for SFTP **client-side** ["posix-rename@openssh.com"
 extension](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=1.28&content-type=text/x-cvsweb-markup) - see section 3.3

## Behavioral changes and enhancements

* [SSHD-1085](https://issues.apache.org/jira/browse/SSHD-1085) Added more notifications related to channel state change for detecting channel closing or closed earlier.
* [SSHD-1091](https://issues.apache.org/jira/browse/SSHD-1091) Renamed `sshd-contrib` top-level package in order to align naming convention.
* [SSHD-1097](https://issues.apache.org/jira/browse/SSHD-1097) Added more `SessionListener` callbacks related to the initial version and key exchange
* [SSHD-1097](https://issues.apache.org/jira/browse/SSHD-1097) Added more capability to send peer identification via `ReservedSessionMessagesHandler`
* [SSHD-1097](https://issues.apache.org/jira/browse/SSHD-1097) Implemented [endless tarpit](https://nullprogram.com/blog/2019/03/22/) example in sshd-contrib
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Replace log4j with logback as the slf4j logger implementation for tests
* [SSHD-1114](https://issues.apache.org/jira/browse/SSHD-1114) Added callbacks for client-side password authentication progress
* [SSHD-1114](https://issues.apache.org/jira/browse/SSHD-1114) Added callbacks for client-side public key authentication progress
* [SSHD-1114](https://issues.apache.org/jira/browse/SSHD-1114) Added callbacks for client-side host-based authentication progress
* [SSHD-1114](https://issues.apache.org/jira/browse/SSHD-1114) Added capability for interactive password authentication participation via UserInteraction
* [SSHD-1114](https://issues.apache.org/jira/browse/SSHD-1114) Added capability for interactive key based authentication participation via UserInteraction
