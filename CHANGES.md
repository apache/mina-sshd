# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# Planned for next version

## Major code re-factoring

* [SSHD-1133](https://issues.apache.org/jira/browse/SSHD-1133) Re-factored locations and names of `ServerSession` and server-side `ChannelSession` related classes
* Moved some helper methods and classes to more natural locations

## Potential compatibility issues

## Minor code helpers

* [SSHD-525](https://issues.apache.org/jira/browse/SSHD-525) Added support for SFTP `posix-rename@openssh.com`
 extension](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=1.28&content-type=text/x-cvsweb-markup) - see section 3.3
* [SSHD-1083](https://issues.apache.org/jira/browse/SSHD-1083) Relaxed required `Nio2Connector/Acceptor` required constructor arguments
* [SSHD-1085](https://issues.apache.org/jira/browse/SSHD-1085) Added `CliLogger` + more verbosity on `SshClientMain`
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Route tests JUL logging via SLF4JBridgeHandler
* [SSHD-1109](https://issues.apache.org/jira/browse/SSHD-1109) Provide full slf4j logger capabilities to CliLogger + use it in all CLI classes
* [SSHD-1110](https://issues.apache.org/jira/browse/SSHD-1110) Replace `Class#newInstance()` calls with `Class#getDefaultConstructor().newInstance()`
* [SSHD-1111](https://issues.apache.org/jira/browse/SSHD-1111) Fixed SshClientCliSupport compression option detection
* [SSHD-1116](https://issues.apache.org/jira/browse/SSHD-1116) Provide SessionContext argument to HostKeyIdentityProvider#loadHostKeys
* [SSHD-1116](https://issues.apache.org/jira/browse/SSHD-1116) Provide SessionContext argument to PasswordIdentityProvider#loadPasswords
* [SSHD-1116](https://issues.apache.org/jira/browse/SSHD-1116) Provide SessionContext argument to AuthenticationIdentitiesProvider#loadIdentities
* [SSHD-1125](https://issues.apache.org/jira/browse/SSHD-1125) Added option to require immediate close of channel in command `ExitCallback` invocation
* [SSHD-1127](https://issues.apache.org/jira/browse/SSHD-1127) Consolidated `SftpSubsystem` support implementations into `SftpSubsystemConfigurator`
* [SSHD-1148](https://issues.apache.org/jira/browse/SSHD-1148) Generate a unique thread name for each `SftpSubsystem` instance

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
* [SSHD-1123](https://issues.apache.org/jira/browse/SSHD-1123) Add option to chunk data in ChannelAsyncOutputStream if window size is smaller than packet size
* [SSHD-1125](https://issues.apache.org/jira/browse/SSHD-1125) Added mechanism to throttle pending write requests in BufferedIoOutputStream
* [SSHD-1127](https://issues.apache.org/jira/browse/SSHD-1127) Added capability to register a custom receiver for SFTP STDERR channel raw or stream data
* [SSHD-1132](https://issues.apache.org/jira/browse/SSHD-1132) Added SFTP client-side support for 'filename-charset' extension
* [SSHD-1132](https://issues.apache.org/jira/browse/SSHD-1132) Added SFTP client-side support for 'filename-translation-control' extension
* [SSHD-1132](https://issues.apache.org/jira/browse/SSHD-1132) Added SFTP servder-side support for non-UTF8 encoding of returned file names
* [SSHD-1133](https://issues.apache.org/jira/browse/SSHD-1133) Added capability to specify a custom charset for parsing incoming commands to the `ScpShell`
* [SSHD-1133](https://issues.apache.org/jira/browse/SSHD-1133) Added capability to specify a custom charset for returning environment variables related data from the `ScpShell`
* [SSHD-1133](https://issues.apache.org/jira/browse/SSHD-1133) Added capability to specify a custom charset for handling the SCP protocol textual commands and responses
* [SSHD-1136](https://issues.apache.org/jira/browse/SSHD-1136) Use configuration property to decide whether to allow fallback to DH group exchange using SHA-1 if no suitable primes found for SHA-256
* [SSHD-1137](https://issues.apache.org/jira/browse/SSHD-1137) Added capability to override LinkOption(s) when accessing a file/folder via SFTP
* [SSHD-1147](https://issues.apache.org/jira/browse/SSHD-1147) SftpInputStreamAsync: get file size before SSH_FXP_OPEN