# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# Planned for next version

## Major code re-factoring

* The `ChannelSession` provides a mechanism for supporting non-standard extended data (a.k.a. STDERR data)
in a similar manner as the "regular" data. Please read the relevant section in the main documentation page.

* The user can use a registered `SessionDisconnectHandler` in order be informed and also intervene in cases
where the code decides to disconnect the session due to various protocol or configuration parameters violations.

* `ScpFileOpener#getMatchingFilesToSend` has been modified to accept a `Path` as the base directory
and also return an `Iterable<Path>`.

* The SFTP command line client provides a `kex` command that displays the KEX parameters of the
current sesssion - client/server proposals and what has been negotiated.

* The `Session` object provides a `KexExtensionHandler` for usage with [KEX extension negotiation](https://tools.wordtothewise.com/rfc/rfc8308)

## Behavioral changes and enhancements

* [SSHD-882](https://issues.apache.org/jira/browse/SSHD-882) - Provide hooks to allow users to register a consumer
for STDERR data sent via the `ChannelSession` - especially for the SFTP subsystem.

* [SSHD=892](https://issues.apache.org/jira/browse/SSHD-882) - Inform user about possible session disconnect prior
to disconnecting and allow intervention via `SessionDisconnectHandler`.

* [SSHD-893](https://issues.apache.org/jira/browse/SSHD-893) - Using Path(s) instead of String(s) as DirectoryScanner results

* [SSHD-896](https://issues.apache.org/jira/browse/SSHD-896) - Added support for [KEX extension negotiation](https://tools.wordtothewise.com/rfc/rfc8308)
