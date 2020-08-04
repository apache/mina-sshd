# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# Planned for next version

## Major code re-factoring

* `SshServerMain` uses by default an ECDSA key instead of an RSA one. This can be overridden either by `-key-type / -key-size`
or `-key-file` command line option.
* [SSHD-1034](https://issues.apache.org/jira/browse/SSHD-1034) Rename `org.apache.sshd.common.ForwardingFilter` to `Forwarder`.
* [SSHD-1035](https://issues.apache.org/jira/browse/SSHD-1035) Move property definitions to common locations.
* [SSHD-1038](https://issues.apache.org/jira/browse/SSHD-1038) Refactor packages from a module into a cleaner hierarchy.

## Minor code helpers

* [SSHD-1030](https://issues.apache.org/jira/browse/SSHD-1030) Added a NoneFileSystemFactory implementation
* [SSHD-1042](https://issues.apache.org/jira/browse/SSHD-1042) Added more callbacks to SftpEventListener
* [SSHD-1040](https://issues.apache.org/jira/browse/SSHD-1040) Make server key available after KEX completed.

## Behavioral changes and enhancements

* [SSHD-506](https://issues.apache.org/jira/browse/SSHD-506) Added support for AES-GCM ciphers.
* [SSHD-1004](https://issues.apache.org/jira/browse/SSHD-1004) Deprecate DES, RC4 and Blowfish ciphers from default setup.
* [SSHD-1004](https://issues.apache.org/jira/browse/SSHD-1004) Deprecate SHA-1 based key exchanges and signatures from default setup.
* [SSHD-1004](https://issues.apache.org/jira/browse/SSHD-1004) Deprecate MD5-based and truncated HMAC algorithms from default setup.
* [SSHD-1020](https://issues.apache.org/jira/browse/SSHD-1020) SSH connections getting closed abruptly with timeout exceptions.
* [SSHD-1026](https://issues.apache.org/jira/browse/SSHD-1026) Improve build reproductibility.
* [SSHD-1028](https://issues.apache.org/jira/browse/SSHD-1028) Fix SSH_MSG_DISCONNECT: Too many concurrent connections.
* [SSHD-1032](https://issues.apache.org/jira/browse/SSHD-1032) Fix possible ArrayIndexOutOfBoundsException in ChannelAsyncOutputStream.
* [SSHD-1033](https://issues.apache.org/jira/browse/SSHD-1033) Fix simultaneous usage of dynamic and local port forwarding.
* [SSHD-1039](https://issues.apache.org/jira/browse/SSHD-1039) Fix support for some basic options in ssh/sshd cli.
* [SSHD-1047](https://issues.apache.org/jira/browse/SSHD-1047) Support for SSH jumps.
* [SSHD-1048](https://issues.apache.org/jira/browse/SSHD-1048) Wrap instead of rethrow IOException in Future.
* [SSHD-1050](https://issues.apache.org/jira/browse/SSHD-1050) Fixed race condition in AuthFuture if exception caught before authentication started