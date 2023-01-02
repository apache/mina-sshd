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

# Planned for next version

## Bug fixes

* [GH-268](https://github.com/apache/mina-sshd/issues/268) (Regression in 2.9.0) Heartbeat should throw an exception if no reply arrives within the timeout.
* [GH-275](https://github.com/apache/mina-sshd/issues/275) SFTP: be more lenient when reading `SSH_FXP_STATUS` replies.
* [GH-282](https://github.com/apache/mina-sshd/issues/282) Correct setting file permissions on newly written host key files on Windows.
* [GH-283](https://github.com/apache/mina-sshd/issues/283) Fix handling of `CoreModuleProperties.PASSWORD_PROMPTS`.
* [GH-285](https://github.com/apache/mina-sshd/issues/285) Fix compilation failure on Java 19.
* [GH-294](https://github.com/apache/mina-sshd/issues/294) Fix memory leak in `SftpFileSystemProvider`.
* [GH-297](https://github.com/apache/mina-sshd/issues/297) Auto-configure file password provider for reading encrypted SSH keys.
* [GH-298](https://github.com/apache/mina-sshd/issues/298) Server side heartbeat not working.
* [GH-300](https://github.com/apache/mina-sshd/issues/300) Read the channel id in `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` as unsigned int.


* [SSHD-1315](https://issues.apache.org/jira/browse/SSHD-1315) Do not log sensitive data at log level `TRACE`.
* [SSHD-1316](https://issues.apache.org/jira/browse/SSHD-1316) Possible OOM in `ChannelPipedInputStream` (fix channel window).


## Major code re-factoring

## Potential compatibility issues

## Minor code helpers

## Behavioral changes and enhancements

* `CoreModuleProperties.PASSWORD_PROMPTS` is now also used for password authentication. Previous versions used it only for keyboard-interactive authentication.
  The semantics has been clarified to be the equivalent of the OpenSSH configuration `NumberOfPasswordPrompts`, which is actually the number of authentication
  *attempts*. (In keyboard-interactive authentication, there may be several prompts per authentication attempt.) Only interactive authentication attempts
  using `UserInteraction` count towards the limit. Attempts fulfilled by explicitly provided passwords (via `session.addPasswordIdentity()` or
  `session.setPasswordIdentityProvider()`) are *not* counted. The default value of the property is unchanged and is 3, as in OpenSSH. The limit is applied
  independently for both authentication mechanisms: with the default setting, there can be three keyboard-interactive authentication attempts, plus three
  more password authentication attempts if both methods are configured and applicable.