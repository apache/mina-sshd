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
* [GH-281](https://github.com/apache/mina-sshd/issues/281) Use OpenSSH first-match semantics for processing HostConfigEntries.
* [GH-282](https://github.com/apache/mina-sshd/issues/282) Correct setting file permissions on newly written host key files on Windows.
* [GH-283](https://github.com/apache/mina-sshd/issues/283) Fix handling of `CoreModuleProperties.PASSWORD_PROMPTS`.
* [GH-285](https://github.com/apache/mina-sshd/issues/285) Fix compilation failure on Java 19.
* [GH-293](https://github.com/apache/mina-sshd/issues/293) Handle SFTP buffer sizes larger than the server limit better.
* [GH-294](https://github.com/apache/mina-sshd/issues/294) Fix memory leak in `SftpFileSystemProvider`.
* [GH-297](https://github.com/apache/mina-sshd/issues/297) Auto-configure file password provider for reading encrypted SSH keys.
* [GH-298](https://github.com/apache/mina-sshd/issues/298) Server side heartbeat not working.
* [GH-300](https://github.com/apache/mina-sshd/issues/300) Read the channel id in `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` as unsigned int.
* [GH-313](https://github.com/apache/mina-sshd/issues/313) Log exceptions in the SFTP subsystem before sending a failure status reply.
* [GH-322](https://github.com/apache/mina-sshd/issues/322) Add basic Android O/S awareness.
* [GH-325](https://github.com/apache/mina-sshd/issues/325) `SftpFileSystemProvider`: fix deletions of symlinks through `Files.delete()`.
* [GH-364](https://github.com/apache/mina-sshd/issues/364) `AbstractAgentClient`: respect flags for RSA signature requests.


* [SSHD-1295](https://issues.apache.org/jira/browse/SSHD-1295) Fix cancellation of futures and add options to cancel futures on time-outs.
* [SSHD-1315](https://issues.apache.org/jira/browse/SSHD-1315) Do not log sensitive data at log level `TRACE`.
* [SSHD-1316](https://issues.apache.org/jira/browse/SSHD-1316) Possible OOM in `ChannelPipedInputStream` (fix channel window).
* [SSHD-1319](https://issues.apache.org/jira/browse/SSHD-1319) Use position in `SftpRemotePathChannel.transferFrom()`.

## Major code re-factoring

## Potential compatibility issues

### Futures and cancellation or time-outs

Apache MINA sshd is an asynchronous framework: for long-running operations, and
in particular operations involving network communication, the API returns a
future that client code can use to wait until the operation is complete. Waiting
on a future is usually done with a `future.verify()` or `future.verify(timeout)`
call. Futures can also be canceled.

Previous versions did not implement cancellation correctly: while the future
object itself was marked as "canceled", the underlying operation was not. The
same problem also existed for time-outs: when `future.verify(timeout)` timed out,
the underlying operation still continued to run asynchronously. This could
lead to problems because if the underlying operation eventually succeeded,
application code would be completely unaware. For instance in

```
  ClientSession session = client.connect(user, host, port).verify(timeout).getSession();
```

the application might get a time-out, but the underlying connect operation
would continue to run, might succeed eventually, and then there would in fact
be a `ClientSession` (and thus also a network connection, and a socket used up).
But the application had no way to access that session to shut it down. The net
effect was a socket leak.

In this version, this has been corrected. By default, the future is canceled
when a time-out occurs, and `future.cancel()` is propagated to the underlying
operation and cancels it.

Canceling an operation itself may not be possible immediately. For instance,
an authentication attempt is a message exchange with the server. If the
authentication request has already been sent when cancellation is requested,
the sending of that request cannot be undone. The authentication can only be
cancelled after the reply from the server has been received, and if that reply
is an authentication success, cancellation isn't even possible anymore. Or
consider requesting a port forwarding: that, too, is a request-reply message
exchange. Once the request has been sent, there are two cases: if the server
replies with a failure message, the port forwarding failed and since there is
nothing to cancel, cancellation is not possible. If the reply indicates the
tunnel was established, but `future.cancel()` had already been called, we have
two options: either we shut down the just established tunnel again and say
cancellation succeeded, or we say cancellation failed and report a successfully
established tunnel. Because cancellations may be caused by time-outs, Apache
MINA sshd chooses the first option and shuts down the tunnel again. Otherwise
an application might get a time-out but still be left with an established
tunnel.

Cancellation is only possible while the operation has not completed yet. If
a future is already done, it cannot be canceled anymore.

The `cancel()` operation on a future is thus a _request_ to cancel the
operation; it may or may not result in actually cancelling the operation.
`cancel()` itself therefore returns a `CancelFuture` that client code can use
to wait for the request having been handled, and then learn whether the
operation was indeed canceled.

Calls to `verify()` throw an `SshException` with a
`java.util.concurrent.CancellationException` as cause if cancelled asynchronously
via the `cancel()` method.

Application code can control the behavior on time-outs. The `verify()` method
takes besides a time-out duration newly also a number of `CancelOption`s as
parameters.

There are three possible values to cancel on a time-out, to cancel on an
interruption, or not to cancel at all when either occurs. For backwards
compatibility, the default behavior of `AuthFuture` and of `OpenFuture` is
unchanged: to cancel on a time-out, client code must pass the
`CancelOption.CANCEL_ON_TIMEOUT` flag.

The default behavior of `ConnectFuture` _has_ been changed: by default, it _does_
cancel the connection attempt if a time-out occurs. To avoid this, client code
would have to pass the `CancelOption.NO_CANCELLATION` flag expressly. This change
in behavior was done to avoid socket leaks, and it was deemed acceptable since
a difference in behavior could only occur if existing client code called
`AuthFuture.verify()` in different threads on the same future instance, or
sequentially on the same future instance again after the first time-out. Both
cases are highly unlikely to occur in existing client code. If existing code
needs this behavior, it needs to be adapted to pass `CancelOption`s as may be
appropriate for the precise use case.

## Minor code helpers

## Behavioral changes and enhancements

* Support for reading SSH keys from PEM files containing encrypted private keys
  [RFC 5958, EncryptedPrivateKeyInfo](https://www.rfc-editor.org/rfc/rfc5958) has
  been added. Such PEM files start with `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
  Reading and decrypting keys from such files requires Bouncy Castle to be
  present.
* Support reading SSH keys from PEM files starting with
  `-----BEGIN ED25519 PRIVATE KEY-----`. Some OpenSSL versions could produce such
  files when the user specified "traditional" PEM output. (Encrypted keys written
  using [RFC 1421](https://www.rfc-editor.org/rfc/rfc1421) encryption.) Modern
  OpenSSL refuses to create such PEM files; it always uses PKCS#8 (RFC 5958) style
  PEM files for EdDSA keys.
* Support reading encrypted private keys in openSSH format that have been
  encrypted with an AEAD cipher.
* `CoreModuleProperties.PASSWORD_PROMPTS` is now also used for password
  authentication. Previous versions used it only for keyboard-interactive
  authentication. The semantics has been clarified to be the equivalent
  of the OpenSSH configuration `NumberOfPasswordPrompts`, which is actually
  the number of authentication *attempts*. (In keyboard-interactive
  authentication, there may be several prompts per authentication attempt.)
  Only interactive authentication attempts using `UserInteraction` count
  towards the limit. Attempts fulfilled by explicitly provided passwords
  (via `session.addPasswordIdentity()` or `session.setPasswordIdentityProvider()`)
  are *not* counted. The default value of the property is unchanged and is
  3, as in OpenSSH. The limit is applied independently for both authentication
  mechanisms: with the default setting, there can be three keyboard-interactive
  authentication attempts, plus three more password authentication attempts if
  both methods are configured and applicable.

### Connection time-outs

Connection time-outs are normally handled in Apache MINA SSHD at the application
level by passing a time-out to `ConnectFuture.verify()`:

```
ClientSession session = client.connect(user, host, port).verify(MY_TIMEOUT).getSession();
```

However, the actual I/O library used might have its own connection time-out.
With large time-outs, the behavior depended on the actual implementation of
the I/O back-end used:

* The default NIO2 back-end has no default connection time-out at all, so the
  `verify(MY_TIMEOUT)` call would always time-out after `MY_TIMEOUT` had elapsed.
* Apache MINA has a default connection time-out of one minute, so even if
  `MY_TIMEOUT` was larger, the time-out would still occur after one minute.
* Netty has a default connection time-out of 30 seconds.

In this version, a new property `CoreModuleProperties.IO_CONNECTION_TIMEOUT`
can be set to control this I/O connection time-out. It can be set on an
`SshClient` or `SshServer`; if set (and > 0), the I/O back-end is configured
to use that value as its I/O connection time-out, and
`ConnectFuture.verify(MY_TIMEOUT)` will always time-out at
`Math.min(CoreModuleProperties.IO_CONNECTION_TIMEOUT, MY_TIMEOUT)`. The property
is also effective for the NIO2 back-end; the default value is 1 minute.

`verify()` throws an `SshException` if it fails or times out. The _cause_ of
that exception is a `java.net.ConnectException` if the I/O connection time-out
expired, and a `java.util.concurrent.TimeoutException` if the application
time-out expired. (And if the future was canceled explicitly before any
time-out was reached, the cause is a `java.util.concurrent.CancellationException`;
see above.)

The new `CancelOption`s discussed above apply only if the application
time-out expires. If the connection attempt times out at I/O level, it is
the responsibility of the I/O library to ensure no resources such as
sockets are consumed, and there is no SSH session created either.
