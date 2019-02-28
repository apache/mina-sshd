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

* The `SignalListener` accepts a `Channel` argument indicating the channel instance through which the signal was received.

* When creating a client shell or command channel one can provide optional PTY and/or environment values in order
to override the internal default ones.

    * In this context, the `PtyCapableChannelSession#setEnv` method has been modified to accept ANY object.
    When the environment values are sent to the server, the object's `toString()` will be used. Furthermore,
    if one provides a `null` value, the previous registered value (if any) is **removed**.

## Minor code helpers

* The `Session` object provides a `isServerSession` method that can be used to distinguish between
client/server instances without having to resort to `instanceof`.

* When creating a CLI SSH client one can specify `-o KexExtensionHandler=XXX` option to initialize
a client-side `KexExtensionHandler` using an FQCN. If `default` is specified as the option value,
then the internal `DefaultClientKexExtensionHandler` is used.

## Behavioral changes and enhancements

* [SSHD-782](https://issues.apache.org/jira/browse/SSHD-882) - Added session level heartbeat mechanism via `SSH_MSG_IGNORE`
or customized user provided code.

In order to support customized user code for this feature, the `ReservedSessionMessagesHandler` can be used to
implement any kind of user-defined heartbeat. *Note:* if the user configured such a mechanism, then the
`sendReservedHeartbeat` method **must** be implemented since the default throws `UnsupportedOperationException`
which will cause the session to be terminated the 1st time the method is invoked.

* [SSHD-882](https://issues.apache.org/jira/browse/SSHD-882) - Provide hooks to allow users to register a consumer
for STDERR data sent via the `ChannelSession` - especially for the SFTP subsystem.

* [SSHD-892](https://issues.apache.org/jira/browse/SSHD-882) - Inform user about possible session disconnect prior
to disconnecting and allow intervention via `SessionDisconnectHandler`.

* [SSHD-893](https://issues.apache.org/jira/browse/SSHD-893) - Using Path(s) instead of String(s) as DirectoryScanner results

* [SSHD-895](https://issues.apache.org/jira/browse/SSHD-895) - Add support for RSA + SHA-256/512 signatures. **Note:** according
to [RFC - 8332 - section 3.3](https://tools.ietf.org/html/rfc8332#section-3.3):

>> Implementation experience has shown that there are servers that apply
>> authentication penalties to clients attempting public key algorithms
>> that the SSH server does not support.

>> When authenticating with an RSA key against a server that does not
>> implement the "server-sig-algs" extension, clients MAY default to an
>> "ssh-rsa" signature to avoid authentication penalties.  When the new
>> rsa-sha2-* algorithms have been sufficiently widely adopted to
>> warrant disabling "ssh-rsa", clients MAY default to one of the new
>> algorithms.

Therefore we do not include by default the "rsa-sha-*" signature factories in the `SshClient`. They can
be easily added by using the relevant `BuiltinSignatures`:

```java
SshClient client = SshClient.setupDefaultClient();
client.setSignatureFactories(
    Arrays.asList(
        /* This is the full list in the recommended preference order,
         * but the initialization code can choose and/or re-order
         */
        BuiltinSignatures.nistp256,
        BuiltinSignatures.nistp384,
        BuiltinSignatures.nistp521,
        BuiltinSignatures.ed25519,
        BuiltinSignatures.rsaSHA512,
        BuiltinSignatures.rsaSHA256,     // should check if isSupported since not required by default for Java 8
        BuiltinSignatures.rsa,
        BuiltinSignatures.dsa));
```

* [SSHD-896](https://issues.apache.org/jira/browse/SSHD-896) - Added support for [KEX extension negotiation](https://tools.ietf.org/html/rfc8308)

* [SSHD-870](https://issues.apache.org/jira/browse/SSHD-896) - Added support for GPGv2 public keyring (Note: requires upgraded
[Bouncycastle](https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk15on/1.61) and [jpgpj](https://mvnrepository.com/artifact/org.c02e.jpgpj/jpgpj/0.6.1) versions).

* [SSHD-897](https://issues.apache.org/jira/browse/SSHD-897) - The default CLI code automatically tries to detect the PTY settings to use
if opening a shell or command channel.

* [SSHD-901](https://issues.apache.org/jira/browse/SSHD-901) - Added capability to request a reply for the `keepalive@...` heartbeat request
in order to avoid client-side session timeout due to no traffic from server.

* [SSHD-903](https://issues.apache.org/jira/browse/SSHD-903) - Fixed the SFTP version negotiation behavior in case client proposed version is higher than server supported one.
