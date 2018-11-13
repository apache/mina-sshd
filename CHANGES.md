# Since version 2.1.0

## Major code re-factoring

* `AttributeStore` "read" methods moved to (new class) `AttributeRepository`

    * `AttributeKey` moved to `AttributeRepository`

    * `getAttribute` and `resolveAttribute` moved to `AttributeRepository`

    * Added `attributeKeys` enumeration method to `AttributeRepository`.

* `DEFAULT_PORT` moved from `SshConfigFileReader` to `SshConstants`

* Moved some session "summary" related definitions from `Session` to `SessionContext` (which `Session` extends)

* Added new `sessionDisconnect` method to `SessionListener`

* `ReservedSessionMessagesHandler#handleUnimplementedMessage` has an extra `cmd` argument
and is called both for `SSH_MSG_UNIMPLEMENTED` as well as for any other unexpected/unrecognized
command encountered during the session message processing loop.

* `ClientSessionCreator` has extra `connect` methods with an `AttributeRepository`
connection context argument

* `connectionEstablished` and `abortEstablishedConnection` methods of `IoServiceEventListener`
accept also an `AttributeRepository` connection context argument (propagated from the
`ClientSessionCreator#connect` invocation).

* `FilePasswordProvider`

    * Added an extra method (`handleDecodeAttemptResult`) that enables users to try and repeat an
    encrypted private key decoding using a different password.

    * The interface methods are also provided with a retry index that indicates the number of
    times they have been re-invoked for the same resource (including on success).

* `SshAgent#getIdentities` returns an `Iterable` rather than a `List`

* `SftpFileSystemProvider` and its associated helper classes have been moved to
`org.apache.sshd.client.subsystem.sftp.fs` package

## Behavioral changes and enhancements

* [SSHD-849](https://issues.apache.org/jira/browse/SSHD-849) - Data forwarding code makes sure all
pending packets have been sent to the peer channel when closing the tunnel gracefully.

* [SSHD-850](https://issues.apache.org/jira/browse/SSHD-850) - Add capability to retry a failed private key decryption

* [SSHD-857](https://issues.apache.org/jira/browse/SSHD-857) - Add session disconnect event signalling to SessionListener

    * Also calling `ReservedSessionMessagesHandler#handleUnimplementedMessage` not only for `SSH_MSG_UNIMPLEMENTED` but
    also for any unexpected/unrecognized command encountered during the session message processing loop.

* [SSHD-859](https://issues.apache.org/jira/browse/SSHD-859) - Provide client session connection context that is propagated to the SSH session

    * Also added connection context argument (propagated from the `ClientSessionCreator#connect` invocation)
    to`connectionEstablished` and `abortEstablishedConnection` methods of `IoServiceEventListener`.

* [SSHD-860](https://issues.apache.org/jira/browse/SSHD-860) - `UserAuthPublicKeyIterator` uses lazy loading of public key
identities both from agent and client session

    * Also using lazy identity `KeyPair`(s) loading in `ClientIdentitiesWatcher`

* [SSHD-861](https://issues.apache.org/jira/browse/SSHD-861) - Fixed username/password encoding for `SftpFileSystem` URI(s)

    * Also added `SftpFileSystemClientSessionInitializer` support in `SftpFileSystemProvider`
