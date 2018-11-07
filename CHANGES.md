# Since version 2.1.0

## Major code re-factoring

* `AttributeKey` moved from `AttributeStore` to `AttributeRepository`

* `getAttribute` moved from `AttributeStore` to `AttributeRepository` + added
`attributeKeys` method.

* `DEFAULT_PORT` moved from `SshConfigFileReader` to `SshConstants`

* Added new `sessionDisconnect` method to `SessionListener`

* `ReservedSessionMessagesHandler#handleUnimplementedMessage` has an extra `cmd` argument
and is called both for `SSH_MSG_UNIMPLEMENTED` and also for any unexpected/unrecognized command
encountered during the session message processing loop.

* `ClientSessionCreator` has extra `connect` methods with an `AttributeRepository`
connection context argument

* `connectionEstablished` and `abortEstablishedConnection` methods of `IoServiceEventListener`
accept also an `AttributeRepository` connection context argument (propagated from the
`ClientSessionCreator#connect` invocation).

* `FilePasswordProvider` has an extra method (`handleDecodeAttemptResult`) that enables
user to try and repeat an encrypted private key decoding using a different password.

* `SshAgent#getIdentities` returns an `Iterable` rather than a `List`


## Behavioral changes

* [SSHD-860](https://issues.apache.org/jira/browse/SSHD-860) `UserAuthPublicKeyIterator` uses lazy loading
of public key identities both from agent and client session
