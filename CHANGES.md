# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# Planned for next version

## Major code re-factoring

* `SftpSubSystemFactory` and its `Builder` use a `Supplier<CloseableExecutorService>` instead of
an executor instance in order to allow users to provide a "fresh" instance every time an SFTP
session is initiated and protect their instance from shutdown when session is destroyed:

```java
    CloseableExecutorService mySpecialExecutor = ...;
    SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder()
        .withExecutorServiceProvider(() -> ThreadUtils.noClose(mySpecialExecutor))
        .build();
    server.setSubsystemFactories(Collections.singletonList(factory));
```

* `SubsystemFactory` is a proper interface and it has been refactored to contain a
`createSubsystem` method that accepts the `ChannelSession` through which the request
has been made

* `UserAuthFactory` is a proper interface and it has been refactored to contain a
`createUserAuth` method that accepts the session instance through which the request is made.

* `ChannelFactory` is a proper interface and it has been refactored to contain a
`createChannel` method that accepts the session instance through which the request is made.

## Minor code helpers

* `SessionListener` supports `sessionPeerIdentificationReceived` that is invoked once successful
peer version data is received.

## Behavioral changes and enhancements

* [SSHD-930](https://issues.apache.org/jira/browse/SSHD-930) - Added configuration allowing the user to specify whether client should wait
for the server's identification before sending its own.

* [SSHD-931](https://issues.apache.org/jira/browse/SSHD-931) - Using an executor supplier instead of a specific instance in `SftpSubsystemFactory`

* [SSHD-934](https://issues.apache.org/jira/browse/SSHD-934) - Fixed ECDSA public key encoding into OpenSSH format.

* [SSHD-937](https://issues.apache.org/jira/browse/SSHD-937) - Provide session instance when creating a subsystem, user authentication, channel.