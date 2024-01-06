# HOWTO(s)

This section contains some useful "cookbook recipes" for getting the most out of the code. Please note that it does **not** covers code samples that already appear in the previous sections - such as creating sessions, managing authentication, 3-way SCP, mounting file systems via SFTP, etc... Instead, it focuses on more "exotic" implementations that are not usually part of the normal SSH flow.

## [Endless tarpit](https://nullprogram.com/blog/2019/03/22/)

In order to achieve this one needs to use a `ReservedSessionMessagesHandler` on the server side that overrides the session identification and KEX message callbacks as follows:

* When `sendIdentification` callback is invoked

    * Check if you wish to trap the peer into the endless tarpit - if not, then return `null`
    
    * Spawn a thread that will feed the peer session with periodic infinite data.
    
    * Return a never succeeding `IoWriteFuture` - see `EndlessWriteFuture` in *sshd-contrib* package for such an implementation
    
* When `sendKexInitRequest` callback is invoked

    * Check if you wish to trap the peer into the endless tarpit - if not, then return `null`

    * Return an `IoWriteFuture` that "succeeds" immediately - see `ImmediateWriteFuture` in *sshd-contrib* package for such an implementation.

The idea is to prevent the normal session establish flow by taking over the initial handshake identification and blocking the initial KEX message from the server.

A sample implementation can be found in the `EndlessTarpitSenderSupportDevelopment` class in the *sshd-contrib* package *test* section.

## Disabling strict KEX

The current code implements the [strict-kex](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) extension by default. If users want/need to disable it, then
this can be done *programmatically* as follows (the example is for the client, but a similar approach can be implemented for the server):


```java
class NoStrictKexSession extends ClientSessionImpl {
    NoStrictKexSession(ClientFactoryManager client, IoSession ioSession) throws Exception {
        super(client, ioSession);
    }

    @Override
    protected Map<KexProposalOption, String> doStrictKexProposal(Map<KexProposalOption, String> proposal) {
        return proposal;
    }
}

class NoStrictKexSessionFactory extends SessionFactory {
    NoStrictKexSessionFactory(ClientFactoryManager client) {
        super(client);
    }

    @Override
    protected ClientSessionImpl doCreateSession(IoSession ioSession) throws Exception {
        return new NoStrictKexSession(getClient(), ioSession);
    }
}

SshClient client = ...;
SessionFactory factory = new NoStrictKexSessionFactory(client);
client.setSessionFactory(factory);
client.start();
```

If one needs to disable the protocol on a per-session basis, then it is possible to examine the peer's address (e.g., or anything else for that matter) in the `doCreateSession`
or the `doStrictKexProposal` overrides and then invoke the super-class (for continuing with strict KEX) or return immediately (for disabling it).