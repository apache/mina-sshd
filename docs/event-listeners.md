## Event listeners

The code supports registering many types of event listeners that enable receiving notifications about important events
as well as sometimes intervening in the way these events are handled. All listener interfaces extend `SshdEventListener`
so they can be easily detected and distinguished from other `EventListener`(s).

In general, event listeners are **cumulative** - e.g., any channel event listeners registered on the `SshClient/Server` are
automatically added to all sessions, *in addition* to any such listeners registered on the `Session`, as well as any specific
listeners registered on a specific `Channel` - e.g.,


```java

    // Any channel event will be signalled to ALL the registered listeners
    sshClient/Server.addChannelListener(new Listener1());
    sshClient/Server.addSessionListener(new SessionListener() {
        @Override
        public void sessionCreated(Session session) {
            session.addChannelListener(new Listener2());
            session.addChannelListener(new ChannelListener() {
                @Override
                public void channelInitialized(Channel channel) {
                    channel.addChannelListener(new Listener3());
                }
            });
        }
    });

```

### `IoServiceEventListener`

This listener provides low-level events regarding connection establishment (by the client) or acceptance (by the server). The listener is registered
on the `IoServiceFactory` via the `FactoryManager`-s (i.e., `SshClient/Server#setIoServiceEventListener`). Unlike other listeners defined in this
section, it is **not cumulative** - i.e., one can `setIoServiceEventListener` but not `addIoServiceEventListener` - thus **replacing** any previously
registered listener.

### `SessionListener`

Informs about session related events. One can modify the session - although the modification effect depends on the session's **state**. E.g., if one
changes the ciphers *after* the key exchange (KEX) phase, then they will take effect only if the keys are re-negotiated. It is important to read the
documentation very carefully and understand at which stage each listener method is invoked and what are the repercussions of changes at that stage.
In this context, it is worth mentioning that one can attach to sessions **arbitrary attributes** that can be retrieved by the user's code later on:


```java

    public static final AttributeKey<String> STR_KEY = new AttributeKey<>();
    public static final AttributeKey<Long> LONG_KEY = new AttributeKey<>();

    sshClient/Server.addSessionListener(new SessionListener() {
        @Override
        public void sessionCreated(Session session) {
            session.setAttribute(STR_KEY, "Some string value");
            session.setAttribute(LONG_KEY, 3777347L);
            // ...etc...
        }

        @Override
        public void sessionClosed(Session session) {
            String str = session.getAttribute(STR_KEY);
            Long l = session.getAttribute(LONG_KEY);
            // ... do something with the retrieved attributes ...
        }
    });
```

### `ChannelListener`

Informs about channel related events - as with sessions, once can influence the channel to some extent, depending on the channel's **state**.
The ability to influence channels is much more limited than sessions. In this context, it is worth mentioning that one can attach to channels
**arbitrary attributes** that can be retrieved by the user's code later on - same was as it is done for sessions.


### `UnknownChannelReferenceHandler`

Invoked whenever a message intended for an unknown channel is received. By default, the code **ignores** the vast majority of such messages
and logs them at DEBUG level. For a select few types of messages the code generates an `SSH_CHANNEL_MSG_FAILURE` packet that is sent to the
peer session - see `DefaultUnknownChannelReferenceHandler` implementation. The user may register handlers at any level - client/server, session
and/or connection service - the one registered "closest" to connection service will be used.

### `KexExtensionHandler`

Provides hook for implementing [KEX extension negotiation](https://tools.wordtothewise.com/rfc/rfc8308)

### `ReservedSessionMessagesHandler`

Can be used to handle the following cases:

* [SSH_MSG_IGNORE](https://tools.ietf.org/html/rfc4253#section-11.2)
* [SSH_MSG_DEBUG](https://tools.ietf.org/html/rfc4253#section-11.3)
* [SSH_MSG_UNIMPLEMENTED](https://tools.ietf.org/html/rfc4253#section-11.4)
* Any other unrecognized message received in the session.

**Note:** The `handleUnimplementedMessage` method serves both for handling `SSH_MSG_UNIMPLEMENTED` and any other unrecognized
message received in the session as well.


```java

    class MyClientSideReservedSessionMessagesHandler implements ReservedSessionMessagesHandler {
        @Override
        public boolean handleUnimplementedMessage(Session session, int cmd, Buffer buffer) throws Exception {
            switch(cmd) {
                case MY_SPECIAL_CMD1:
                    ....
                    return true;
                case MY_SPECIAL_CMD2:
                    ....
                    return true;
                default:
                    return false;    // send SSH_MSG_UNIMPLEMENTED reply if necessary
            }
        }
    }

    // client side
    SshClient client = SshClient.setupDefaultClient();
    // This is the default for ALL sessions unless specifically overridden
    client.setReservedSessionMessagesHandler(new MyClientSideReservedSessionMessagesHandler());
    // Adding it via a session listener
    client.setSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // Overrides the one set at the client level.
                if (isSomeSessionOfInterest(session)) {
                    session.setReservedSessionMessagesHandler(new MyClientSessionReservedSessionMessagesHandler(session));
                }
            }
    });

    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        // setting it explicitly
        session.setReservedSessionMessagesHandler(new MyOtherClientSessionReservedSessionMessagesHandler(session));
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        ...use the session...
    }


    // server side
    SshServer server = SshServer.setupDefaultServer();
    // This is the default for ALL sessions unless specifically overridden
    server.setReservedSessionMessagesHandler(new MyServerSideReservedSessionMessagesHandler());
    // Adding it via a session listener
    server.setSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // Overrides the one set at the server level.
                if (isSomeSessionOfInterest(session)) {
                    session.setReservedSessionMessagesHandler(new MyServerSessionReservedSessionMessagesHandler(session));
                }
            }
    });

```

**NOTE:** Unlike "regular" event listeners, the handler is not cumulative - i.e., setting it overrides the previous instance
rather than being accumulated. However, one can use the `EventListenerUtils` and create a cumulative listener - see how
`SessionListener` or `ChannelListener` proxies were implemented.

### `SessionDisconnectHandler`

This handler can be registered in order to monitor session disconnect initiated by the internal code due to various
protocol requirements - e.g., unknown service, idle timeout, etc.. In many cases the implementor can intervene and
cancel the disconnect by handling the problem somehow and then signaling to the code that there is no longer any need
to disconnect. The handler can be registered globally at the `SshClient/Server` instance or per-session (via a `SessionListener`).

**NOTE:** this handler is non-cumulative - i.e., setting it replaces any existing previous handler instance.

### `SignalListener`

Informs about signal requests as described in [RFC 4254 - section 6.9](https://tools.ietf.org/html/rfc4254#section-6.9), break requests
(sent as SIGINT) as described in [RFC 4335](https://tools.ietf.org/html/rfc4335) and "window-change" (sent as SIGWINCH) requests as described
in [RFC 4254 - section 6.7](https://tools.ietf.org/html/rfc4254#section-6.7)


### `SftpEventListener`

Provides information about major SFTP protocol events. The provided `File/DirectoryHandle` to the various callbacks an also be used to
store user-defined attributes via its `AttributeStore` implementation. The listener is registered at the `SftpSubsystemFactory`:


```java
    public class MySfpEventListener implements SftpEventListener {
        private static final AttributeKey<SomeType> MY_SPECIAL_KEY = new Attribute<SomeType>();

        ...
        @Override
        public void opening(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
            localHandle.setAttribute(MY_SPECIAL_KEY, instanceOfSomeType);
        }

        @Override
        public void writing(
                ServerSession session, String remoteHandle, FileHandle localHandle,
                long offset, byte[] data, int dataOffset, int dataLen)
                    throws IOException {
            SomeType myData = localHandle.getAttribute(MY_SPECIAL_KEY);
            ...do something based on my data...
        }
    }


    SftpSubsystemFactory factory = new SftpSubsystemFactory();
    factory.addSftpEventListener(new MySftpEventListener());
    sshd.setSubsystemFactories(Collections.<NamedFactory<Command>>singletonList(factory));

```

**Note:** the attached attributed are automatically removed once handle has been closed - regardless of
whether the close attempt was successful or not. In other words, after `SftpEventListener#closed` has been
called, all attributes associated with the handle are cleared.

### `PortForwardingEventListener`

Informs and allows tracking of port forwarding events as described in [RFC 4254 - section 7](https://tools.ietf.org/html/rfc4254#section-7)
as well as the (simple) [SOCKS](https://en.wikipedia.org/wiki/SOCKS) protocol (versions 4, 5). In this context, one can create a
`PortForwardingTracker` that can be used in a `try-with-resource` block so that the set up forwarding is automatically torn down when
the tracker is `close()`-d:


```java

    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        try (PortForwardingTracker tracker = session.createLocal/RemotePortForwardingTracker(...)) {
            ...do something that requires the tunnel...
        }

        // Tunnel is torn down when code reaches this point
    }
```

### `ScpTransferEventListener`

Inform about SCP related events. `ScpTransferEventListener`(s) can be registered on *both* client and server side:


```java

    // Server side
    ScpCommandFactory factory = new ScpCommandFactory(...with/out delegate..);
    factory.addEventListener(new MyServerSideScpTransferEventListener());
    sshd.setCommandFactory(factory);

    // Client side
    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        ScpClient scp = session.createScpClient(new MyClientSideScpTransferEventListener());
        ...scp.upload/download...
    }
```
