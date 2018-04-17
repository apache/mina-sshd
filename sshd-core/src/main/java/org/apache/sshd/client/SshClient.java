/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.file.LinkOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.DefaultConnectFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.AbstractClientSession;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientProxyConnector;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.client.session.ClientUserAuthServiceFactory;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.client.simple.AbstractSimpleClientSessionCreator;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * <P>
 * Entry point for the client side of the SSH protocol.
 * </P>
 *
 * <P>
 * The default configured client can be created using
 * the {@link #setUpDefaultClient()}.  The next step is to
 * start the client using the {@link #start()} method.
 * </P>
 *
 * <P>
 * Sessions can then be created using on of the
 * {@link #connect(String, String, int)} or {@link #connect(String, java.net.SocketAddress)}
 * methods.
 * </P>
 *
 * <P>
 * The client can be stopped any time using the {@link #stop()} method.
 * </P>
 *
 * <P>
 * Following is an example of using the {@code SshClient}:
 * </P>
 *
 * <pre>
 * try (SshClient client = SshClient.setUpDefaultClient()) {
 *      client.start();
 *
 *      try (ClientSession session = client.connect(login, host, port).await().getSession()) {
 *          session.addPasswordIdentity(password);
 *          session.auth().verify(...timeout...);
 *
 *          try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
 *              channel.setIn(new NoCloseInputStream(System.in));
 *              channel.setOut(new NoCloseOutputStream(System.out));
 *              channel.setErr(new NoCloseOutputStream(System.err));
 *              channel.open();
 *              channel.waitFor(ClientChannel.CLOSED, 0);
 *          } finally {
 *              session.close(false);
 *          }
 *    } finally {
 *        client.stop();
 *    }
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshClient extends AbstractFactoryManager implements ClientFactoryManager, ClientSessionCreator, Closeable {

    public static final Factory<SshClient> DEFAULT_SSH_CLIENT_FACTORY = SshClient::new;

    /**
     * Default user authentication preferences if not set
     * @see <A HREF="http://linux.die.net/man/5/ssh_config">ssh_config(5) - PreferredAuthentications</A>
     */
    public static final List<NamedFactory<UserAuth>> DEFAULT_USER_AUTH_FACTORIES =
            Collections.unmodifiableList(Arrays.<NamedFactory<UserAuth>>asList(
                    UserAuthPublicKeyFactory.INSTANCE,
                    UserAuthKeyboardInteractiveFactory.INSTANCE,
                    UserAuthPasswordFactory.INSTANCE
            ));
    public static final List<ServiceFactory> DEFAULT_SERVICE_FACTORIES =
            Collections.unmodifiableList(Arrays.asList(
                    ClientUserAuthServiceFactory.INSTANCE,
                    ClientConnectionServiceFactory.INSTANCE
            ));

    protected IoConnector connector;
    protected SessionFactory sessionFactory;
    protected UserInteraction userInteraction;
    protected List<NamedFactory<UserAuth>> userAuthFactories;

    private ClientProxyConnector proxyConnector;
    private ServerKeyVerifier serverKeyVerifier;
    private HostConfigEntryResolver hostConfigEntryResolver;
    private ClientIdentityLoader clientIdentityLoader;
    private FilePasswordProvider filePasswordProvider;
    private PasswordIdentityProvider passwordIdentityProvider;
    private ScpFileOpener scpOpener;

    private final List<Object> identities = new CopyOnWriteArrayList<>();
    private final AuthenticationIdentitiesProvider identitiesProvider;
    private final AtomicBoolean started = new AtomicBoolean(false);

    public SshClient() {
        identitiesProvider = AuthenticationIdentitiesProvider.wrap(identities);
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public ClientProxyConnector getClientProxyConnector() {
        return proxyConnector;
    }

    @Override
    public void setClientProxyConnector(ClientProxyConnector proxyConnector) {
        this.proxyConnector = proxyConnector;
    }

    @Override
    public ScpFileOpener getScpFileOpener() {
        return scpOpener;
    }

    @Override
    public void setScpFileOpener(ScpFileOpener opener) {
        scpOpener = opener;
    }

    @Override
    public ServerKeyVerifier getServerKeyVerifier() {
        return serverKeyVerifier;
    }

    @Override
    public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = Objects.requireNonNull(serverKeyVerifier, "No server key verifier");
    }

    @Override
    public HostConfigEntryResolver getHostConfigEntryResolver() {
        return hostConfigEntryResolver;
    }

    @Override
    public void setHostConfigEntryResolver(HostConfigEntryResolver resolver) {
        this.hostConfigEntryResolver = Objects.requireNonNull(resolver, "No host configuration entry resolver");
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return filePasswordProvider;
    }

    @Override
    public void setFilePasswordProvider(FilePasswordProvider provider) {
        this.filePasswordProvider = Objects.requireNonNull(provider, "No file password provider");
    }

    @Override
    public ClientIdentityLoader getClientIdentityLoader() {
        return clientIdentityLoader;
    }

    @Override
    public void setClientIdentityLoader(ClientIdentityLoader loader) {
        this.clientIdentityLoader = Objects.requireNonNull(loader, "No client identity loader");
    }

    @Override
    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    @Override
    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction;
    }

    @Override
    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return userAuthFactories;
    }

    @Override
    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = ValidateUtils.checkNotNullAndNotEmpty(userAuthFactories, "No user auth factories");
    }

    @Override
    public AuthenticationIdentitiesProvider getRegisteredIdentities() {
        return identitiesProvider;
    }

    @Override
    public PasswordIdentityProvider getPasswordIdentityProvider() {
        return passwordIdentityProvider;
    }

    @Override
    public void setPasswordIdentityProvider(PasswordIdentityProvider provider) {
        passwordIdentityProvider = provider;
    }

    @Override
    public void addPasswordIdentity(String password) {
        // DO NOT USE checkNotNullOrNotEmpty SINCE IT TRIMS THE RESULT
        ValidateUtils.checkTrue((password != null) && (!password.isEmpty()), "No password provided");
        identities.add(password);
        if (log.isDebugEnabled()) { // don't show the password in the log
            log.debug("addPasswordIdentity({}) {}", this, KeyUtils.getFingerPrint(password));
        }
    }

    @Override
    public String removePasswordIdentity(String password) {
        if (GenericUtils.isEmpty(password)) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.PASSWORD_IDENTITY_COMPARATOR, password);
        if (index >= 0) {
            return (String) identities.remove(index);
        } else {
            return null;
        }
    }

    @Override
    public void addPublicKeyIdentity(KeyPair kp) {
        Objects.requireNonNull(kp, "No key-pair to add");
        Objects.requireNonNull(kp.getPublic(), "No public key");
        Objects.requireNonNull(kp.getPrivate(), "No private key");

        identities.add(kp);

        if (log.isDebugEnabled()) {
            log.debug("addPublicKeyIdentity({}) {}", this, KeyUtils.getFingerPrint(kp.getPublic()));
        }
    }

    @Override
    public KeyPair removePublicKeyIdentity(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.KEYPAIR_IDENTITY_COMPARATOR, kp);
        if (index >= 0) {
            return (KeyPair) identities.remove(index);
        } else {
            return null;
        }
    }

    @Override
    protected void checkConfig() {
        super.checkConfig();

        Objects.requireNonNull(getForwarderFactory(), "ForwarderFactory not set");
        Objects.requireNonNull(getServerKeyVerifier(), "ServerKeyVerifier not set");
        Objects.requireNonNull(getHostConfigEntryResolver(), "HostConfigEntryResolver not set");
        Objects.requireNonNull(getClientIdentityLoader(), "ClientIdentityLoader not set");
        Objects.requireNonNull(getFilePasswordProvider(), "FilePasswordProvider not set");

        // if no client identities override use the default
        KeyPairProvider defaultIdentities = getKeyPairProvider();
        if (defaultIdentities == null) {
            setKeyPairProvider(new DefaultClientIdentitiesWatcher(this::getClientIdentityLoader, this::getFilePasswordProvider));
        }

        // Register the additional agent forwarding channel if needed
        SshAgentFactory agentFactory = getAgentFactory();
        if (agentFactory != null) {
            List<NamedFactory<Channel>> forwarders =
                    ValidateUtils.checkNotNullAndNotEmpty(
                            agentFactory.getChannelForwardingFactories(this), "No agent channel forwarding factories for %s", agentFactory);
            List<NamedFactory<Channel>> factories = getChannelFactories();
            if (GenericUtils.isEmpty(factories)) {
                factories = forwarders;
            } else {
                // create a copy in case un-modifiable original
                List<NamedFactory<Channel>> factories2 =
                    new ArrayList<>(factories.size() + forwarders.size());
                factories2.addAll(factories);
                factories2.addAll(forwarders);
                factories = factories2;
            }

            setChannelFactories(factories);
        }

        if (GenericUtils.isEmpty(getServiceFactories())) {
            setServiceFactories(DEFAULT_SERVICE_FACTORIES);
        }

        if (GenericUtils.isEmpty(getUserAuthFactories())) {
            setUserAuthFactories(DEFAULT_USER_AUTH_FACTORIES);
        }
    }

    public boolean isStarted() {
        return started.get();
    }

    /**
     * Starts the SSH client and can start creating sessions using it.
     * Ignored if already {@link #isStarted() started}.
     */
    public void start() {
        if (isStarted()) {
            return;
        }

        checkConfig();
        if (sessionFactory == null) {
            sessionFactory = createSessionFactory();
        }

        setupSessionTimeout(sessionFactory);

        connector = createConnector();
        started.set(true);
    }

    public void stop() {
        if (!started.getAndSet(false)) {
            return;
        }

        try {
            long maxWait = this.getLongProperty(STOP_WAIT_TIME, DEFAULT_STOP_WAIT_TIME);
            boolean successful = close(true).await(maxWait);
            if (!successful) {
                throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getClass().getSimpleName() + " while stopping client: " + e.getMessage());
            }

            if (log.isTraceEnabled()) {
                log.trace("Stop exception details", e);
            }
        }
    }

    public void open() throws IOException {
        start();
    }

    @Override
    protected Closeable getInnerCloseable() {
        Object closeId = toString();
        return builder()
            .run(closeId, () -> removeSessionTimeout(sessionFactory))
            .sequential(connector, ioServiceFactory)
            .run(closeId, () -> {
                connector = null;
                ioServiceFactory = null;
                if (shutdownExecutor && (executor != null) && (!executor.isShutdown())) {
                    try {
                        executor.shutdownNow();
                    } finally {
                        executor = null;
                    }
                }
            })
            .build();
    }

    @Override
    public ConnectFuture connect(String username, String host, int port) throws IOException {
        HostConfigEntryResolver resolver = getHostConfigEntryResolver();
        HostConfigEntry entry = resolver.resolveEffectiveHost(host, port, username);
        if (entry == null) {
            // generate a synthetic entry
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) no overrides", username, host, port);
            }

            // IPv6 addresses have a format which means they need special treatment, separate from pattern validation
            if (SshdSocketAddress.isIPv6Address(host)) {
                // Not using a pattern as the host name passed in was a valid IPv6 address
                entry = new HostConfigEntry("", host, port, username);
            } else {
                entry = new HostConfigEntry(host, host, port, username);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) effective: {}", username, host, port, entry);
            }
        }

        return connect(entry);
    }

    @Override
    public ConnectFuture connect(String username, SocketAddress address) throws IOException {
        Objects.requireNonNull(address, "No target address");
        if (address instanceof InetSocketAddress) {
            InetSocketAddress inetAddress = (InetSocketAddress) address;
            String host = ValidateUtils.checkNotNullAndNotEmpty(inetAddress.getHostString(), "No host");
            int port = inetAddress.getPort();
            ValidateUtils.checkTrue(port > 0, "Invalid port: %d", port);

            HostConfigEntryResolver resolver = getHostConfigEntryResolver();
            HostConfigEntry entry = resolver.resolveEffectiveHost(host, port, username);
            if (entry == null) {
                if (log.isDebugEnabled()) {
                    log.debug("connect({}@{}:{}) no overrides", username, host, port);
                }

                return doConnect(username, address, Collections.emptyList(), true);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("connect({}@{}:{}) effective: {}", username, host, port, entry);
                }

                return connect(entry);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}) not an InetSocketAddress: {}", username, address, address.getClass().getName());
            }
            return doConnect(username, address, Collections.emptyList(), true);
        }
    }

    @Override
    public ConnectFuture connect(HostConfigEntry hostConfig) throws IOException {
        Objects.requireNonNull(hostConfig, "No host configuration");
        String host = ValidateUtils.checkNotNullAndNotEmpty(hostConfig.getHostName(), "No target host");
        int port = hostConfig.getPort();
        ValidateUtils.checkTrue(port > 0, "Invalid port: %d", port);

        Collection<KeyPair> keys = loadClientIdentities(hostConfig.getIdentities(), IoUtils.EMPTY_LINK_OPTIONS);
        return doConnect(hostConfig.getUsername(), new InetSocketAddress(host, port), keys, !hostConfig.isIdentitiesOnly());
    }

    protected List<KeyPair> loadClientIdentities(Collection<String> locations, LinkOption... options) throws IOException {
        if (GenericUtils.isEmpty(locations)) {
            return Collections.emptyList();
        }

        List<KeyPair> ids = new ArrayList<>(locations.size());
        boolean ignoreNonExisting = this.getBooleanProperty(IGNORE_INVALID_IDENTITIES, DEFAULT_IGNORE_INVALID_IDENTITIES);
        ClientIdentityLoader loader = Objects.requireNonNull(getClientIdentityLoader(), "No ClientIdentityLoader");
        FilePasswordProvider provider = Objects.requireNonNull(getFilePasswordProvider(), "No FilePasswordProvider");
        boolean debugEnabled = log.isDebugEnabled();
        for (String l : locations) {
            if (!loader.isValidLocation(l)) {
                if (ignoreNonExisting) {
                    if (debugEnabled) {
                        log.debug("loadClientIdentities - skip non-existing identity location: {}", l);
                    }
                    continue;
                }

                throw new FileNotFoundException("Invalid identity location: " + l);
            }

            try {
                KeyPair kp = loader.loadClientIdentity(l, provider);
                if (kp == null) {
                    throw new IOException("No identity loaded from " + l);
                }

                if (debugEnabled) {
                    log.debug("loadClientIdentities({}) type={}, fingerprint={}",
                              l, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
                }

                ids.add(kp);
            } catch (GeneralSecurityException e) {
                throw new StreamCorruptedException("Failed (" + e.getClass().getSimpleName() + ") to load identity from " + l + ": " + e.getMessage());
            }
        }

        return ids;
    }

    protected ConnectFuture doConnect(
            String username, SocketAddress address, Collection<? extends KeyPair> identities,  boolean useDefaultIdentities)
                    throws IOException {
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }

        ConnectFuture connectFuture = new DefaultConnectFuture(username + "@" + address, null);
        SshFutureListener<IoConnectFuture> listener = createConnectCompletionListener(connectFuture, username, address, identities, useDefaultIdentities);
        connector.connect(address).addListener(listener);
        return connectFuture;
    }

    protected SshFutureListener<IoConnectFuture> createConnectCompletionListener(
            ConnectFuture connectFuture, String username, SocketAddress address,
            Collection<? extends KeyPair> identities, boolean useDefaultIdentities) {
        return new SshFutureListener<IoConnectFuture>() {
            @Override
            @SuppressWarnings("synthetic-access")
            public void operationComplete(IoConnectFuture future) {
                if (future.isCanceled()) {
                    connectFuture.cancel();
                    return;
                }

                Throwable t = future.getException();
                if (t != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("operationComplete({}@{}) failed ({}): {}",
                                  username, address, t.getClass().getSimpleName(), t.getMessage());
                    }
                    connectFuture.setException(t);
                } else {
                    IoSession ioSession = future.getSession();
                    try {
                        onConnectOperationComplete(ioSession, connectFuture, username, address, identities, useDefaultIdentities);
                    } catch (RuntimeException e) {
                        log.warn("operationComplete({}@{}) failed ({}) to signal completion of session={}: {}",
                                username, address, e.getClass().getSimpleName(), ioSession, e.getMessage());
                        if (log.isDebugEnabled()) {
                            log.debug("operationComplete(" + username + "@" + address + ") session=" + ioSession + " completion signal failure details", e);
                        }
                        connectFuture.setException(e);

                        ioSession.close(true);
                    }
                }
            }

            @Override
            public String toString() {
                return "ConnectCompletionListener[" + username + "@" + address + "]";
            }
        };
    }

    protected void onConnectOperationComplete(IoSession ioSession, ConnectFuture connectFuture,
            String username, SocketAddress address, Collection<? extends KeyPair> identities, boolean useDefaultIdentities) {
        AbstractClientSession session = (AbstractClientSession) AbstractSession.getSession(ioSession);
        session.setUsername(username);
        session.setConnectAddress(address);

        if (useDefaultIdentities) {
            setupDefaultSessionIdentities(session);
        }

        int numIds = GenericUtils.size(identities);
        if (numIds > 0) {
            if (log.isDebugEnabled()) {
                log.debug("onConnectOperationComplete({}) adding {} identities", session, numIds);
            }

            boolean traceEnabled = log.isTraceEnabled();
            for (KeyPair kp : identities) {
                if (traceEnabled) {
                    log.trace("onConnectOperationComplete({}) add identity type={}, fingerprint={}",
                              session, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
                }
                session.addPublicKeyIdentity(kp);
            }
        }

        connectFuture.setSession(session);
    }

    protected void setupDefaultSessionIdentities(ClientSession session) {
        // check if session listener intervened
        KeyPairProvider kpSession = session.getKeyPairProvider();
        KeyPairProvider kpClient = getKeyPairProvider();
        boolean debugEnabled = log.isDebugEnabled();
        if (kpSession == null) {
            session.setKeyPairProvider(kpClient);
        } else {
            if (kpSession != kpClient) {
                if (debugEnabled) {
                    log.debug("setupDefaultSessionIdentities({}) key-pair provider override", session);
                }
            }
        }

        PasswordIdentityProvider passSession = session.getPasswordIdentityProvider();
        PasswordIdentityProvider passClient = getPasswordIdentityProvider();
        if (passSession == null) {
            session.setPasswordIdentityProvider(passClient);
        } else {
            if (passSession != passClient) {
                if (debugEnabled) {
                    log.debug("setupDefaultSessionIdentities({}) password provider override", session);
                }
            }
        }

        AuthenticationIdentitiesProvider idsClient = getRegisteredIdentities();
        boolean traceEnabled = log.isTraceEnabled();
        for (Iterator<?> iter = GenericUtils.iteratorOf((idsClient == null) ? null : idsClient.loadIdentities()); iter.hasNext();) {
            Object id = iter.next();
            if (id instanceof String) {
                if (traceEnabled) {
                    log.trace("setupDefaultSessionIdentities({}) add password fingerprint={}",
                              session, KeyUtils.getFingerPrint(id.toString()));
                }
                session.addPasswordIdentity((String) id);
            } else if (id instanceof KeyPair) {
                KeyPair kp = (KeyPair) id;
                if (traceEnabled) {
                    log.trace("setupDefaultSessionIdentities({}) add identity type={}, fingerprint={}",
                              session, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
                }
                session.addPublicKeyIdentity(kp);
            } else {
                if (debugEnabled) {
                    log.debug("setupDefaultSessionIdentities({}) ignored identity={}", session, id);
                }
            }
        }
    }

    protected IoConnector createConnector() {
        return getIoServiceFactory().createConnector(getSessionFactory());
    }

    protected SessionFactory createSessionFactory() {
        return new SessionFactory(this);
    }

    @Override
    public String toString() {
        return "SshClient[" + Integer.toHexString(hashCode()) + "]";
    }

    /**
     * Setup a default client, starts it and then wraps it as a {@link SimpleClient}
     *
     * @return The {@link SimpleClient} wrapper. <B>Note:</B> when the wrapper
     * is closed the client is also stopped
     * @see #setUpDefaultClient()
     * @see #wrapAsSimpleClient(SshClient)
     */
    public static SimpleClient setUpDefaultSimpleClient() {
        SshClient client = setUpDefaultClient();
        client.start();
        return wrapAsSimpleClient(client);
    }

    /**
     * Wraps an {@link SshClient} instance as a {@link SimpleClient}
     *
     * @param client The client instance - never {@code null}. <B>Note:</B>
     * client must be started <U>before</U> the simple client wrapper is used.
     * @return The {@link SimpleClient} wrapper. <B>Note:</B> when the
     * wrapper is closed the client is also stopped
     */
    public static SimpleClient wrapAsSimpleClient(final SshClient client) {
        Objects.requireNonNull(client, "No client instance");
        // wrap the client so that close() is also stop()
        final java.nio.channels.Channel channel = new java.nio.channels.Channel() {
            @Override
            public boolean isOpen() {
                return client.isOpen();
            }

            @Override
            public void close() throws IOException {
                Exception err = null;
                try {
                    client.close();
                } catch (Exception e) {
                    err = GenericUtils.accumulateException(err, e);
                }

                try {
                    client.stop();
                } catch (Exception e) {
                    err = GenericUtils.accumulateException(err, e);
                }

                if (err != null) {
                    if (err instanceof IOException) {
                        throw (IOException) err;
                    } else {
                        throw new IOException(err);
                    }
                }
            }
        };

        return AbstractSimpleClientSessionCreator.wrap(client, channel);
    }

    /**
     * Setup a default client.  The client does not require any additional setup.
     *
     * @return a newly create SSH client
     */
    public static SshClient setUpDefaultClient() {
        return ClientBuilder.builder().build();
    }
}
