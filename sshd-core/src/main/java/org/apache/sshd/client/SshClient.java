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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.channels.UnsupportedAddressTypeException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.config.keys.ClientIdentity;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.DefaultConnectFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.client.proxy.ProxyDataFactory;
import org.apache.sshd.client.session.AbstractClientSession;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientUserAuthServiceFactory;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.client.simple.AbstractSimpleClientSessionCreator;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.future.Cancellable;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.AbstractResourceKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MultiKeyIdentityProvider;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.functors.UnaryEquator;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * <P>
 * Entry point for the client side of the SSH protocol.
 * </P>
 *
 * <P>
 * The default configured client can be created using the {@link #setUpDefaultClient()}. The next step is to configure
 * and then start the client using the {@link #start()} method.
 * </P>
 *
 * <P>
 * Sessions can then be created using on of the {@link #connect(String, String, int)} or
 * {@link #connect(String, java.net.SocketAddress)} methods.
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
 * <code>
 * try (SshClient client = SshClient.setUpDefaultClient()) {
 *      ...further configuration of the client...
 *      client.start();
 *
 *      try (ClientSession session = client.connect(login, host, port)
 *                  .verify(...timeout...)
 *                  .getSession()) {
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
 * </code>
 * </pre>
 *
 * <B>Note</B>: the idea is to have <U>one</U> {@code SshClient} instance for the entire application and re-use it
 * repeatedly in order to create as many sessions as necessary - possibly with different hosts, ports, users, passwords,
 * etc. - including <U>concurrently</U>. In other words, except for exceptional cases, it is recommended to initialize
 * one instance of {@code SshClient} for the application and then use throughout - including for multi-threading. As
 * long as the {@code SshClient} is not re-configured it should be multi-thread safe regardless of the target session
 * being created.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshClient extends AbstractFactoryManager implements ClientFactoryManager {
    public static final Factory<SshClient> DEFAULT_SSH_CLIENT_FACTORY = SshClient::new;

    /**
     * Default user authentication preferences if not set
     *
     * @see <A HREF="http://linux.die.net/man/5/ssh_config">ssh_config(5) - PreferredAuthentications</A>
     */
    public static final List<UserAuthFactory> DEFAULT_USER_AUTH_FACTORIES = Collections.unmodifiableList(
            Arrays.asList(
                    UserAuthPublicKeyFactory.INSTANCE,
                    UserAuthKeyboardInteractiveFactory.INSTANCE,
                    UserAuthPasswordFactory.INSTANCE));
    public static final List<ServiceFactory> DEFAULT_SERVICE_FACTORIES = Collections.unmodifiableList(
            Arrays.asList(
                    ClientUserAuthServiceFactory.INSTANCE,
                    ClientConnectionServiceFactory.INSTANCE));

    protected IoConnector connector;
    protected SessionFactory sessionFactory;
    protected List<UserAuthFactory> userAuthFactories;

    private ProxyDataFactory proxyDataFactory;
    private ServerKeyVerifier serverKeyVerifier;
    private HostConfigEntryResolver hostConfigEntryResolver;
    private ClientIdentityLoader clientIdentityLoader;
    private KeyIdentityProvider keyIdentityProvider;
    private PublicKeyAuthenticationReporter publicKeyAuthenticationReporter;
    private FilePasswordProvider filePasswordProvider;
    private PasswordIdentityProvider passwordIdentityProvider;
    private PasswordAuthenticationReporter passwordAuthenticationReporter;
    private HostBasedAuthenticationReporter hostBasedAuthenticationReporter;
    private UserInteraction userInteraction;

    private final List<Object> identities = new CopyOnWriteArrayList<>();
    private final AuthenticationIdentitiesProvider identitiesProvider;
    private final AtomicBoolean started = new AtomicBoolean(false);

    public SshClient() {
        identitiesProvider = AuthenticationIdentitiesProvider.wrapIdentities(identities);
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public ProxyDataFactory getProxyDataFactory() {
        return proxyDataFactory;
    }

    public void setProxyDataFactory(ProxyDataFactory proxyDataFactory) {
        this.proxyDataFactory = proxyDataFactory;
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
    public PasswordAuthenticationReporter getPasswordAuthenticationReporter() {
        return passwordAuthenticationReporter;
    }

    @Override
    public void setPasswordAuthenticationReporter(PasswordAuthenticationReporter reporter) {
        this.passwordAuthenticationReporter = reporter;
    }

    @Override
    public HostBasedAuthenticationReporter getHostBasedAuthenticationReporter() {
        return hostBasedAuthenticationReporter;
    }

    @Override
    public void setHostBasedAuthenticationReporter(HostBasedAuthenticationReporter reporter) {
        this.hostBasedAuthenticationReporter = reporter;
    }

    @Override
    public List<UserAuthFactory> getUserAuthFactories() {
        return userAuthFactories;
    }

    @Override
    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
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
            log.debug("addPublicKeyIdentity({}) {}",
                    this, KeyUtils.getFingerPrint(kp.getPublic()));
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
    public KeyIdentityProvider getKeyIdentityProvider() {
        return keyIdentityProvider;
    }

    @Override
    public void setKeyIdentityProvider(KeyIdentityProvider keyIdentityProvider) {
        this.keyIdentityProvider = keyIdentityProvider;
    }

    @Override
    public PublicKeyAuthenticationReporter getPublicKeyAuthenticationReporter() {
        return publicKeyAuthenticationReporter;
    }

    @Override
    public void setPublicKeyAuthenticationReporter(PublicKeyAuthenticationReporter reporter) {
        this.publicKeyAuthenticationReporter = reporter;
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
        KeyIdentityProvider defaultIdentities = getKeyIdentityProvider();
        if (defaultIdentities == null) {
            KeyIdentityProvider idsWatcher = new DefaultClientIdentitiesWatcher(
                    this::getClientIdentityLoader, this::getFilePasswordProvider);
            setKeyIdentityProvider(idsWatcher);
        }

        // Register the additional agent forwarding channel(s) if needed
        SshAgentFactory agentFactory = getAgentFactory();
        if (agentFactory != null) {
            List<ChannelFactory> forwarders = agentFactory.getChannelForwardingFactories(this);
            if (!GenericUtils.isEmpty(forwarders)) {
                List<? extends ChannelFactory> factories = getChannelFactories();
                if (GenericUtils.isEmpty(factories)) {
                    factories = forwarders;
                } else {
                    // create a copy in case un-modifiable original
                    List<ChannelFactory> factories2 = new ArrayList<>(factories.size() + forwarders.size());
                    factories2.addAll(factories);
                    factories2.addAll(forwarders);
                    factories = factories2;
                }
                setChannelFactories(factories);
            }
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
     * Starts the SSH client and can start creating sessions using it. Ignored if already {@link #isStarted() started}.
     */
    public void start() {
        if (isClosed()) {
            throw new IllegalStateException("Can not start the client again");
        }
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
            Duration maxWait = CoreModuleProperties.STOP_WAIT_TIME.getRequired(this);
            boolean successful = close(true).await(maxWait);
            if (!successful) {
                throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
            }
        } catch (IOException e) {
            warn("{} while stopping client: {}", e.getClass().getSimpleName(), e.getMessage(), e);
        } finally {
            // clear the attributes since we close stop the client
            clearAttributes();
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
    public ConnectFuture connect(String uriStr) throws IOException {
        Objects.requireNonNull(uriStr, "No uri address");
        URI uri = URI.create(uriStr.contains("//") ? uriStr : "ssh://" + uriStr);
        if (GenericUtils.isNotEmpty(uri.getScheme()) && !"ssh".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Unsupported scheme for uri: " + uri);
        }
        String host = uri.getHost();
        int port = uri.getPort();
        String userInfo = uri.getUserInfo();
        return connect(userInfo, host, port);
    }

    @Override
    public ConnectFuture connect(
            String username, SocketAddress targetAddress,
            AttributeRepository context, SocketAddress localAddress)
            throws IOException {
        Objects.requireNonNull(targetAddress, "No target address");
        if (!(targetAddress instanceof InetSocketAddress)) {
            throw new UnsupportedAddressTypeException();
        }
        InetSocketAddress inetAddress = (InetSocketAddress) targetAddress;
        String host = ValidateUtils.checkNotNullAndNotEmpty(inetAddress.getHostString(), "No host");
        int port = inetAddress.getPort();
        ValidateUtils.checkTrue(port > 0, "Invalid port: %d", port);
        return connect(username, host, port, context, localAddress);
    }

    @Override
    public ConnectFuture connect(
            String username, String host, int port,
            AttributeRepository context, SocketAddress localAddress)
            throws IOException {
        HostConfigEntry entry = resolveHost(username, host, port, context, localAddress);
        return connect(entry, context, localAddress);
    }

    @Override
    public ConnectFuture connect(
            HostConfigEntry hostConfig, AttributeRepository context, SocketAddress localAddress)
            throws IOException {
        List<HostConfigEntry> jumps = parseProxyJumps(hostConfig, context);
        return doConnect(hostConfig, jumps, context, localAddress);
    }

    protected ConnectFuture doConnect(
            HostConfigEntry hostConfig, List<HostConfigEntry> jumps,
            AttributeRepository context, SocketAddress localAddress)
            throws IOException {
        Objects.requireNonNull(hostConfig, "No host configuration");
        ValidateUtils.checkNotNullAndNotEmpty(hostConfig.getHostName(), "No target host");
        int port = hostConfig.getPort();
        ValidateUtils.checkTrue(port > 0, "Invalid port: %d", port);
        String username = hostConfig.getUsername();
        InetSocketAddress targetAddress = new InetSocketAddress(hostConfig.getHostName(), hostConfig.getPort());
        if (GenericUtils.isNotEmpty(jumps)) {
            ConnectFuture connectFuture = new DefaultConnectFuture(username + "@" + targetAddress, null);
            HostConfigEntry jump = jumps.remove(0);
            ConnectFuture f1 = doConnect(jump, jumps, context, null);
            AtomicReference<Cancellable> toCancel = new AtomicReference<>(f1);
            connectFuture.addListener(c -> {
                if (!c.isCanceled()) {
                    return;
                }
                Cancellable inner = toCancel.get();
                if (inner == null) {
                    return;
                }
                CancelFuture cancellation = inner.cancel();
                if (cancellation == null) {
                    return;
                }
                cancellation.addListener(cf -> {
                    if (cf.isDone()) {
                        c.getCancellation().setCanceled();
                    }
                });
            });
            f1.addListener(f2 -> {
                if (f2.isConnected()) {
                    ClientSession proxySession = f2.getClientSession();
                    try {
                        if (connectFuture.isCanceled()) {
                            proxySession.close(true);
                        }
                        AuthFuture auth = proxySession.auth();
                        toCancel.set(auth);
                        auth.addListener(f3 -> {
                            if (f3.isSuccess()) {
                                try {
                                    SshdSocketAddress address
                                            = new SshdSocketAddress(hostConfig.getHostName(), hostConfig.getPort());
                                    ExplicitPortForwardingTracker tracker = proxySession
                                            .createLocalPortForwardingTracker(SshdSocketAddress.LOCALHOST_ADDRESS, address);
                                    SshdSocketAddress bound = tracker.getBoundAddress();
                                    ConnectFuture f4 = doConnect(hostConfig.getUsername(), bound.toInetSocketAddress(), null,
                                            context, localAddress, hostConfig);
                                    toCancel.set(f4);
                                    if (connectFuture.isCanceled()) {
                                        f4.cancel();
                                    }
                                    f4.addListener(f5 -> {
                                        if (f5.isConnected()) {
                                            ClientSession clientSession = f5.getClientSession();
                                            clientSession.setAttribute(TARGET_SERVER, address);
                                            connectFuture.setSession(clientSession);
                                            proxySession.addCloseFutureListener(f6 -> clientSession.close(true));
                                            clientSession.addCloseFutureListener(f6 -> proxySession.close(true));
                                        } else {
                                            proxySession.close(true);
                                            connectFuture.setException(f5.getException());
                                        }
                                    });
                                } catch (IOException e) {
                                    proxySession.close(true);
                                    connectFuture.setException(e);
                                }
                            } else {
                                proxySession.close(true);
                                connectFuture.setException(f3.getException());
                            }
                        });
                    } catch (IOException e) {
                        proxySession.close(true);
                        connectFuture.setException(e);
                    }
                } else {
                    connectFuture.setException(f2.getException());
                }
            });
            return connectFuture;
        } else {
            // This is a direct connection to an SSH server. Check whether we have to use a proxy (not an SSH
            // proxyJump).
            ProxyDataFactory factory = getProxyDataFactory();
            ProxyData proxy = factory == null ? null : factory.get(targetAddress);
            return doConnect(hostConfig.getUsername(), targetAddress, proxy,
                    context, localAddress, hostConfig);
        }
    }

    protected ConnectFuture doConnect(
            String username, InetSocketAddress targetAddress, ProxyData proxy,
            AttributeRepository context, SocketAddress localAddress, HostConfigEntry hostConfig)
            throws IOException {
        if (connector == null) {
            throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
        }
        Map<AttributeRepository.AttributeKey<?>, Object> sessionAttributes = new HashMap<>();
        sessionAttributes.put(AbstractClientSession.HOST_CONFIG_ENTRY, hostConfig);
        InetSocketAddress connectAddress = targetAddress;
        if (proxy != null) {
            sessionAttributes.put(AbstractClientSession.PROXY_DATA, proxy);
            sessionAttributes.put(TARGET_SERVER, new SshdSocketAddress(targetAddress));
            connectAddress = proxy.getAddress();
            if (connectAddress.isUnresolved()) {
                connectAddress = new InetSocketAddress(connectAddress.getHostName(), connectAddress.getPort());
            }
        }
        AttributeRepository sessionContext = AttributeRepository.ofAttributesMap(sessionAttributes);
        if (context != null) {
            sessionContext = new ShadowingAttributeRepository(sessionContext, context);
        }
        ConnectFuture connectFuture = new DefaultConnectFuture(username + "@" + targetAddress, null);
        SshFutureListener<IoConnectFuture> listener = createConnectCompletionListener(connectFuture, username, targetAddress);
        IoConnectFuture connectingFuture = connector.connect(connectAddress, sessionContext, localAddress);
        connectFuture.addListener(c -> {
            if (c.isCanceled()) {
                connectingFuture.cancel();
            }
        });
        connectingFuture.addListener(listener);
        return connectFuture;
    }

    protected List<HostConfigEntry> parseProxyJumps(HostConfigEntry entry, AttributeRepository context)
            throws IOException {
        List<HostConfigEntry> hops;
        try {
            hops = parseProxyJumps(entry.getProxyJump(), context);
            if (GenericUtils.isEmpty(hops)) {
                return hops;
            }
            // If the last entry itself has proxy jumps, we need to append them. Guard against possible proxy jump
            // loops by imposing an upper limit on the total number of jumps.
            for (;;) {
                HostConfigEntry last = hops.get(hops.size() - 1);
                try {
                    List<HostConfigEntry> additionalHops = parseProxyJumps(last.getProxyJump(), context);
                    if (additionalHops.isEmpty()) {
                        break;
                    } else {
                        hops.addAll(additionalHops);
                        if (hops.size() > CoreModuleProperties.MAX_PROXY_JUMPS.getRequired(this)) {
                            throw new IllegalArgumentException("Too many proxy jumps for host " + entry.getHost());
                        }
                    }
                } catch (IOException | RuntimeException e) {
                    throw new IllegalArgumentException("Problem parsing proxyJump from host config " + last.getHost(), e);
                }
            }
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("Problem parsing proxyJump from host config " + entry.getHost(), e);
        }
        return hops;
    }

    protected List<HostConfigEntry> parseProxyJumps(String proxyJump, AttributeRepository context) throws IOException {
        List<HostConfigEntry> jumps = new ArrayList<>();
        if (GenericUtils.isEmpty(proxyJump)) {
            return jumps;
        }
        String[] hops = GenericUtils.split(proxyJump, ',');
        for (String hop : hops) {
            String h = hop.trim();
            if (h.isEmpty()) {
                throw new IllegalArgumentException("Empty proxy jump in list: " + proxyJump);
            }
            URI uri = URI.create(h.contains("://") ? h : "ssh://" + h);
            if (GenericUtils.isNotEmpty(uri.getScheme()) && !"ssh".equals(uri.getScheme())) {
                throw new IllegalArgumentException("Unsupported scheme for proxy jump: " + hop);
            }
            String host = uri.getHost();
            int port = uri.getPort();
            String userInfo = uri.getUserInfo();
            HostConfigEntry entry = resolveHost(userInfo, host, port, context, null);
            jumps.add(entry);
        }
        return jumps;
    }

    protected HostConfigEntry resolveHost(
            String username, String host, int port, AttributeRepository context, SocketAddress localAddress)
            throws IOException {
        HostConfigEntryResolver resolver = getHostConfigEntryResolver();
        HostConfigEntry entry = resolver.resolveEffectiveHost(host, port, localAddress, username, null, context);
        if (entry == null) {
            // generate a synthetic entry
            if (port <= 0) {
                port = SshConstants.DEFAULT_PORT;
            }
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) no overrides", username, host, port);
            }

            // IPv6 addresses have a format which means they need special treatment, separate from pattern validation
            if (SshdSocketAddress.isIPv6Address(host)) {
                // Not using a pattern as the host name passed in was a valid IPv6 address
                entry = new HostConfigEntry("", host, port, username, null);
            } else {
                entry = new HostConfigEntry(host, host, port, username, null);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) effective: {}", username, host, port, entry);
            }
        }
        return entry;
    }

    protected SshFutureListener<IoConnectFuture> createConnectCompletionListener(
            ConnectFuture connectFuture, String username, SocketAddress address) {
        return new SshFutureListener<IoConnectFuture>() {
            @Override
            @SuppressWarnings("synthetic-access")
            public void operationComplete(IoConnectFuture future) {
                if (future.isCanceled()) {
                    CancelFuture cancellation = connectFuture.cancel();
                    if (cancellation != null) {
                        future.getCancellation().addListener(f -> cancellation.setCanceled(f.getBackTrace()));
                    }
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
                        onConnectOperationComplete(ioSession, connectFuture, username, address);
                    } catch (IOException | GeneralSecurityException | RuntimeException e) {
                        warn("operationComplete({}@{}) failed ({}) to signal completion of session={}: {}",
                                username, address, e.getClass().getSimpleName(), ioSession, e.getMessage(), e);
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

    protected void onConnectOperationComplete(
            IoSession ioSession, ConnectFuture connectFuture, String username, SocketAddress address)
            throws IOException, GeneralSecurityException {
        AbstractClientSession session = (AbstractClientSession) AbstractSession.getSession(ioSession);
        session.setUsername(username);
        session.setConnectAddress(address);

        configure(session);

        connectFuture.setSession(session);
        if (session != connectFuture.getSession()) {
            // Must have been canceled before
            try {
                session.close(true);
            } finally {
                CancelFuture cancellation = connectFuture.cancel();
                if (cancellation != null) {
                    cancellation.setCanceled();
                }
            }
        }
    }

    protected void configure(ClientSession session) throws IOException, GeneralSecurityException {
        setSessionKeyIdentities(session);
    }

    protected void setSessionKeyIdentities(ClientSession session)
            throws IOException, GeneralSecurityException {
        HostConfigEntry hostConfig = session.getHostConfigEntry();
        KeyIdentityProvider fromHostConfig = getKeyIdentities(hostConfig);
        if (!hostConfig.isIdentitiesOnly()) {
            setupDefaultSessionIdentities(session, fromHostConfig);
        } else if (fromHostConfig == null) {
            session.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        } else {
            session.setKeyIdentityProvider(ensureFilePasswordProvider(fromHostConfig));
        }
    }

    protected KeyIdentityProvider getKeyIdentities(HostConfigEntry hostConfig) {
        Collection<String> hostIds = hostConfig.getIdentities();
        Collection<PathResource> idFiles = GenericUtils.stream(hostIds)
                .map(Paths::get)
                .map(PathResource::new)
                .collect(Collectors.toCollection(() -> new ArrayList<>(hostIds.size())));
        return preloadClientIdentities(idFiles);
    }

    protected KeyIdentityProvider preloadClientIdentities(Collection<? extends NamedResource> locations) {
        return GenericUtils.isEmpty(locations)
                ? KeyIdentityProvider.EMPTY_KEYS_PROVIDER
                : ClientIdentityLoader.asKeyIdentityProvider(
                        Objects.requireNonNull(getClientIdentityLoader(), "No ClientIdentityLoader"), locations,
                        getFilePasswordProvider(), CoreModuleProperties.IGNORE_INVALID_IDENTITIES.getRequired(this));
    }

    /**
     * Sets this client's {@link FilePasswordProvider} on the {@link KeyIdentityProvider} if it is an
     * {@link AbstractResourceKeyPairProvider} or implements {@link FilePasswordProviderManager} and doesn't have one
     * yet. If the given {@code identities} is a {@link MultiKeyIdentityProvider}, the wrapped identity providers are
     * set up.
     *
     * @param  identities {@link KeyIdentityProvider} to set up
     * @return            a {@link KeyIdentityProvider} configured with a {@link FilePasswordProvider}
     * @see               #getFilePasswordProvider()
     */
    protected KeyIdentityProvider ensureFilePasswordProvider(KeyIdentityProvider identities) {
        if (identities instanceof AbstractResourceKeyPairProvider<?>) {
            AbstractResourceKeyPairProvider<?> keyProvider = (AbstractResourceKeyPairProvider<?>) identities;
            if (keyProvider.getPasswordFinder() == null) {
                FilePasswordProvider passwordProvider = getFilePasswordProvider();
                if (passwordProvider != null) {
                    keyProvider.setPasswordFinder(passwordProvider);
                }
            }
        } else if (identities instanceof FilePasswordProviderManager) {
            FilePasswordProviderManager keyProvider = (FilePasswordProviderManager) identities;
            if (keyProvider.getFilePasswordProvider() == null) {
                FilePasswordProvider passwordProvider = getFilePasswordProvider();
                if (passwordProvider != null) {
                    keyProvider.setFilePasswordProvider(passwordProvider);
                }
            }
        } else if (identities instanceof MultiKeyIdentityProvider) {
            MultiKeyIdentityProvider multiProvider = (MultiKeyIdentityProvider) identities;
            multiProvider.getProviders().forEach(this::ensureFilePasswordProvider);
        }
        return identities;
    }

    protected void setupDefaultSessionIdentities(
            ClientSession session, KeyIdentityProvider extraIdentities)
            throws IOException, GeneralSecurityException {
        boolean debugEnabled = log.isDebugEnabled();
        // check if session listener intervened
        KeyIdentityProvider kpSession = session.getKeyIdentityProvider();
        KeyIdentityProvider kpClient = getKeyIdentityProvider();
        if (UnaryEquator.isSameReference(kpSession, kpClient)) {
            if (debugEnabled) {
                log.debug("setupDefaultSessionIdentities({}) key identity provider override in session listener", session);
            }
        }

        // Prefer the extra identities to come first since they were probably indicated by the host-config entry
        KeyIdentityProvider kpEffective = KeyIdentityProvider.resolveKeyIdentityProvider(extraIdentities, kpSession);
        kpEffective = ensureFilePasswordProvider(kpEffective);
        if (!UnaryEquator.isSameReference(kpSession, kpEffective)) {
            if (debugEnabled) {
                log.debug("setupDefaultSessionIdentities({}) key identity provider enhanced", session);
            }
            session.setKeyIdentityProvider(kpEffective);
        }

        PasswordIdentityProvider passSession = session.getPasswordIdentityProvider();
        PasswordIdentityProvider passClient = getPasswordIdentityProvider();
        if (!UnaryEquator.isSameReference(passSession, passClient)) {
            if (debugEnabled) {
                log.debug("setupDefaultSessionIdentities({}) password provider override", session);
            }
        }

        AuthenticationIdentitiesProvider idsClient = getRegisteredIdentities();
        boolean traceEnabled = log.isTraceEnabled();
        for (Iterator<?> iter = GenericUtils.iteratorOf((idsClient == null) ? null : idsClient.loadIdentities(session));
             iter.hasNext();) {
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
        return getClass().getSimpleName() + "[" + Integer.toHexString(hashCode()) + "]";
    }

    /**
     * Setup a default client, starts it and then wraps it as a {@link SimpleClient}
     *
     * @return The {@link SimpleClient} wrapper. <B>Note:</B> when the wrapper is closed the client is also stopped
     * @see    #setUpDefaultClient()
     * @see    #wrapAsSimpleClient(SshClient)
     */
    public static SimpleClient setUpDefaultSimpleClient() {
        SshClient client = setUpDefaultClient();
        client.start();
        return wrapAsSimpleClient(client);
    }

    /**
     * Wraps an {@link SshClient} instance as a {@link SimpleClient}
     *
     * @param  client The client instance - never {@code null}. <B>Note:</B> client must be started <U>before</U> the
     *                simple client wrapper is used.
     * @return        The {@link SimpleClient} wrapper. <B>Note:</B> when the wrapper is closed the client is also
     *                stopped
     */
    public static SimpleClient wrapAsSimpleClient(SshClient client) {
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
                    err = ExceptionUtils.accumulateException(err, e);
                }

                try {
                    client.stop();
                } catch (Exception e) {
                    err = ExceptionUtils.accumulateException(err, e);
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
     * Setup a default client. The client does not require any additional setup.
     *
     * @return a newly create {@link SshClient} with default configurations
     */
    public static SshClient setUpDefaultClient() {
        ClientBuilder builder = ClientBuilder.builder();
        return builder.build();
    }

    /**
     * @param  <C>                      The generic client class
     * @param  client                   The {@link SshClient} to updated
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          The updated <tt>client</tt> instance - provided a non-{@code null}
     *                                  {@link KeyPairProvider} was generated
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             #setKeyPairProvider(SshClient, Path, boolean, boolean, FilePasswordProvider,
     *                                  LinkOption...)
     */
    public static <C extends SshClient> C setKeyPairProvider(
            C client, boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        return setKeyPairProvider(
                client, PublicKeyEntry.getDefaultKeysFolderPath(), strict, supportedOnly, provider, options);
    }

    /**
     * @param  <C>                      The generic client class
     * @param  client                   The {@link SshClient} to updated
     * @param  dir                      The folder to scan for the built-in identities
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          The updated <tt>client</tt> instance - provided a non-{@code null}
     *                                  {@link KeyIdentityProvider} was generated
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             ClientIdentity#loadDefaultKeyPairProvider(Path, boolean, boolean,
     *                                  FilePasswordProvider, LinkOption...)
     */
    public static <C extends SshClient> C setKeyPairProvider(
            C client, Path dir, boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        KeyIdentityProvider kpp = ClientIdentity.loadDefaultKeyPairProvider(dir, strict, supportedOnly, provider, options);
        if (kpp != null) {
            client.setKeyIdentityProvider(kpp);
        }

        return client;
    }

    protected static class ShadowingAttributeRepository implements AttributeRepository {

        private final AttributeRepository shadow;

        private final AttributeRepository parent;

        public ShadowingAttributeRepository(AttributeRepository shadow, AttributeRepository parent) {
            this.shadow = Objects.requireNonNull(shadow);
            this.parent = Objects.requireNonNull(parent);
        }

        @Override
        public int getAttributesCount() {
            return attributeKeys().size();
        }

        @Override
        public <T> T getAttribute(AttributeKey<T> key) {
            if (shadow.attributeKeys().contains(Objects.requireNonNull(key))) {
                return shadow.getAttribute(key);
            }
            return parent.getAttribute(key);
        }

        @Override
        public Collection<AttributeKey<?>> attributeKeys() {
            Set<AttributeKey<?>> keys = new HashSet<>(shadow.attributeKeys());
            keys.addAll(parent.attributeKeys());
            return keys;
        }

        @Override
        public <T> T resolveAttribute(AttributeKey<T> key) {
            if (shadow.attributeKeys().contains(Objects.requireNonNull(key))) {
                return shadow.getAttribute(key);
            }
            return parent.resolveAttribute(key);
        }
    }
}
