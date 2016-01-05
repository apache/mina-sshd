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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StreamCorruptedException;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.DefaultConnectFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.client.session.ClientUserAuthServiceFactory;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.client.simple.AbstractSimpleClientSessionCreator;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.AbstractFileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseOutputStream;

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
 * try(SshClient client = SshClient.setUpDefaultClient()) {
 *      client.start();
 *
 *      try(ClientSession session = client.connect(login, host, port).await().getSession()) {
 *          session.addPasswordIdentity(password);
 *          session.auth().verify(...timeout...);
 *
 *          try(ClientChannel channel = session.createChannel("shell")) {
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

    public static final Factory<SshClient> DEFAULT_SSH_CLIENT_FACTORY = new Factory<SshClient>() {
        @Override
        public SshClient create() {
            return new SshClient();
        }
    };

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

    private ServerKeyVerifier serverKeyVerifier;
    private HostConfigEntryResolver hostConfigEntryResolver;
    private ClientIdentityLoader clientIdentityLoader;
    private FilePasswordProvider filePasswordProvider;
    private PasswordIdentityProvider passwordIdentityProvider;
    private final List<Object> identities = new CopyOnWriteArrayList<>();
    private final AuthenticationIdentitiesProvider identitiesProvider;

    public SshClient() {
        identitiesProvider = AuthenticationIdentitiesProvider.Utils.wrap(identities);
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public ServerKeyVerifier getServerKeyVerifier() {
        return serverKeyVerifier;
    }

    @Override
    public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = ValidateUtils.checkNotNull(serverKeyVerifier, "No server key verifier");
    }

    @Override
    public HostConfigEntryResolver getHostConfigEntryResolver() {
        return hostConfigEntryResolver;
    }

    @Override
    public void setHostConfigEntryResolver(HostConfigEntryResolver resolver) {
        this.hostConfigEntryResolver = ValidateUtils.checkNotNull(resolver, "No host configuration entry resolver");
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return filePasswordProvider;
    }

    @Override
    public void setFilePasswordProvider(FilePasswordProvider provider) {
        this.filePasswordProvider = ValidateUtils.checkNotNull(provider, "No file password provider");
    }

    @Override
    public ClientIdentityLoader getClientIdentityLoader() {
        return clientIdentityLoader;
    }

    @Override
    public void setClientIdentityLoader(ClientIdentityLoader loader) {
        this.clientIdentityLoader = ValidateUtils.checkNotNull(loader, "No client identity loader");
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
        identities.add(ValidateUtils.checkNotNullAndNotEmpty(password, "No password provided"));
        if (log.isDebugEnabled()) { // don't show the password in the log
            log.debug("addPasswordIdentity({}) {}", this, KeyUtils.getFingerPrint(password));
        }
    }

    @Override
    public String removePasswordIdentity(String password) {
        if (GenericUtils.isEmpty(password)) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.Utils.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.Utils.PASSWORD_IDENTITY_COMPARATOR, password);
        if (index >= 0) {
            return (String) identities.remove(index);
        } else {
            return null;
        }
    }

    @Override
    public void addPublicKeyIdentity(KeyPair kp) {
        ValidateUtils.checkNotNull(kp, "No key-pair to add");
        ValidateUtils.checkNotNull(kp.getPublic(), "No public key");
        ValidateUtils.checkNotNull(kp.getPrivate(), "No private key");

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

        int index = AuthenticationIdentitiesProvider.Utils.findIdentityIndex(
                identities, AuthenticationIdentitiesProvider.Utils.KEYPAIR_IDENTITY_COMPARATOR, kp);
        if (index >= 0) {
            return (KeyPair) identities.remove(index);
        } else {
            return null;
        }
    }

    @Override
    protected void checkConfig() {
        super.checkConfig();

        ValidateUtils.checkNotNull(getTcpipForwarderFactory(), "TcpipForwarderFactory not set");
        ValidateUtils.checkNotNull(getServerKeyVerifier(), "ServerKeyVerifier not set");
        ValidateUtils.checkNotNull(getHostConfigEntryResolver(), "HostConfigEntryResolver not set");
        ValidateUtils.checkNotNull(getClientIdentityLoader(), "ClientIdentityLoader not set");
        ValidateUtils.checkNotNull(getFilePasswordProvider(), "FilePasswordProvider not set");

        // if no client identities override use the default
        KeyPairProvider defaultIdentities = getKeyPairProvider();
        if (defaultIdentities == null) {
            setKeyPairProvider(new DefaultClientIdentitiesWatcher(
                    new Supplier<ClientIdentityLoader>() {
                        @Override
                        public ClientIdentityLoader get() {
                            return getClientIdentityLoader();
                        }
                    },
                    new Supplier<FilePasswordProvider>() {
                        @Override
                        public FilePasswordProvider get() {
                            return getFilePasswordProvider();
                        }
                    }));
        }

        // Register the additional agent forwarding channel if needed
        SshAgentFactory agentFactory = getAgentFactory();
        if (agentFactory != null) {
            List<NamedFactory<Channel>> factories = getChannelFactories();
            if (GenericUtils.isEmpty(factories)) {
                factories = new ArrayList<>();
            } else {
                factories = new ArrayList<>(factories);
            }
            factories.add(ValidateUtils.checkNotNull(agentFactory.getChannelForwardingFactory(), "No agent channel forwarding factory for %s", agentFactory));

            setChannelFactories(factories);
        }

        if (GenericUtils.isEmpty(getServiceFactories())) {
            setServiceFactories(DEFAULT_SERVICE_FACTORIES);
        }

        if (GenericUtils.isEmpty(getUserAuthFactories())) {
            setUserAuthFactories(DEFAULT_USER_AUTH_FACTORIES);
        }
    }

    public void start() {
        checkConfig();
        if (sessionFactory == null) {
            sessionFactory = createSessionFactory();
        }

        setupSessionTimeout(sessionFactory);

        connector = createConnector();
    }

    public void stop() {
        try {
            close(true).await();    // TODO use verify + configurable timeout
        } catch (IOException e) {
            log.debug("Exception caught while stopping client", e);
        }
    }

    public void open() throws IOException {
        start();
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .run(new Runnable() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public void run() {
                        removeSessionTimeout(sessionFactory);
                    }
                })
                .sequential(connector, ioServiceFactory)
                .run(new Runnable() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public void run() {
                        connector = null;
                        ioServiceFactory = null;
                        if (shutdownExecutor && (executor != null) && (!executor.isShutdown())) {
                            try {
                                executor.shutdownNow();
                            } finally {
                                executor = null;
                            }
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
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) no overrides", username, host, port);
            }

            // generate a synthetic entry
            entry = new HostConfigEntry(host, host, port, username);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("connect({}@{}:{}) effective: {}", username, host, port, entry);
            }
        }

        return connect(entry);
    }

    @Override
    public ConnectFuture connect(String username, SocketAddress address) throws IOException {
        ValidateUtils.checkNotNull(address, "No target address");
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

                return doConnect(username, address, Collections.<KeyPair>emptyList(), true);
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
            return doConnect(username, address, Collections.<KeyPair>emptyList(), true);
        }
    }

    @Override
    public ConnectFuture connect(HostConfigEntry hostConfig) throws IOException {
        ValidateUtils.checkNotNull(hostConfig, "No host configuration");
        String host = ValidateUtils.checkNotNullAndNotEmpty(hostConfig.getHostName(), "No target host");
        int port = hostConfig.getPort();
        ValidateUtils.checkTrue(port > 0, "Invalid port: %d", port);

        Collection<KeyPair> keys = loadClientIdentities(hostConfig.getIdentities(), IoUtils.EMPTY_LINK_OPTIONS);
        return doConnect(hostConfig.getUsername(), new InetSocketAddress(host, port), keys, !hostConfig.isIdentitiesOnly());
    }

    protected List<KeyPair> loadClientIdentities(Collection<String> locations, LinkOption ... options) throws IOException {
        if (GenericUtils.isEmpty(locations)) {
            return Collections.emptyList();
        }

        List<KeyPair> ids = new ArrayList<>(locations.size());
        boolean ignoreNonExisting = PropertyResolverUtils.getBooleanProperty(this, IGNORE_INVALID_IDENTITIES, DEFAULT_IGNORE_INVALID_IDENTITIES);
        ClientIdentityLoader loader = ValidateUtils.checkNotNull(getClientIdentityLoader(), "No ClientIdentityLoader");
        FilePasswordProvider provider = ValidateUtils.checkNotNull(getFilePasswordProvider(), "No FilePasswordProvider");
        for (String l : locations) {
            if (!loader.isValidLocation(l)) {
                if (ignoreNonExisting) {
                    log.debug("loadClientIdentities - skip non-existing identity location: {}", l);
                    continue;
                }

                throw new FileNotFoundException("Invalid identity location: " + l);
            }

            try {
                KeyPair kp = loader.loadClientIdentity(l, provider);
                if (kp == null) {
                    throw new IOException("No identity loaded from " + l);
                }

                if (log.isDebugEnabled()) {
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

        ConnectFuture connectFuture = new DefaultConnectFuture(null);
        SshFutureListener<IoConnectFuture> listener = createConnectCompletionListener(connectFuture, username, address, identities, useDefaultIdentities);
        connector.connect(address).addListener(listener);
        return connectFuture;
    }

    protected SshFutureListener<IoConnectFuture> createConnectCompletionListener(
            final ConnectFuture connectFuture, final String username, final SocketAddress address,
            final Collection<? extends KeyPair> identities, final boolean useDefaultIdentities) {
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
                    onConnectOperationComplete(future.getSession(), connectFuture, username, address, identities, useDefaultIdentities);
                }
            }
        };
    }

    protected void onConnectOperationComplete(IoSession ioSession, ConnectFuture connectFuture,
            String username, SocketAddress address, Collection<? extends KeyPair> identities, boolean useDefaultIdentities) {
        ClientSession session = (ClientSession) AbstractSession.getSession(ioSession);
        session.setUsername(username);

        if (useDefaultIdentities) {
            setupDefaultSessionIdentities(session);
        }

        int numIds = GenericUtils.size(identities);
        if (numIds > 0) {
            if (log.isDebugEnabled()) {
                log.debug("onConnectOperationComplete({}) adding {} identities", session, numIds);
            }
            for (KeyPair kp : identities) {
                if (log.isTraceEnabled()) {
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
        if (kpSession == null) {
            session.setKeyPairProvider(kpClient);
        } else {
            if (kpSession != kpClient) {
                if (log.isDebugEnabled()) {
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
                if (log.isDebugEnabled()) {
                    log.debug("setupDefaultSessionIdentities({}) password provider override", session);
                }
            }
        }

        AuthenticationIdentitiesProvider idsClient = getRegisteredIdentities();
        for (Iterator<?> iter = GenericUtils.iteratorOf((idsClient == null) ? null : idsClient.loadIdentities()); iter.hasNext();) {
            Object id = iter.next();
            if (id instanceof String) {
                if (log.isTraceEnabled()) {
                    log.trace("setupDefaultSessionIdentities({}) add password fingerprint={}",
                              session, KeyUtils.getFingerPrint(id.toString()));
                }
                session.addPasswordIdentity((String) id);
            } else if (id instanceof KeyPair) {
                KeyPair kp = (KeyPair) id;
                if (log.isTraceEnabled()) {
                    log.trace("setupDefaultSessionIdentities({}) add identity type={}, fingerprint={}",
                              session, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic()));
                }
                session.addPublicKeyIdentity(kp);
            } else {
                if (log.isDebugEnabled()) {
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
        ValidateUtils.checkNotNull(client, "No client instance");
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

    /*=================================
          Main class implementation
     *=================================*/

    public static boolean showError(PrintStream stderr, String message) {
        stderr.println(message);
        return true;
    }

    public static boolean isArgumentedOption(String portOption, String argName) {
        return portOption.equals(argName)
             || "-i".equals(argName)
             || "-o".equals(argName)
             || "-l".equals(argName)
             || "-w".equals(argName)
             || "-E".equals(argName);
    }

    // NOTE: ClientSession#getFactoryManager is the SshClient
    public static ClientSession setupClientSession(
            String portOption, final BufferedReader stdin, final PrintStream stdout, final PrintStream stderr, String... args)
            throws Exception {

        int port = -1;
        String host = null;
        String login = null;
        String password = null;
        boolean error = false;
        List<File> identities = new ArrayList<>();
        Map<String, String> options = new LinkedHashMap<>();
        int numArgs = GenericUtils.length(args);
        for (int i = 0; (!error) && (i < numArgs); i++) {
            String argName = args[i];
            String argVal = null;
            if (isArgumentedOption(portOption, argName)) {
                if ((i + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                argVal = args[++i];
            }

            if (portOption.equals(argName)) {
                if (port > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + port);
                    break;
                }

                port = Integer.parseInt(argVal);
                if (port <= 0) {
                    error = showError(stderr, "Bad option value for " + argName + ": " + port);
                    break;
                }
            } else if ("-w".equals(argName)) {
                if (GenericUtils.length(password) > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + password);
                    break;
                }
                password = argVal;
            } else if ("-i".equals(argName)) {
                identities.add(new File(argVal));
            } else if ("-o".equals(argName)) {
                String opt = argVal;
                int idx = opt.indexOf('=');
                if (idx <= 0) {
                    error = showError(stderr, "bad syntax for option: " + opt);
                    break;
                }
                options.put(opt.substring(0, idx), opt.substring(idx + 1));
            } else if ("-l".equals(argName)) {
                if (login != null) {
                    error = showError(stderr, argName + " option value re-specified: " + port);
                    break;
                }

                login = argVal;
            } else if (argName.charAt(0) != '-') {
                if (host != null) { // assume part of a command following it
                    break;
                }

                host = argName;
                int pos = host.indexOf('@');  // check if user@host
                if (pos > 0) {
                    if (login == null) {
                        login = host.substring(0, pos);
                        host = host.substring(pos + 1);
                    } else {
                        error = showError(stderr, "Login already specified using -l option (" + login + "): " + host);
                        break;
                    }
                }
            }
        }

        if ((!error) && GenericUtils.isEmpty(host)) {
            error = showError(stderr, "Hostname not specified");
        }

        if (login == null) {
            login = OsUtils.getCurrentUser();
        }

        if (port <= 0) {
            port = SshConfigFileReader.DEFAULT_PORT;
        }

        if (error) {
            return null;
        }

        SshClient client = SshClient.setUpDefaultClient();
        client.setFilePasswordProvider(new FilePasswordProvider() {
            @Override
            public String getPassword(String file) throws IOException {
                stdout.print("Enter password for private key file=" + file + ": ");
                return stdin.readLine();
            }
        });

        try {
            if (GenericUtils.size(identities) > 0) {
                try {
                    AbstractFileKeyPairProvider provider = SecurityUtils.createFileKeyPairProvider();
                    provider.setFiles(identities);
                    client.setKeyPairProvider(provider);
                } catch (Throwable t) {
                    error = showError(stderr, t.getClass().getSimpleName() + " while loading user keys: " + t.getMessage());
                }
            }

            Map<String, Object> props = client.getProperties();
            props.putAll(options);

            client.start();
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public void welcome(ClientSession clientSession, String banner, String lang) {
                    stdout.println(banner);
                }

                @Override
                public String[] interactive(ClientSession clientSession, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                    int numPropmts = GenericUtils.length(prompt);
                    String[] answers = new String[numPropmts];
                    try {
                        for (int i = 0; i < numPropmts; i++) {
                            stdout.append(prompt[i]).print(" ");
                            answers[i] = stdin.readLine();
                        }
                    } catch (IOException e) {
                        // ignored
                    }
                    return answers;
                }

                @Override
                public String getUpdatedPassword(ClientSession clientSession, String prompt, String lang) {
                    stdout.append(prompt).print(" ");
                    try {
                        return stdin.readLine();
                    } catch (IOException e) {
                        return null;
                    }
                }
            });

            // TODO use a configurable wait time
            ClientSession session = client.connect(login, host, port).verify().getSession();
            try {
                if (GenericUtils.length(password) > 0) {
                    session.addPasswordIdentity(password);
                }
                session.auth().verify(FactoryManager.DEFAULT_AUTH_TIMEOUT);    // TODO use a configurable wait time
                return session;
            } catch (Exception e) {
                session.close(true);
                throw e;
            }
        } catch (Exception e) {
            client.close();
            throw e;
        }
    }

    public static Level resolveLoggingVerbosity(String ... args) {
        return resolveLoggingVerbosity(args, GenericUtils.length(args));
    }

    public static Level resolveLoggingVerbosity(String[] args, int maxIndex) {
        for (int index = 0; index < maxIndex; index++) {
            String argName = args[index];
            if ("-v".equals(argName)) {
                return Level.INFO;
            } else if ("-vv".equals(argName)) {
                return Level.FINE;
            } else if ("-vvv".equals(argName)) {
                return Level.FINEST;
            }
        }

        return Level.WARNING;
    }

    public static OutputStream resolveLoggingTargetStream(PrintStream stdout, PrintStream stderr, String ... args) {
        return resolveLoggingTargetStream(stdout, stderr, args, GenericUtils.length(args));
    }

    public static OutputStream resolveLoggingTargetStream(PrintStream stdout, PrintStream stderr, String[] args, int maxIndex) {
        for (int index = 0; index < maxIndex; index++) {
            String argName = args[index];
            if ("-E".equals(argName)) {
                if ((index + 1) >= maxIndex) {
                    showError(stderr, "Missing " + argName + " option argument");
                    return null;
                }

                String argVal = args[index + 1];
                if ("--".equals(argVal)) {
                    return stdout;
                }

                try {
                    Path path = Paths.get(argVal).normalize().toAbsolutePath();
                    return Files.newOutputStream(path);
                } catch (IOException e) {
                    showError(stderr, "Failed (" + e.getClass().getSimpleName() + ") to open " + argVal + ": " + e.getMessage());
                    return null;
                }
            }
        }

        return stderr;
    }

    public static Handler setupLogging(Level level, final PrintStream stdout, final PrintStream stderr, final OutputStream outputStream) {
        Handler fh = new ConsoleHandler() {
            {
                setOutputStream(outputStream); // override the default (stderr)
            }

            @Override
            protected synchronized void setOutputStream(OutputStream out) throws SecurityException {
                if ((out == stdout) || (out == stderr)) {
                    super.setOutputStream(new NoCloseOutputStream(out));
                } else {
                    super.setOutputStream(out);
                }
            }
        };
        fh.setLevel(Level.FINEST);
        fh.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String message = formatMessage(record);
                String throwable = "";
                if (record.getThrown() != null) {
                    StringWriter sw = new StringWriter();
                    try (PrintWriter pw = new PrintWriter(sw)) {
                        pw.println();
                        record.getThrown().printStackTrace(pw);
                    }
                    throwable = sw.toString();
                }
                return String.format("%1$tY-%1$tm-%1$td: %2$-7.7s: %3$-32.32s: %4$s%5$s%n",
                        new Date(record.getMillis()), record.getLevel().getName(),
                        record.getLoggerName(), message, throwable);
            }
        });

        Logger root = Logger.getLogger("");
        for (Handler handler : root.getHandlers()) {
            root.removeHandler(handler);
        }
        root.addHandler(fh);
        root.setLevel(level);
        return fh;
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        PrintStream stdout = System.out;
        PrintStream stderr = System.err;
        boolean agentForward = false;
        List<String> command = null;
        int socksPort = -1;
        int numArgs = GenericUtils.length(args);
        boolean error = false;
        String target = null;
        Level level = Level.WARNING;
        OutputStream logStream = stderr;
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            // handled by 'setupClientSession'
            if ((command == null) && isArgumentedOption("-p", argName)) {
                if ((i + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                i++;
                continue;
            }

            // verbosity handled separately
            if ((command == null) && ("-v".equals(argName) || "-vv".equals(argName) || "-vvv".equals(argName))) {
                continue;
            }

            if ((command == null) && "-D".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }
                if (socksPort > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + socksPort);
                    break;
                }

                socksPort = Integer.parseInt(args[++i]);
                if (socksPort <= 0) {
                    error = showError(stderr, "Bad option value for " + argName + ": " + socksPort);
                    break;
                }
            } else if ((command == null) && "-A".equals(argName)) {
                agentForward = true;
            } else if ((command == null) && "-a".equals(argName)) {
                agentForward = false;
            } else {
                level = resolveLoggingVerbosity(args, i);
                logStream = resolveLoggingTargetStream(stdout, stderr, args, i);
                if (logStream == null) {
                    error = true;
                    break;
                }
                if ((command == null) && target == null) {
                    target = argName;
                } else {
                    if (command == null) {
                        command = new ArrayList<>();
                    }
                    command.add(argName);
                }
            }
        }

        ClientSession session = null;
        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(new NoCloseInputStream(System.in)))) {
            if (!error) {
                setupLogging(level, stdout, stderr, logStream);

                session = setupClientSession("-p", stdin, stdout, stderr, args);
                if (session == null) {
                    error = true;
                }
            }

            if (error) {
                System.err.println("usage: ssh [-A|-a] [-v[v][v]] [-E logoutput] [-D socksPort] [-l login] [-p port] [-o option=value] [-w password] hostname/user@host [command]");
                System.exit(-1);
                return;
            }

            try (SshClient client = (SshClient) session.getFactoryManager()) {
                /*
                String authSock = System.getenv(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
                if (authSock == null && provider != null) {
                    Iterable<KeyPair> keys = provider.loadKeys();
                    AgentServer server = new AgentServer();
                    authSock = server.start();
                    SshAgent agent = new AgentClient(authSock);
                    for (KeyPair key : keys) {
                        agent.addIdentity(key, "");
                    }
                    agent.close();
                    props.put(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSock);
                }
                */

                try {
                    if (socksPort >= 0) {
                        session.startDynamicPortForwarding(new SshdSocketAddress(SshdSocketAddress.LOCALHOST_NAME, socksPort));
                        Thread.sleep(Long.MAX_VALUE);
                    } else {
                        ClientChannel channel;
                        if (command == null) {
                            channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                            ((ChannelShell) channel).setAgentForwarding(agentForward);
                            channel.setIn(new NoCloseInputStream(System.in));
                        } else {
                            StringWriter w = new StringWriter();
                            for (String cmd : command) {
                                w.append(cmd).append(" ");
                            }
                            w.close();
                            channel = session.createChannel(ClientChannel.CHANNEL_EXEC, w.toString());
                        }

                        try {
                            channel.setOut(new NoCloseOutputStream(System.out));
                            channel.setErr(new NoCloseOutputStream(System.err));
                            channel.open().await(); // TODO use verify and a configurable timeout
                            channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), 0);
                        } finally {
                            channel.close();
                        }
                        session.close(false);
                    }
                } finally {
                    client.stop();
                }
            } finally {
                session.close();
            }
        } finally {
            if ((logStream != stdout) && (logStream != stderr)) {
                logStream.close();
            }
        }
    }
}
