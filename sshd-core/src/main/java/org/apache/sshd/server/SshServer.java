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
package org.apache.sshd.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.HostKeyCertificateProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.server.session.ServerProxyAcceptor;
import org.apache.sshd.server.session.ServerUserAuthServiceFactory;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.subsystem.SubsystemFactory;

/**
 * <p>
 * The SshServer class is the main entry point for the server side of the SSH protocol.
 * </p>
 *
 * <p>
 * The SshServer has to be configured before being started. Such configuration can be done either using a dependency
 * injection mechanism (such as the Spring framework) or programmatically. Basic setup is usually done using the
 * {@link #setUpDefaultServer()} method, which will known ciphers, macs, channels, etc... Besides this basic setup, a
 * few things have to be manually configured such as the port number, {@link Factory}, the
 * {@link org.apache.sshd.common.keyprovider.KeyPairProvider} and the {@link PasswordAuthenticator}.
 * </p>
 *
 * <p>
 * Some properties can also be configured using the {@link PropertyResolverUtils} {@code updateProperty} methods.
 * </p>
 *
 * Once the SshServer instance has been configured, it can be started using the {@link #start()} method and stopped
 * using the {@link #stop()} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    ServerFactoryManager
 * @see    org.apache.sshd.common.FactoryManager
 */
public class SshServer extends AbstractFactoryManager implements ServerFactoryManager, Closeable {
    public static final Factory<SshServer> DEFAULT_SSH_SERVER_FACTORY = SshServer::new;

    public static final List<ServiceFactory> DEFAULT_SERVICE_FACTORIES = Collections.unmodifiableList(
            Arrays.asList(
                    ServerUserAuthServiceFactory.INSTANCE,
                    ServerConnectionServiceFactory.INSTANCE));

    protected IoAcceptor acceptor;
    protected String host;
    protected int port;

    private ServerProxyAcceptor proxyAcceptor;
    private ShellFactory shellFactory;
    private SessionFactory sessionFactory;
    private CommandFactory commandFactory;
    private List<SubsystemFactory> subsystemFactories;
    private List<UserAuthFactory> userAuthFactories;
    private KeyPairProvider keyPairProvider;
    private HostKeyCertificateProvider hostKeyCertificateProvider;
    private PasswordAuthenticator passwordAuthenticator;
    private PublickeyAuthenticator publickeyAuthenticator;
    private KeyboardInteractiveAuthenticator interactiveAuthenticator;
    private HostBasedAuthenticator hostBasedAuthenticator;
    private GSSAuthenticator gssAuthenticator;
    private final AtomicBoolean started = new AtomicBoolean(false);

    public SshServer() {
        super();
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Configure the port number to use for this SSH server.
     *
     * @param port the port number for this SSH server
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @return The currently bound addresses - valid only after server {@link #start() started} and while not
     *         {@link #stop() stopped}
     */
    public Set<SocketAddress> getBoundAddresses() {
        return (acceptor == null) ? Collections.emptySet() : acceptor.getBoundAddresses();
    }

    @Override
    public List<UserAuthFactory> getUserAuthFactories() {
        return userAuthFactories;
    }

    @Override
    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    @Override
    public ShellFactory getShellFactory() {
        return shellFactory;
    }

    public void setShellFactory(ShellFactory shellFactory) {
        this.shellFactory = shellFactory;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public ServerProxyAcceptor getServerProxyAcceptor() {
        return proxyAcceptor;
    }

    @Override
    public void setServerProxyAcceptor(ServerProxyAcceptor proxyAcceptor) {
        this.proxyAcceptor = proxyAcceptor;
    }

    @Override
    public CommandFactory getCommandFactory() {
        return commandFactory;
    }

    public void setCommandFactory(CommandFactory commandFactory) {
        this.commandFactory = commandFactory;
    }

    @Override
    public List<SubsystemFactory> getSubsystemFactories() {
        return subsystemFactories;
    }

    public void setSubsystemFactories(List<SubsystemFactory> subsystemFactories) {
        this.subsystemFactories = subsystemFactories;
    }

    @Override
    public PasswordAuthenticator getPasswordAuthenticator() {
        return passwordAuthenticator;
    }

    @Override
    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator;
    }

    @Override
    public PublickeyAuthenticator getPublickeyAuthenticator() {
        return publickeyAuthenticator;
    }

    @Override
    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator;
    }

    @Override
    public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
        return interactiveAuthenticator;
    }

    @Override
    public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
        this.interactiveAuthenticator = interactiveAuthenticator;
    }

    @Override
    public GSSAuthenticator getGSSAuthenticator() {
        return gssAuthenticator;
    }

    @Override
    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
        this.gssAuthenticator = gssAuthenticator;
    }

    @Override
    public HostBasedAuthenticator getHostBasedAuthenticator() {
        return hostBasedAuthenticator;
    }

    @Override
    public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
        this.hostBasedAuthenticator = hostBasedAuthenticator;
    }

    @Override
    public KeyPairProvider getKeyPairProvider() {
        return keyPairProvider;
    }

    @Override
    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    @Override
    public HostKeyCertificateProvider getHostKeyCertificateProvider() {
        return hostKeyCertificateProvider;
    }

    @Override
    public void setHostKeyCertificateProvider(HostKeyCertificateProvider hostKeyCertificateProvider) {
        this.hostKeyCertificateProvider = hostKeyCertificateProvider;
    }

    @Override
    protected void checkConfig() {
        super.checkConfig();

        ValidateUtils.checkTrue(getPort() >= 0 /* zero means not set yet */, "Bad port number: %d", Integer.valueOf(getPort()));

        List<UserAuthFactory> authFactories = ServerAuthenticationManager.resolveUserAuthFactories(this);
        setUserAuthFactories(
                ValidateUtils.checkNotNullAndNotEmpty(authFactories, "UserAuthFactories not set"));

        ValidateUtils.checkNotNullAndNotEmpty(getChannelFactories(), "ChannelFactories not set");
        Objects.requireNonNull(getKeyPairProvider(), "HostKeyProvider not set");
        Objects.requireNonNull(getFileSystemFactory(), "FileSystemFactory not set");

        if (GenericUtils.isEmpty(getServiceFactories())) {
            setServiceFactories(DEFAULT_SERVICE_FACTORIES);
        }
    }

    public boolean isStarted() {
        return started.get();
    }

    /**
     * Start the SSH server and accept incoming exceptions on the configured port. Ignored if already
     * {@link #isStarted() started}
     *
     * @throws IOException If failed to start
     */
    public void start() throws IOException {
        if (isClosed()) {
            throw new IllegalStateException("Can not start the server again");
        }
        if (isStarted()) {
            return;
        }

        checkConfig();
        if (sessionFactory == null) {
            sessionFactory = createSessionFactory();
        }
        acceptor = createAcceptor();

        setupSessionTimeout(sessionFactory);

        String hostsList = getHost();
        if (!GenericUtils.isEmpty(hostsList)) {
            String[] hosts = GenericUtils.split(hostsList, ',');
            for (String host : hosts) {
                if (log.isDebugEnabled()) {
                    log.debug("start() - resolve bind host={}", host);
                }

                InetAddress[] inetAddresses = InetAddress.getAllByName(host);
                for (InetAddress inetAddress : inetAddresses) {
                    if (log.isTraceEnabled()) {
                        log.trace("start() - bind host={} / {}", host, inetAddress);
                    }

                    acceptor.bind(new InetSocketAddress(inetAddress, port));
                    if (port == 0) {
                        SocketAddress selectedAddress = GenericUtils.head(acceptor.getBoundAddresses());
                        port = ((InetSocketAddress) selectedAddress).getPort();
                        log.info("start() listen on auto-allocated port=" + port);
                    }
                }
            }
        } else {
            acceptor.bind(new InetSocketAddress(port));
            if (port == 0) {
                SocketAddress selectedAddress = GenericUtils.head(acceptor.getBoundAddresses());
                port = ((InetSocketAddress) selectedAddress).getPort();
                log.info("start() listen on auto-allocated port=" + port);
            }
        }

        started.set(true);
    }

    /**
     * Stop the SSH server. This method will block until all resources are actually disposed.
     * 
     * @throws IOException if stopping failed somehow
     */
    public void stop() throws IOException {
        stop(false);
    }

    public void stop(boolean immediately) throws IOException {
        if (!started.getAndSet(false)) {
            return;
        }

        try {
            Duration maxWait
                    = immediately ? CoreModuleProperties.STOP_WAIT_TIME.getRequired(this) : Duration.ofMillis(Long.MAX_VALUE);
            boolean successful = close(immediately).await(maxWait);
            if (!successful) {
                throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
            }
        } finally {
            // clear the attributes since we close stop the server
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
                .sequential(acceptor, ioServiceFactory)
                .run(closeId, () -> {
                    acceptor = null;
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

    /**
     * Obtain the list of active sessions.
     *
     * @return A {@link List} of the currently active session
     */
    public List<AbstractSession> getActiveSessions() {
        List<AbstractSession> sessions = new ArrayList<>();
        for (IoSession ioSession : acceptor.getManagedSessions().values()) {
            AbstractSession session = AbstractSession.getSession(ioSession, true);
            if (session != null) {
                sessions.add(session);
            }
        }
        return sessions;
    }

    protected IoAcceptor createAcceptor() {
        IoServiceFactory ioFactory = getIoServiceFactory();
        SessionFactory sessFactory = getSessionFactory();
        return ioFactory.createAcceptor(sessFactory);
    }

    protected SessionFactory createSessionFactory() {
        return new SessionFactory(this);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[" + Integer.toHexString(hashCode()) + "]"
               + "(port=" + getPort() + ")";
    }

    /**
     * Setup a default server
     *
     * @return a newly create {@link SshServer} with default configurations
     */
    public static SshServer setUpDefaultServer() {
        ServerBuilder builder = ServerBuilder.builder();
        return builder.build();
    }
}
