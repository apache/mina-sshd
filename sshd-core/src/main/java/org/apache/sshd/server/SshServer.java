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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MappedKeyPairProvider;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.config.SshServerConfigFileReader;
import org.apache.sshd.server.config.keys.ServerIdentity;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.server.session.ServerProxyAcceptor;
import org.apache.sshd.server.session.ServerUserAuthServiceFactory;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.server.shell.InteractiveProcessShellFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;

/**
 * <p>
 * The SshServer class is the main entry point for the server side of the SSH protocol.
 * </p>
 *
 * <p>
 * The SshServer has to be configured before being started.  Such configuration can be
 * done either using a dependency injection mechanism (such as the Spring framework)
 * or programmatically. Basic setup is usually done using the {@link #setUpDefaultServer()}
 * method, which will known ciphers, macs, channels, etc...
 * Besides this basic setup, a few things have to be manually configured such as the
 * port number, {@link Factory}, the {@link org.apache.sshd.common.keyprovider.KeyPairProvider}
 * and the {@link PasswordAuthenticator}.
 * </p>
 *
 * <p>
 * Some properties can also be configured using the {@link PropertyResolverUtils}
 * {@code updateProperty} methods.
 * </p>
 *
 * Once the SshServer instance has been configured, it can be started using the
 * {@link #start()} method and stopped using the {@link #stop()} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see ServerFactoryManager
 * @see org.apache.sshd.common.FactoryManager
 */
public class SshServer extends AbstractFactoryManager implements ServerFactoryManager, Closeable {

    public static final Factory<SshServer> DEFAULT_SSH_SERVER_FACTORY = SshServer::new;

    public static final List<ServiceFactory> DEFAULT_SERVICE_FACTORIES =
            Collections.unmodifiableList(Arrays.asList(
                    ServerUserAuthServiceFactory.INSTANCE,
                    ServerConnectionServiceFactory.INSTANCE
            ));


    protected IoAcceptor acceptor;
    protected String host;
    protected int port;

    private ServerProxyAcceptor proxyAcceptor;
    private Factory<Command> shellFactory;
    private SessionFactory sessionFactory;
    private CommandFactory commandFactory;
    private List<NamedFactory<Command>> subsystemFactories;
    private List<NamedFactory<UserAuth>> userAuthFactories;
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
     * @return The currently bound addresses - valid only after server {@link #start() started}
     * and while not {@link #stop() stopped}
     */
    public Set<SocketAddress> getBoundAddresses() {
        return (acceptor == null) ? Collections.emptySet() : acceptor.getBoundAddresses();
    }

    @Override
    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return userAuthFactories;
    }

    @Override
    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    @Override
    public Factory<Command> getShellFactory() {
        return shellFactory;
    }

    public void setShellFactory(Factory<Command> shellFactory) {
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
    public List<NamedFactory<Command>> getSubsystemFactories() {
        return subsystemFactories;
    }

    public void setSubsystemFactories(List<NamedFactory<Command>> subsystemFactories) {
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
    protected void checkConfig() {
        super.checkConfig();

        ValidateUtils.checkTrue(getPort() >= 0 /* zero means not set yet */, "Bad port number: %d", Integer.valueOf(getPort()));

        List<NamedFactory<UserAuth>> authFactories = ServerAuthenticationManager.resolveUserAuthFactories(this);
        setUserAuthFactories(ValidateUtils.checkNotNullAndNotEmpty(authFactories, "UserAuthFactories not set"));

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
     * Start the SSH server and accept incoming exceptions on the configured port.
     * Ignored if already {@link #isStarted() started}
     *
     * @throws IOException If failed to start
     */
    public void start() throws IOException {
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
                        port = ((InetSocketAddress) acceptor.getBoundAddresses().iterator().next()).getPort();
                        log.info("start() listen on auto-allocated port=" + port);
                    }
                }
            }
        } else {
            acceptor.bind(new InetSocketAddress(port));
            if (port == 0) {
                port = ((InetSocketAddress) acceptor.getBoundAddresses().iterator().next()).getPort();
                log.info("start() listen on auto-allocated port=" + port);
            }
        }

        started.set(true);
    }

    /**
     * Stop the SSH server.  This method will block until all resources are actually disposed.
     * @throws IOException if stopping failed somehow
     */
    public void stop() throws IOException {
        stop(false);
    }

    public void stop(boolean immediately) throws IOException {
        if (!started.getAndSet(false)) {
            return;
        }

        long maxWait = immediately ? this.getLongProperty(STOP_WAIT_TIME, DEFAULT_STOP_WAIT_TIME) : Long.MAX_VALUE;
        boolean successful = close(immediately).await(maxWait);
        if (!successful) {
            throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
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
        return "SshServer[" + Integer.toHexString(hashCode()) + "]";
    }

    public static SshServer setUpDefaultServer() {
        return ServerBuilder.builder().build();
    }

    /*=================================
          Main class implementation
     *=================================*/

    public static KeyPairProvider setupServerKeys(SshServer sshd, String hostKeyType, int hostKeySize, Collection<String> keyFiles) throws Exception {
        if (GenericUtils.isEmpty(keyFiles)) {
            AbstractGeneratorHostKeyProvider hostKeyProvider;
            Path hostKeyFile;
            if (SecurityUtils.isBouncyCastleRegistered()) {
                hostKeyFile = new File("key.pem").toPath();
                hostKeyProvider = SecurityUtils.createGeneratorHostKeyProvider(hostKeyFile);
            } else {
                hostKeyFile = new File("key.ser").toPath();
                hostKeyProvider = new SimpleGeneratorHostKeyProvider(hostKeyFile);
            }
            hostKeyProvider.setAlgorithm(hostKeyType);
            if (hostKeySize != 0) {
                hostKeyProvider.setKeySize(hostKeySize);
            }

            List<KeyPair> keys = ValidateUtils.checkNotNullAndNotEmpty(hostKeyProvider.loadKeys(),
                    "Failed to load keys from %s", hostKeyFile);
            KeyPair kp = keys.get(0);
            PublicKey pubKey = kp.getPublic();
            String keyAlgorithm = pubKey.getAlgorithm();
            if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyAlgorithm)) {
                keyAlgorithm = KeyUtils.EC_ALGORITHM;
            } else if (BuiltinIdentities.Constants.ED25519.equals(keyAlgorithm)) {
                keyAlgorithm = SecurityUtils.EDDSA;
                // TODO change the hostKeyProvider to one that supports read/write of EDDSA keys - see SSHD-703
            }

            // force re-generation of host key if not same algorithm
            if (!Objects.equals(keyAlgorithm, hostKeyType)) {
                Files.deleteIfExists(hostKeyFile);
                hostKeyProvider.clearLoadedKeys();
            }

            return hostKeyProvider;
        } else {
            List<KeyPair> pairs = new ArrayList<>(keyFiles.size());
            for (String keyFilePath : keyFiles) {
                Path path = Paths.get(keyFilePath);
                try (InputStream inputStream = Files.newInputStream(path)) {
                    KeyPair kp = SecurityUtils.loadKeyPairIdentity(keyFilePath, inputStream, null);
                    pairs.add(kp);
                } catch (Exception e) {
                    System.err.append("Failed (" + e.getClass().getSimpleName() + ")"
                                + " to load host key file=" + keyFilePath
                                + ": " + e.getMessage());
                    throw e;
                }
            }

            return new MappedKeyPairProvider(pairs);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 8000;
        String provider;
        boolean error = false;
        String hostKeyType = AbstractGeneratorHostKeyProvider.DEFAULT_ALGORITHM;
        int hostKeySize = 0;
        Collection<String> keyFiles = null;
        Map<String, Object> options = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        int numArgs = GenericUtils.length(args);
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            if ("-p".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if ("-key-type".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                if (keyFiles != null) {
                    System.err.println("option conflicts with -key-file: " + argName);
                    error = true;
                    break;
                }
                hostKeyType = args[++i].toUpperCase();
            } else if ("-key-size".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                if (keyFiles != null) {
                    System.err.println("option conflicts with -key-file: " + argName);
                    error = true;
                    break;
                }

                hostKeySize = Integer.parseInt(args[++i]);
            } else if ("-key-file".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }

                String keyFilePath = args[++i];
                if (keyFiles == null) {
                    keyFiles = new LinkedList<>();
                }
                keyFiles.add(keyFilePath);
            } else if ("-io".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    error = true;
                    break;
                }
                provider = args[++i];
                if ("mina".equals(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), BuiltinIoServiceFactoryFactories.MINA.getFactoryClassName());
                } else if ("nio2".endsWith(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), BuiltinIoServiceFactoryFactories.NIO2.getFactoryClassName());
                } else {
                    System.err.println("provider should be mina or nio2: " + argName);
                    error = true;
                    break;
                }
            } else if ("-o".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires and argument: " + argName);
                    error = true;
                    break;
                }
                String opt = args[++i];
                int idx = opt.indexOf('=');
                if (idx <= 0) {
                    System.err.println("bad syntax for option: " + opt);
                    error = true;
                    break;
                }

                String optName = opt.substring(0, idx);
                String optValue = opt.substring(idx + 1);
                if (ServerIdentity.HOST_KEY_CONFIG_PROP.equals(optName)) {
                    if (keyFiles == null) {
                        keyFiles = new LinkedList<>();
                    }
                    keyFiles.add(optValue);
                } else {
                    options.put(optName, optValue);
                }
            } else if (argName.startsWith("-")) {
                System.err.println("illegal option: " + argName);
                error = true;
                break;
            } else {
                System.err.println("extra argument: " + argName);
                error = true;
                break;
            }
        }
        if (error) {
            System.err.println("usage: sshd [-p port] [-io mina|nio2] [-key-type RSA|DSA|EC] [-key-size NNNN] [-key-file <path>] [-o option=value]");
            System.exit(-1);
        }

        SshServer sshd = SshServer.setUpDefaultServer();
        Map<String, Object> props = sshd.getProperties();
        props.putAll(options);

        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(options);
        KeyPairProvider hostKeyProvider = setupServerKeys(sshd, hostKeyType, hostKeySize, keyFiles);
        sshd.setKeyPairProvider(hostKeyProvider);
        // Should come AFTER key pair provider setup so auto-welcome can be generated if needed
        setupServerBanner(sshd, resolver);
        sshd.setPort(port);

        String macsOverride = resolver.getString(SshConfigFileReader.MACS_CONFIG_PROP);
        if (GenericUtils.isNotEmpty(macsOverride)) {
            SshConfigFileReader.configureMacs(sshd, macsOverride, true, true);
        }

        sshd.setShellFactory(InteractiveProcessShellFactory.INSTANCE);
        sshd.setPasswordAuthenticator((username, password, session) -> Objects.equals(username, password));
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        setupServerForwarding(sshd, resolver);
        sshd.setCommandFactory(new ScpCommandFactory.Builder().withDelegate(
            command -> new ProcessShellFactory(GenericUtils.split(command, ' ')).create()
        ).build());

        System.err.println("Starting SSHD on port " + port);
        sshd.start();
        Thread.sleep(Long.MAX_VALUE);
    }

    public static ForwardingFilter setupServerForwarding(SshServer server, PropertyResolver options) {
        ForwardingFilter forwardFilter = SshServerConfigFileReader.resolveServerForwarding(options);
        server.setForwardingFilter(forwardFilter);
        return forwardFilter;
    }

    public static Object setupServerBanner(ServerFactoryManager server, PropertyResolver options) {
        Object banner = SshServerConfigFileReader.resolveBanner(options);
        PropertyResolverUtils.updateProperty(server, ServerAuthenticationManager.WELCOME_BANNER, banner);
        return banner;
    }
}
