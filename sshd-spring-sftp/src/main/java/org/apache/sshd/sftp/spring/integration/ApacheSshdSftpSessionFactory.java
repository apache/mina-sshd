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

package org.apache.sshd.sftp.spring.integration;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.simple.SimpleClientConfigurator;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.MutableBasicCredentials;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.pem.PEMResourceParserUtils;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.integration.file.remote.session.Session;
import org.springframework.integration.file.remote.session.SessionFactory;
import org.springframework.integration.file.remote.session.SharedSessionCapable;

/**
 * A proper replacement for the {@code org.springframework.integration.sftp.session.DefaultSftpSessionFactory}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ApacheSshdSftpSessionFactory
        extends AbstractLoggingBean
        implements SessionFactory<DirEntry>, SharedSessionCapable,
        MutableBasicCredentials, FilePasswordProviderManager, SimpleClientConfigurator,
        InitializingBean, DisposableBean {

    private final boolean sharedSession;
    private final AtomicReference<ClientSession> sharedSessionHolder = new AtomicReference<>();

    private volatile String hostValue;
    private volatile int portValue = SshConstants.DEFAULT_PORT;
    private volatile String userValue;
    private volatile String passwordValue;
    // TODO add support for loading multiple private keys
    private volatile KeyPair privateKeyPair;
    private volatile Resource privateKey;
    private volatile String privateKeyPassphrase;
    private volatile FilePasswordProvider passwordProvider;
    private volatile Properties sessionConfig;
    private volatile long connTimeout = DEFAULT_CONNECT_TIMEOUT;
    private volatile long authTimeout = DEFAULT_AUTHENTICATION_TIMEOUT;
    private volatile SftpVersionSelector versionSelector = SftpVersionSelector.CURRENT;

    private SshClient sshClient;

    public ApacheSshdSftpSessionFactory() {
        this(false);
    }

    public ApacheSshdSftpSessionFactory(boolean sharedSession) {
        this.sharedSession = sharedSession;
    }

    public String getHost() {
        return hostValue;
    }

    /**
     * @param host The host to connect to - this is a mandatory property.
     */
    public void setHost(String host) {
        this.hostValue = ValidateUtils.checkNotNullAndNotEmpty(host, "No host name provided");
    }

    public int getPort() {
        return portValue;
    }

    /**
     * The port over which the SFTP connection shall be established. If not specified, this value defaults to
     * <code>22</code>. If specified, this property must be a positive number.
     *
     * @param port The port value
     */
    public void setPort(int port) {
        ValidateUtils.checkTrue(port > 0, "Non-positive port value specified: %d", port);
        this.portValue = port;
    }

    @Override
    public String getUsername() {
        return userValue;
    }

    /**
     * The remote user to use. This is a mandatory property.
     *
     * @param user The (never {@code null}/empty) username
     */
    @Override
    public void setUsername(String user) {
        this.userValue = ValidateUtils.checkNotNullAndNotEmpty(user, "No user specified: %s", user);
    }

    @Override
    public String getPassword() {
        return passwordValue;
    }

    /**
     * The password to authenticate against the remote host. If a password is not provided, then a
     * {@link #setPrivateKeyLocation(Resource)} call is mandatory.
     *
     * @param password The password to use - if {@code null} then no password is set - in which case the
     *                 {@link #getPrivateKeyLocation()} resource is used
     */
    @Override
    public void setPassword(String password) {
        this.passwordValue = password;
    }

    public Resource getPrivateKeyLocation() {
        return privateKey;
    }

    /**
     * Allows you to set a {@link Resource}, which represents the location of the private key used for authenticating
     * against the remote host. If the privateKey is not provided, then the {@link #setPassword(String)} call is
     * mandatory
     *
     * @param privateKey The private key {@link Resource}
     */
    public void setPrivateKeyLocation(Resource privateKey) {
        this.privateKey = privateKey;
    }

    public String getPrivateKeyPassphrase() {
        return privateKeyPassphrase;
    }

    /**
     * @param privateKeyPassphrase The password for the private key - required if the private key resource is encrypted
     */
    public void setPrivateKeyPassphrase(String privateKeyPassphrase) {
        this.privateKeyPassphrase = privateKeyPassphrase;
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return passwordProvider;
    }

    @Override
    public void setFilePasswordProvider(FilePasswordProvider provider) {
        this.passwordProvider = provider;
    }

    public KeyPair getPrivateKeyPair() {
        return privateKeyPair;
    }

    public void setPrivateKeyPair(KeyPair privateKeyPair) {
        this.privateKeyPair = privateKeyPair;
    }

    @Override // In seconds
    public long getConnectTimeout() {
        return connTimeout;
    }

    @Override
    public void setConnectTimeout(long timeout) {
        connTimeout = timeout;
    }

    @Override // In seconds
    public long getAuthenticationTimeout() {
        return authTimeout;
    }

    @Override
    public void setAuthenticationTimeout(long timeout) {
        authTimeout = timeout;
    }

    public Properties getSessionConfig() {
        return sessionConfig;
    }

    /**
     * @param sessionConfig Extra {@link Properties} that can be used to set specific SSHD session properties
     */
    public void setSessionConfig(Properties sessionConfig) {
        this.sessionConfig = sessionConfig;
    }

    public SshClient getSshClient() {
        return sshClient;
    }

    public void setSshClient(SshClient sshClient) {
        this.sshClient = sshClient;
    }

    @Override
    public boolean isSharedSession() {
        return sharedSession;
    }

    public SftpVersionSelector getSftpVersionSelector() {
        return versionSelector;
    }

    public void setSftpVersion(String version) {
        if ("CURRENT".equalsIgnoreCase(version)) {
            setSftpVersionSelector(SftpVersionSelector.CURRENT);
        } else if ("MAXIMUM".equalsIgnoreCase(version)) {
            setSftpVersionSelector(SftpVersionSelector.MAXIMUM);
        } else if ("MINIMUM".equalsIgnoreCase(version)) {
            setSftpVersionSelector(SftpVersionSelector.MINIMUM);
        } else {
            int fixedVersion = Integer.parseInt(version);
            ValidateUtils.checkTrue((fixedVersion >= SftpSubsystemEnvironment.LOWER_SFTP_IMPL)
                    && (fixedVersion <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL),
                    "Unsupported SFTP version: %s", version);
            setSftpVersionSelector(SftpVersionSelector.fixedVersionSelector(fixedVersion));
        }
    }

    public void setSftpVersionSelector(SftpVersionSelector selector) {
        versionSelector = Objects.requireNonNull(selector, "No version selector provided");
    }

    protected ClientSession getSharedClientSession() {
        synchronized (sharedSessionHolder) {
            return sharedSessionHolder.get();
        }
    }

    @Override
    public void resetSharedSession() {
        ClientSession sharedSession;
        synchronized (sharedSessionHolder) {
            sharedSession = sharedSessionHolder.getAndSet(null);
        }

        if (sharedSession != null) {
            log.info("resetSharedSession - session={}", sharedSession);
            sharedSession.close(false).addListener(new SshFutureListener<CloseFuture>() {
                @Override
                @SuppressWarnings("synthetic-access")
                public void operationComplete(CloseFuture future) {
                    log.info("resetSharedSession - session closed: {}", sharedSession);
                }
            });
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        KeyPair kp = getPrivateKeyPair();
        Resource privateKeyLocation = getPrivateKeyLocation();
        ValidateUtils.checkState(
                GenericUtils.isNotEmpty(getPassword()) || (kp != null) || (privateKeyLocation != null),
                "Either password or private key must be provided");

        SshClient client = getSshClient();
        if (client == null) {
            client = createSshClientInstance();
            setSshClient(client);
        }

        if (!client.isOpen()) {
            log.info("afterPropertiesSet() - starting client");
            client.start();
            log.info("afterPropertiesSet() - client started");
        }
    }

    protected SshClient createSshClientInstance() throws Exception {
        return SshClient.setUpDefaultClient();
    }

    @Override
    public void destroy() throws Exception {
        SshClient client = getSshClient();
        if ((client != null) && client.isOpen()) {
            log.info("destroy() - stopping client");
            client.close(false); // do not wait for the close to complete
            log.info("destroy() - client stopped");
        }
    }

    protected KeyPair resolveKeyIdentity(ClientSession session) throws IOException, GeneralSecurityException {
        KeyPair kp = getPrivateKeyPair();
        if (kp != null) {
            return kp;
        }

        Resource location = getPrivateKeyLocation();
        if (location == null) {
            return null;
        }

        kp = loadPrivateKey(session, location, getPrivateKeyPassphrase());
        if (kp != null) {
            setPrivateKeyPair(kp); // cache it for re-use
        }

        return kp;
    }

    protected FilePasswordProvider resolveFilePasswordProvider(
            ClientSession session, Resource keyResource, String keyPassword) {
        FilePasswordProvider provider = getFilePasswordProvider();
        if (provider != null) {
            return provider;
        }

        return GenericUtils.isEmpty(keyPassword)
                ? FilePasswordProvider.EMPTY
                : FilePasswordProvider.of(keyPassword);
    }

    protected KeyPair loadPrivateKey(ClientSession session, Resource keyResource, String keyPassword)
            throws IOException, GeneralSecurityException {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("loadPrivateKey({}) loading from {}", session, keyResource);
        }

        FilePasswordProvider provider = resolveFilePasswordProvider(session, keyResource, keyPassword);
        SpringIoResource location = new SpringIoResource(keyResource);
        Collection<KeyPair> keyPairs = PEMResourceParserUtils.PROXY.loadKeyPairs(session, location, provider);
        int numLoaded = GenericUtils.size(keyPairs);
        if (numLoaded <= 0) {
            if (debugEnabled) {
                log.debug("loadPrivateKey({}) no keys loaded from {}", session, keyResource);
            }
        }

        // TODO add support for multiple keys
        ValidateUtils.checkState(numLoaded == 1, "Multiple keys loaded from %s", keyResource);

        KeyPair kp = GenericUtils.head(keyPairs);
        if (debugEnabled) {
            PublicKey pubKey = kp.getPublic();
            log.debug("loadPrivateKey({}) loaded {} key={} from {}",
                    session, KeyUtils.getKeyType(pubKey), KeyUtils.getFingerPrint(pubKey), keyResource);
        }
        return kp;
    }

    @Override
    public Session<DirEntry> getSession() {
        boolean sharedInstance = isSharedSession();
        try {
            ClientSession session = null;
            try {
                session = resolveClientSession(sharedInstance);

                SftpVersionSelector selector = getSftpVersionSelector();
                SftpClientFactory sftpFactory = SftpClientFactory.instance();
                SftpClient sftpClient = sftpFactory.createSftpClient(session, selector);
                try {
                    ClientSession sessionInstance = session;
                    Session<DirEntry> result = sharedInstance
                            ? new SpringSftpSession(sftpClient)
                            : new SpringSftpSession(sftpClient, () -> {
                                try {
                                    sessionInstance.close();
                                    return null;
                                } catch (Exception e) {
                                    return e;
                                }
                            });
                    // avoid auto-close at finally clause
                    sftpClient = null;
                    session = null;
                    return result;
                } finally {
                    if (sftpClient != null) {
                        sftpClient.close();
                    }
                }
            } finally {
                if (session != null) {
                    try {
                        session.close();
                    } finally {
                        if (sharedInstance) {
                            resetSharedSession();
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw GenericUtils.toRuntimeException(e);
        }
    }

    protected ClientSession resolveClientSession(boolean sharedInstance) throws Exception {
        ClientSession session;
        if (sharedInstance) {
            synchronized (sharedSessionHolder) {
                session = sharedSessionHolder.get();
                if (session == null) {
                    session = createClientSession();
                }
                sharedSessionHolder.set(session);
            }
        } else {
            session = createClientSession();
        }

        return session;
    }

    protected ClientSession createClientSession() throws Exception {
        String hostname = ValidateUtils.checkNotNullAndNotEmpty(getHost(), "Host must not be empty");
        String username = ValidateUtils.checkNotNullAndNotEmpty(getUsername(), "User must not be empty");
        ClientSession session
                = createClientSession(hostname, username, getPort(), getEffectiveTimeoutValue(getConnectTimeout()));
        try {
            session = configureClientSessionProperties(session, getSessionConfig());
            session = authenticateClientSession(session, getEffectiveTimeoutValue(getAuthenticationTimeout()));

            ClientSession newSession = session;
            if (log.isDebugEnabled()) {
                log.debug("createClientSession - session={}", session);
            }
            session = null; // avoid auto-close at finally clause
            return newSession;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    protected ClientSession createClientSession(String hostname, String username, int port, long timeout) throws IOException {
        SshClient client = getSshClient();
        if (log.isDebugEnabled()) {
            log.debug("createClientSession({}@{}:{}) waitTimeout={}", username, hostname, port, timeout);
        }
        ConnectFuture connectFuture = client.connect(username, hostname, port);
        return connectFuture.verify(timeout).getSession();
    }

    protected ClientSession configureClientSessionProperties(ClientSession session, Properties props) throws IOException {
        if (GenericUtils.isEmpty(props)) {
            return session;
        }

        boolean debugEnabled = log.isDebugEnabled();
        for (String propName : props.stringPropertyNames()) {
            String propValue = props.getProperty(propName);
            if (debugEnabled) {
                log.debug("configureClientSessionProperties({}) set {}={}", session, propName, propValue);
            }
            PropertyResolverUtils.updateProperty(session, propName, propValue);
        }

        return session;
    }

    protected ClientSession authenticateClientSession(ClientSession session, long timeout)
            throws IOException, GeneralSecurityException {
        boolean debugEnabled = log.isDebugEnabled();

        String passwordIdentity = getPassword();
        if (GenericUtils.isNotEmpty(passwordIdentity)) {
            if (debugEnabled) {
                log.debug("authenticateClientSession({}) using password identity", session);
            }
            session.addPasswordIdentity(passwordIdentity);
        }

        KeyPair privateKeyIdentity = resolveKeyIdentity(session);
        if (privateKeyIdentity != null) {
            if (debugEnabled) {
                PublicKey pubKey = privateKeyIdentity.getPublic();
                log.debug("authenticateClientSession({}) using {} key={}",
                        session, KeyUtils.getKeyType(pubKey), KeyUtils.getFingerPrint(pubKey));
            }
            session.addPublicKeyIdentity(privateKeyIdentity);
        }

        if (debugEnabled) {
            log.debug("authenticateClientSession({}) authenticate - timeout=", session, timeout);
        }
        session.auth().verify(timeout);
        return session;
    }

    protected long getEffectiveTimeoutValue(long timeoutSeconds) {
        if (timeoutSeconds < (Long.MAX_VALUE / 61L)) {
            return TimeUnit.SECONDS.toMillis(timeoutSeconds);
        } else {
            return timeoutSeconds;
        }
    }
}
