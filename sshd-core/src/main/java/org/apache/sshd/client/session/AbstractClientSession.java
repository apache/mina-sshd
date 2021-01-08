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

package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.auth.UserAuthFactory;
import org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.PtyChannelConfigurationHolder;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.helpers.AbstractConnectionService;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Provides default implementations of {@link ClientSession} related methods
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractClientSession extends AbstractSession implements ClientSession {
    protected final boolean sendImmediateClientIdentification;
    protected final boolean sendImmediateKexInit;

    private final List<Object> identities = new CopyOnWriteArrayList<>();
    private final AuthenticationIdentitiesProvider identitiesProvider;
    private final AttributeRepository connectionContext;

    private PublicKey serverKey;
    private ServerKeyVerifier serverKeyVerifier;
    private UserInteraction userInteraction;
    private PasswordIdentityProvider passwordIdentityProvider;
    private PasswordAuthenticationReporter passwordAuthenticationReporter;
    private KeyIdentityProvider keyIdentityProvider;
    private PublicKeyAuthenticationReporter publicKeyAuthenticationReporter;
    private HostBasedAuthenticationReporter hostBasedAuthenticationReporter;
    private List<UserAuthFactory> userAuthFactories;
    private SocketAddress connectAddress;
    private ClientProxyConnector proxyConnector;

    protected AbstractClientSession(ClientFactoryManager factoryManager, IoSession ioSession) {
        super(false, factoryManager, ioSession);

        sendImmediateClientIdentification = CoreModuleProperties.SEND_IMMEDIATE_IDENTIFICATION.getRequired(this);
        sendImmediateKexInit = CoreModuleProperties.SEND_IMMEDIATE_KEXINIT.getRequired(this);

        identitiesProvider = AuthenticationIdentitiesProvider.wrapIdentities(identities);
        connectionContext = (AttributeRepository) ioSession.getAttribute(AttributeRepository.class);
    }

    @Override
    public AttributeRepository getConnectionContext() {
        return connectionContext;
    }

    @Override
    public ClientFactoryManager getFactoryManager() {
        return (ClientFactoryManager) super.getFactoryManager();
    }

    @Override
    public SocketAddress getConnectAddress() {
        return resolvePeerAddress(connectAddress);
    }

    public void setConnectAddress(SocketAddress connectAddress) {
        this.connectAddress = connectAddress;
    }

    @Override
    public PublicKey getServerKey() {
        return serverKey;
    }

    public void setServerKey(PublicKey serverKey) {
        if (log.isDebugEnabled()) {
            log.debug("setServerKey({}) keyType={}, digest={}",
                    this, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey));
        }

        this.serverKey = serverKey;
    }

    @Override
    public ServerKeyVerifier getServerKeyVerifier() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(ServerKeyVerifier.class, serverKeyVerifier, manager.getServerKeyVerifier());
    }

    @Override
    public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
        this.serverKeyVerifier = serverKeyVerifier; // OK if null - inherit from parent
    }

    @Override
    public UserInteraction getUserInteraction() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(UserInteraction.class, userInteraction, manager.getUserInteraction());
    }

    @Override
    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction; // OK if null - inherit from parent
    }

    @Override
    public PasswordAuthenticationReporter getPasswordAuthenticationReporter() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(PasswordAuthenticationReporter.class, passwordAuthenticationReporter,
                manager.getPasswordAuthenticationReporter());
    }

    @Override
    public void setPasswordAuthenticationReporter(PasswordAuthenticationReporter reporter) {
        this.passwordAuthenticationReporter = reporter;
    }

    @Override
    public List<UserAuthFactory> getUserAuthFactories() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveFactories(userAuthFactories, manager.getUserAuthFactories());
    }

    @Override
    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories = userAuthFactories; // OK if null/empty - inherit from parent
    }

    @Override
    public AuthenticationIdentitiesProvider getRegisteredIdentities() {
        return identitiesProvider;
    }

    @Override
    public PasswordIdentityProvider getPasswordIdentityProvider() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(PasswordIdentityProvider.class, passwordIdentityProvider,
                manager.getPasswordIdentityProvider());
    }

    @Override
    public void setPasswordIdentityProvider(PasswordIdentityProvider provider) {
        passwordIdentityProvider = provider;
    }

    @Override
    public KeyIdentityProvider getKeyIdentityProvider() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(KeyIdentityProvider.class, keyIdentityProvider,
                manager.getKeyIdentityProvider());
    }

    @Override
    public void setKeyIdentityProvider(KeyIdentityProvider keyIdentityProvider) {
        this.keyIdentityProvider = keyIdentityProvider;
    }

    @Override
    public PublicKeyAuthenticationReporter getPublicKeyAuthenticationReporter() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(PublicKeyAuthenticationReporter.class, publicKeyAuthenticationReporter,
                manager.getPublicKeyAuthenticationReporter());
    }

    @Override
    public void setPublicKeyAuthenticationReporter(PublicKeyAuthenticationReporter reporter) {
        this.publicKeyAuthenticationReporter = reporter;
    }

    @Override
    public HostBasedAuthenticationReporter getHostBasedAuthenticationReporter() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(HostBasedAuthenticationReporter.class, hostBasedAuthenticationReporter,
                manager.getHostBasedAuthenticationReporter());
    }

    @Override
    public void setHostBasedAuthenticationReporter(HostBasedAuthenticationReporter reporter) {
        this.hostBasedAuthenticationReporter = reporter;
    }

    @Override
    public ClientProxyConnector getClientProxyConnector() {
        ClientFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(ClientProxyConnector.class, proxyConnector, manager.getClientProxyConnector());
    }

    @Override
    public void setClientProxyConnector(ClientProxyConnector proxyConnector) {
        this.proxyConnector = proxyConnector;
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

        int index = AuthenticationIdentitiesProvider.findIdentityIndex(identities,
                AuthenticationIdentitiesProvider.PASSWORD_IDENTITY_COMPARATOR, password);
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
            PublicKey key = kp.getPublic();
            log.debug("addPublicKeyIdentity({}) {}-{}", this, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }
    }

    @Override
    public KeyPair removePublicKeyIdentity(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        int index = AuthenticationIdentitiesProvider.findIdentityIndex(identities,
                AuthenticationIdentitiesProvider.KEYPAIR_IDENTITY_COMPARATOR, kp);
        if (index >= 0) {
            return (KeyPair) identities.remove(index);
        } else {
            return null;
        }
    }

    protected void initializeKeyExchangePhase() throws Exception {
        KexExtensionHandler extHandler = getKexExtensionHandler();
        if ((extHandler == null) || (!extHandler.isKexExtensionsAvailable(this, AvailabilityPhase.PREKEX))) {
            kexState.set(KexState.INIT);
            sendKexInit();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("initializeKexPhase({}) delay KEX-INIT until server-side one received", this);
            }
        }
    }

    protected void initializeProxyConnector() throws Exception {
        ClientProxyConnector proxyConnector = getClientProxyConnector();
        boolean debugEnabled = log.isDebugEnabled();
        if (proxyConnector == null) {
            if (debugEnabled) {
                log.debug("initializeProxyConnector({}) no proxy to initialize", this);
            }
            return;
        }

        try {
            if (debugEnabled) {
                log.debug("initializeProxyConnector({}) initialize proxy={}", this, proxyConnector);
            }

            proxyConnector.sendClientProxyMetadata(this);

            if (debugEnabled) {
                log.debug("initializeProxyConnector({}) proxy={} initialized", this, proxyConnector);
            }
        } catch (Throwable t) {
            warn("initializeProxyConnector({}) failed ({}) to send proxy metadata: {}",
                    this, t.getClass().getSimpleName(), t.getMessage(), t);

            if (t instanceof Exception) {
                throw (Exception) t;
            } else {
                throw new RuntimeSshException(t);
            }
        }
    }

    protected IoWriteFuture sendClientIdentification() throws Exception {
        clientVersion = resolveIdentificationString(CoreModuleProperties.CLIENT_IDENTIFICATION.getName());
        // Note: we intentionally use an unmodifiable list in order to enforce the fact that client cannot send header lines
        signalSendIdentification(clientVersion, Collections.emptyList());
        return sendIdentification(clientVersion, Collections.emptyList());
    }

    @Override
    public ClientChannel createChannel(String type) throws IOException {
        return createChannel(type, null);
    }

    @Override
    public ClientChannel createChannel(String type, String subType) throws IOException {
        if (Channel.CHANNEL_SHELL.equals(type)) {
            return createShellChannel();
        } else if (Channel.CHANNEL_EXEC.equals(type)) {
            return createExecChannel(subType);
        } else if (Channel.CHANNEL_SUBSYSTEM.equals(type)) {
            return createSubsystemChannel(subType);
        } else {
            throw new IllegalArgumentException("Unsupported channel type requested: " + type);
        }
    }

    @Override
    public ChannelExec createExecChannel(String command, PtyChannelConfigurationHolder ptyConfig, Map<String, ?> env)
            throws IOException {
        ChannelExec channel = new ChannelExec(command, ptyConfig, env);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createExecChannel({})[{}] created id={} - PTY={}", this, command, id, ptyConfig);
        }
        return channel;
    }

    @Override
    public ChannelSubsystem createSubsystemChannel(String subsystem) throws IOException {
        ChannelSubsystem channel = new ChannelSubsystem(subsystem);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createSubsystemChannel({})[{}] created id={}", this, subsystem, id);
        }
        return channel;
    }

    @Override
    public ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote)
            throws IOException {
        ChannelDirectTcpip channel = new ChannelDirectTcpip(local, remote);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createDirectTcpipChannel({})[{} => {}] created id={}", this, local, remote, id);
        }
        return channel;
    }

    protected ClientUserAuthService getUserAuthService() {
        return getService(ClientUserAuthService.class);
    }

    @Override
    protected ConnectionService getConnectionService() {
        return getService(ConnectionService.class);
    }

    @Override
    public SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote)
            throws IOException {
        Forwarder forwarder = getForwarder();
        return forwarder.startLocalPortForwarding(local, remote);
    }

    @Override
    public void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
        Forwarder forwarder = getForwarder();
        forwarder.stopLocalPortForwarding(local);
    }

    @Override
    public SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local)
            throws IOException {
        Forwarder forwarder = getForwarder();
        return forwarder.startRemotePortForwarding(remote, local);
    }

    @Override
    public void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        Forwarder forwarder = getForwarder();
        forwarder.stopRemotePortForwarding(remote);
    }

    @Override
    public SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        Forwarder forwarder = getForwarder();
        return forwarder.startDynamicPortForwarding(local);
    }

    @Override
    public void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        Forwarder forwarder = getForwarder();
        forwarder.stopDynamicPortForwarding(local);
    }

    @Override
    protected Forwarder getForwarder() {
        ConnectionService service = Objects.requireNonNull(getConnectionService(), "No connection service");
        return Objects.requireNonNull(service.getForwarder(), "No forwarder");
    }

    @Override
    protected String resolveAvailableSignaturesProposal(FactoryManager manager) {
        // the client does not have to provide keys for the available signatures
        ValidateUtils.checkTrue(manager == getFactoryManager(), "Mismatched factory manager instances");
        return NamedResource.getNames(getSignatureFactories());
    }

    @Override
    public void startService(String name, Buffer buffer) throws Exception {
        SessionDisconnectHandler handler = getSessionDisconnectHandler();
        if ((handler != null) && handler.handleUnsupportedServiceDisconnectReason(this,
                SshConstants.SSH_MSG_SERVICE_REQUEST, name, buffer)) {
            if (log.isDebugEnabled()) {
                log.debug("startService({}) ignore unknown service={} by handler", this, name);
            }
            return;
        }

        throw new IllegalStateException("Starting services is not supported on the client side: " + name);
    }

    @Override
    public ChannelShell createShellChannel(PtyChannelConfigurationHolder ptyConfig, Map<String, ?> env)
            throws IOException {
        if ((inCipher instanceof CipherNone) || (outCipher instanceof CipherNone)) {
            throw new IllegalStateException("Interactive channels are not supported with none cipher");
        }

        ChannelShell channel = new ChannelShell(ptyConfig, env);
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createShellChannel({}) created id={} - PTY={}", this, id, ptyConfig);
        }
        return channel;
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws Exception {
        List<String> ident = doReadIdentification(buffer, false);
        int numLines = GenericUtils.size(ident);
        serverVersion = (numLines <= 0) ? null : ident.remove(numLines - 1);
        if (serverVersion == null) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("readIdentification({}) Server version string: {}", this, serverVersion);
        }

        if (!SessionContext.isValidVersionPrefix(serverVersion)) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Unsupported protocol version: " + serverVersion);
        }

        signalExtraServerVersionInfo(serverVersion, ident);

        // Now that we have the server's identity reported see if have delayed any of our duties...
        if (!sendImmediateClientIdentification) {
            sendClientIdentification();
            // if client identification not sent then KEX-INIT was not sent either
            initializeKeyExchangePhase();
        } else if (!sendImmediateKexInit) {
            // if client identification sent, perhaps we delayed KEX-INIT
            initializeKeyExchangePhase();
        }

        return true;
    }

    protected void signalExtraServerVersionInfo(String version, List<String> lines) throws Exception {
        signalPeerIdentificationReceived(version, lines);

        if (GenericUtils.isEmpty(lines)) {
            return;
        }

        UserInteraction ui = getUserInteraction();
        try {
            if ((ui != null) && ui.isInteractionAllowed(this)) {
                ui.serverVersionInfo(this, lines);
            }
        } catch (Error e) {
            warn("signalExtraServerVersionInfo({})[{}] failed ({}) to consult interaction: {}",
                    this, version, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }
    }

    @Override
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws Exception {
        mergeProposals(clientProposal, proposal);
        return super.sendKexInit(proposal);
    }

    @Override
    protected void setKexSeed(byte... seed) {
        setClientKexData(seed);
    }

    @Override
    protected byte[] receiveKexInit(Buffer buffer) throws Exception {
        byte[] seed = super.receiveKexInit(buffer);
        /*
         * Check if the session has delayed its KEX-INIT until the server's one was received in order to support KEX
         * extension negotiation (RFC 8308).
         */
        if (kexState.compareAndSet(KexState.UNKNOWN, KexState.RUN)) {
            if (log.isDebugEnabled()) {
                log.debug("receiveKexInit({}) sending client proposal", this);
            }
            kexState.set(KexState.INIT);
            sendKexInit();
        }

        return seed;
    }

    @Override
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        mergeProposals(serverProposal, proposal);
        setServerKexData(seed);
    }

    @Override
    protected void checkKeys() throws IOException {
        ServerKeyVerifier serverKeyVerifier = Objects.requireNonNull(getServerKeyVerifier(), "No server key verifier");
        IoSession networkSession = getIoSession();
        SocketAddress remoteAddress = networkSession.getRemoteAddress();
        PublicKey serverKey = Objects.requireNonNull(getServerKey(), "No server key to verify");
        SshdSocketAddress targetServerAddress = getAttribute(ClientSessionCreator.TARGET_SERVER);
        if (targetServerAddress != null) {
            remoteAddress = targetServerAddress.toInetSocketAddress();
        }

        boolean verified = false;
        if (serverKey instanceof OpenSshCertificate) {
            // check if we trust the CA
            verified = serverKeyVerifier.verifyServerKey(this, remoteAddress, ((OpenSshCertificate) serverKey).getCaPubKey());
            if (log.isDebugEnabled()) {
                log.debug("checkCA({}) key={}-{}, verified={}",
                        this, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey), verified);
            }

            if (!verified) {
                // fallback to actual public host key
                serverKey = ((OpenSshCertificate) serverKey).getServerHostKey();
            }
        }

        if (!verified) {
            verified = serverKeyVerifier.verifyServerKey(this, remoteAddress, serverKey);
            if (log.isDebugEnabled()) {
                log.debug("checkKeys({}) key={}-{}, verified={}",
                        this, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey), verified);
            }
        }

        if (!verified) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "Server key did not validate");
        }
    }

    @Override
    public KeyExchangeFuture switchToNoneCipher() throws IOException {
        if (!(currentService instanceof AbstractConnectionService)
                || !GenericUtils.isEmpty(((AbstractConnectionService) currentService).getChannels())) {
            throw new IllegalStateException(
                    "The switch to the none cipher must be done immediately after authentication");
        }

        if (kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
            DefaultKeyExchangeFuture kexFuture = new DefaultKeyExchangeFuture(toString(), null);
            DefaultKeyExchangeFuture prev = kexFutureHolder.getAndSet(kexFuture);
            if (prev != null) {
                synchronized (prev) {
                    Object value = prev.getValue();
                    if (value == null) {
                        prev.setValue(new SshException("Switch to none cipher while previous KEX is ongoing"));
                    }
                }
            }

            String c2sEncServer;
            String s2cEncServer;
            synchronized (serverProposal) {
                c2sEncServer = serverProposal.get(KexProposalOption.C2SENC);
                s2cEncServer = serverProposal.get(KexProposalOption.S2CENC);
            }
            boolean c2sEncServerNone = BuiltinCiphers.Constants.isNoneCipherIncluded(c2sEncServer);
            boolean s2cEncServerNone = BuiltinCiphers.Constants.isNoneCipherIncluded(s2cEncServer);

            String c2sEncClient;
            String s2cEncClient;
            synchronized (clientProposal) {
                c2sEncClient = clientProposal.get(KexProposalOption.C2SENC);
                s2cEncClient = clientProposal.get(KexProposalOption.S2CENC);
            }

            boolean c2sEncClientNone = BuiltinCiphers.Constants.isNoneCipherIncluded(c2sEncClient);
            boolean s2cEncClientNone = BuiltinCiphers.Constants.isNoneCipherIncluded(s2cEncClient);

            if ((!c2sEncServerNone) || (!s2cEncServerNone)) {
                kexFuture.setValue(new SshException("Server does not support none cipher"));
            } else if ((!c2sEncClientNone) || (!s2cEncClientNone)) {
                kexFuture.setValue(new SshException("Client does not support none cipher"));
            } else {
                log.info("switchToNoneCipher({}) switching", this);

                Map<KexProposalOption, String> proposal = new EnumMap<>(KexProposalOption.class);
                synchronized (clientProposal) {
                    proposal.putAll(clientProposal);
                }

                proposal.put(KexProposalOption.C2SENC, BuiltinCiphers.Constants.NONE);
                proposal.put(KexProposalOption.S2CENC, BuiltinCiphers.Constants.NONE);

                try {
                    synchronized (kexState) {
                        byte[] seed = sendKexInit(proposal);
                        setKexSeed(seed);
                    }
                } catch (Exception e) {
                    GenericUtils.rethrowAsIoException(e);
                }
            }

            return Objects.requireNonNull(kexFutureHolder.get(), "No current KEX future");
        } else {
            throw new SshException("In flight key exchange");
        }
    }
}
