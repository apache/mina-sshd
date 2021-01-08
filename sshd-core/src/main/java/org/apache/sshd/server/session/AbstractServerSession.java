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

package org.apache.sshd.server.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.AbstractUserAuthServiceFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexFactoryManager;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.KexPhase;
import org.apache.sshd.common.keyprovider.HostKeyCertificateProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.WelcomeBannerPhase;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;

/**
 * Provides default implementations for {@link ServerSession} related methods
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractServerSession extends AbstractSession implements ServerSession {
    private ServerProxyAcceptor proxyAcceptor;
    private SocketAddress clientAddress;
    private PasswordAuthenticator passwordAuthenticator;
    private PublickeyAuthenticator publickeyAuthenticator;
    private KeyboardInteractiveAuthenticator interactiveAuthenticator;
    private GSSAuthenticator gssAuthenticator;
    private HostBasedAuthenticator hostBasedAuthenticator;
    private List<UserAuthFactory> userAuthFactories;
    private KeyPairProvider keyPairProvider;
    private HostKeyCertificateProvider hostKeyCertificateProvider;

    protected AbstractServerSession(ServerFactoryManager factoryManager, IoSession ioSession) {
        super(true, factoryManager, ioSession);
    }

    @Override
    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager) super.getFactoryManager();
    }

    @Override
    public ServerProxyAcceptor getServerProxyAcceptor() {
        return resolveEffectiveProvider(
                ServerProxyAcceptor.class, proxyAcceptor, getFactoryManager().getServerProxyAcceptor());
    }

    @Override
    public void setServerProxyAcceptor(ServerProxyAcceptor proxyAcceptor) {
        this.proxyAcceptor = proxyAcceptor;
    }

    @Override
    public SocketAddress getClientAddress() {
        return resolvePeerAddress(clientAddress);
    }

    public void setClientAddress(SocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    @Override
    public PasswordAuthenticator getPasswordAuthenticator() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(
                PasswordAuthenticator.class, passwordAuthenticator, manager.getPasswordAuthenticator());
    }

    @Override
    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public PublickeyAuthenticator getPublickeyAuthenticator() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(
                PublickeyAuthenticator.class, publickeyAuthenticator, manager.getPublickeyAuthenticator());
    }

    @Override
    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(
                KeyboardInteractiveAuthenticator.class, interactiveAuthenticator,
                manager.getKeyboardInteractiveAuthenticator());
    }

    @Override
    public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
        this.interactiveAuthenticator = interactiveAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public GSSAuthenticator getGSSAuthenticator() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(
                GSSAuthenticator.class, gssAuthenticator, manager.getGSSAuthenticator());
    }

    @Override
    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
        this.gssAuthenticator = gssAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public HostBasedAuthenticator getHostBasedAuthenticator() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(
                HostBasedAuthenticator.class, hostBasedAuthenticator, manager.getHostBasedAuthenticator());
    }

    @Override
    public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
        this.hostBasedAuthenticator = hostBasedAuthenticator;
    }

    @Override
    public List<UserAuthFactory> getUserAuthFactories() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveFactories(userAuthFactories, manager.getUserAuthFactories());
    }

    @Override
    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories = userAuthFactories; // OK if null/empty - inherit from parent
    }

    @Override
    public KeyPairProvider getKeyPairProvider() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveProvider(KeyPairProvider.class, keyPairProvider,
                (parent == null) ? null : ((ServerAuthenticationManager) parent).getKeyPairProvider());
    }

    @Override
    public HostKeyCertificateProvider getHostKeyCertificateProvider() {
        ServerFactoryManager manager = getFactoryManager();
        return resolveEffectiveProvider(HostKeyCertificateProvider.class,
                hostKeyCertificateProvider, manager.getHostKeyCertificateProvider());
    }

    @Override
    public void setHostKeyCertificateProvider(HostKeyCertificateProvider hostKeyCertificateProvider) {
        this.hostKeyCertificateProvider = hostKeyCertificateProvider;
    }

    @Override
    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    /**
     * Sends the server identification + any extra header lines
     *
     * @param  headerLines Extra header lines to be prepended to the actual identification string - ignored if
     *                     {@code null}/empty
     * @return             An {@link IoWriteFuture} that can be used to be notified of identification data being written
     *                     successfully or failing
     * @throws Exception   If failed to send identification
     * @see                <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>
     */
    protected IoWriteFuture sendServerIdentification(List<String> headerLines) throws Exception {
        serverVersion = resolveIdentificationString(CoreModuleProperties.SERVER_IDENTIFICATION.getName());
        signalSendIdentification(serverVersion, headerLines);
        return sendIdentification(serverVersion, headerLines);
    }

    @Override
    protected void checkKeys() {
        // nothing
    }

    @Override
    protected boolean handleServiceRequest(String serviceName, Buffer buffer) throws Exception {
        boolean started = super.handleServiceRequest(serviceName, buffer);
        if (!started) {
            return false;
        }

        if (AbstractUserAuthServiceFactory.DEFAULT_NAME.equals(serviceName)
                && (currentService instanceof ServerUserAuthService)) {
            ServerUserAuthService authService = (ServerUserAuthService) currentService;
            if (WelcomeBannerPhase.IMMEDIATE.equals(authService.getWelcomePhase())) {
                authService.sendWelcomeBanner(this);
            }
        }

        return true;
    }

    @Override
    public void startService(String name, Buffer buffer) throws Exception {
        FactoryManager factoryManager = getFactoryManager();
        currentService = ServiceFactory.create(
                factoryManager.getServiceFactories(),
                ValidateUtils.checkNotNullAndNotEmpty(name, "No service name specified"),
                this);
        /*
         * According to RFC4253:
         *
         * If the server rejects the service request, it SHOULD send an appropriate SSH_MSG_DISCONNECT message and MUST
         * disconnect.
         */
        if (currentService == null) {
            try {
                SessionDisconnectHandler handler = getSessionDisconnectHandler();
                if ((handler != null)
                        && handler.handleUnsupportedServiceDisconnectReason(
                                this, SshConstants.SSH_MSG_SERVICE_REQUEST, name, buffer)) {
                    if (log.isDebugEnabled()) {
                        log.debug("startService({}) ignore unknown service={} by handler", this, name);
                    }
                    return;
                }
            } catch (IOException | RuntimeException e) {
                warn("startService({})[{}] failed ({}) to invoke disconnect handler: {}",
                        this, name, e.getClass().getSimpleName(), e.getMessage(), e);
            }

            throw new SshException(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Unknown service: " + name);
        }
    }

    @Override
    public IoWriteFuture signalAuthenticationSuccess(
            String username, String authService, Buffer buffer)
            throws Exception {
        KexState curState = kexState.get();
        if (!KexState.DONE.equals(curState)) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                    "Authentication success signalled though KEX state=" + curState);
        }

        /*
         * According to https://tools.ietf.org/html/rfc8308#section-2.4
         *
         * If a server sends SSH_MSG_EXT_INFO, it MAY send it at zero, one, or both of the following opportunities:
         *
         * ...
         *
         * + Immediately preceding the server's SSH_MSG_USERAUTH_SUCCESS
         */
        KexExtensionHandler extHandler = getKexExtensionHandler();
        if ((extHandler != null) && extHandler.isKexExtensionsAvailable(this, AvailabilityPhase.AUTHOK)) {
            extHandler.sendKexExtensions(this, KexPhase.AUTHOK);
        }

        Buffer response = createBuffer(SshConstants.SSH_MSG_USERAUTH_SUCCESS, Byte.SIZE);
        IoWriteFuture future;
        IoSession networkSession = getIoSession();
        synchronized (encodeLock) {
            Buffer packet = resolveOutputPacket(response);

            setUsername(username);
            // must be AFTER the USERAUTH-SUCCESS packet created in case delayed compression is used
            setAuthenticated();
            startService(authService, buffer);

            // Now we can inform the peer that authentication is successful
            future = networkSession.writeBuffer(packet);
        }

        resetIdleTimeout();
        log.info("Session {}@{} authenticated", username, networkSession.getRemoteAddress());
        return future;
    }

    @Override
    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        super.handleServiceAccept(serviceName, buffer);

        try {
            SessionDisconnectHandler handler = getSessionDisconnectHandler();
            if ((handler != null)
                    && handler.handleUnsupportedServiceDisconnectReason(
                            this, SshConstants.SSH_MSG_SERVICE_ACCEPT, serviceName, buffer)) {
                if (log.isDebugEnabled()) {
                    log.debug("handleServiceAccept({}) ignore unknown service={} by handler", this, serviceName);
                }
                return;
            }
        } catch (IOException | RuntimeException e) {
            warn("handleServiceAccept({}) failed ({}) to invoke disconnect handler of unknown service={}: {}",
                    this, e.getClass().getSimpleName(), serviceName, e.getMessage(), e);
        }

        // TODO: can services be initiated by the server-side ?
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                "Unsupported packet: SSH_MSG_SERVICE_ACCEPT for " + serviceName);
    }

    @Override
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws Exception {
        mergeProposals(serverProposal, proposal);
        return super.sendKexInit(proposal);
    }

    @Override
    protected void setKexSeed(byte... seed) {
        setServerKexData(seed);
    }

    @Override
    protected String resolveAvailableSignaturesProposal(FactoryManager proposedManager)
            throws IOException, GeneralSecurityException {
        /*
         * Make sure we can provide key(s) for the available signatures
         */
        ValidateUtils.checkTrue(proposedManager == getFactoryManager(),
                "Mismatched signatures proposed factory manager");

        KeyPairProvider kpp = getKeyPairProvider();
        Collection<String> provided = null;
        try {
            if (kpp != null) {
                provided = GenericUtils.stream(kpp.getKeyTypes(this)).collect(Collectors.toSet());

                HostKeyCertificateProvider hostKeyCertificateProvider = getHostKeyCertificateProvider();
                if (hostKeyCertificateProvider != null) {
                    Iterable<OpenSshCertificate> certificates = hostKeyCertificateProvider.loadCertificates(this);
                    for (OpenSshCertificate certificate : certificates) {
                        // Add the certificate alg only if the corresponding keyPair type is available
                        String rawKeyType = certificate.getRawKeyType();
                        if (provided.contains(rawKeyType)) {
                            provided.add(certificate.getKeyType());
                        } else {
                            log.info(
                                    "resolveAvailableSignaturesProposal({}) No private key of type={} available in provided certificate",
                                    this, rawKeyType);
                        }
                    }
                }
            }
        } catch (Error e) {
            warn("resolveAvailableSignaturesProposal({}) failed ({}) to get key types: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);

            throw new RuntimeSshException(e);
        }

        Collection<String> available = NamedResource.getNameList(getSignatureFactories());
        if ((provided == null) || GenericUtils.isEmpty(available)) {
            return resolveEmptySignaturesProposal(available, provided);
        }

        Collection<String> supported = SignatureFactory.resolveSignatureFactoryNamesProposal(provided, available);
        if (GenericUtils.isEmpty(supported)) {
            return resolveEmptySignaturesProposal(available, provided);
        } else {
            return GenericUtils.join(supported, ',');
        }
    }

    /**
     * Called by {@link #resolveAvailableSignaturesProposal(FactoryManager)} if none of the provided keys is supported -
     * last chance for the derived implementation to do something
     *
     * @param  supported The supported key types - may be {@code null}/empty
     * @param  provided  The available signature types - may be {@code null}/empty
     * @return           The resolved proposal - {@code null} by default
     */
    protected String resolveEmptySignaturesProposal(
            Iterable<String> supported, Iterable<String> provided) {
        if (log.isDebugEnabled()) {
            log.debug("resolveEmptySignaturesProposal({})[{}] none of the keys appears in supported list: {}",
                    this, provided, supported);
        }
        return null;
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws Exception {
        ServerProxyAcceptor acceptor = getServerProxyAcceptor();
        int rpos = buffer.rpos();
        boolean debugEnabled = log.isDebugEnabled();
        if (acceptor != null) {
            try {
                boolean completed = acceptor.acceptServerProxyMetadata(this, buffer);
                if (!completed) {
                    buffer.rpos(rpos); // restore original buffer position
                    return false; // more data required
                }
            } catch (Throwable t) {
                warn("readIdentification({}) failed ({}) to accept proxy metadata: {}",
                        this, t.getClass().getSimpleName(), t.getMessage(), t);

                if (t instanceof IOException) {
                    throw (IOException) t;
                } else {
                    throw new SshException(t);
                }
            }
        }

        List<String> ident = doReadIdentification(buffer, true);
        int numLines = GenericUtils.size(ident);
        clientVersion = (numLines <= 0) ? null : ident.remove(numLines - 1);
        if (GenericUtils.isEmpty(clientVersion)) {
            buffer.rpos(rpos); // restore original buffer position
            return false; // more data required
        }

        if (debugEnabled) {
            log.debug("readIdentification({}) client version string: {}", this, clientVersion);
        }

        IOException err;
        if (SessionContext.isValidVersionPrefix(clientVersion)) {
            /*
             * NOTE: because of the way that "doReadIdentification" works we are assured that there are no extra lines
             * beyond the version one, but we check this nevertheless
             */
            err = (numLines > 1)
                    ? new SshException(
                            SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                            "Unexpected extra " + (numLines - 1) + " lines from client=" + clientVersion)
                    : null;
        } else {
            err = new SshException(
                    SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Unsupported protocol version: " + clientVersion);
        }

        if (err != null) {
            IoSession networkSession = getIoSession();
            networkSession.writeBuffer(
                    new ByteArrayBuffer((err.getMessage() + "\n").getBytes(StandardCharsets.UTF_8)))
                    .addListener(future -> close(true));
            throw err;
        }

        signalPeerIdentificationReceived(clientVersion, ident);

        kexState.set(KexState.INIT);
        sendKexInit();
        return true;
    }

    @Override
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed)
            throws IOException {
        mergeProposals(clientProposal, proposal);
        setClientKexData(seed);
    }

    @Override
    public KeyPair getHostKey() {
        String proposedKey = getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
        String keyType = KeyUtils.getCanonicalKeyType(proposedKey);
        if (GenericUtils.isEmpty(keyType)) {
            return null;    // OK if not negotiated yet
        }

        KeyPairProvider provider = Objects.requireNonNull(getKeyPairProvider(), "No host keys provider");
        try {
            HostKeyCertificateProvider hostKeyCertificateProvider = getHostKeyCertificateProvider();
            if (hostKeyCertificateProvider != null) {
                OpenSshCertificate publicKey = hostKeyCertificateProvider.loadCertificate(this, keyType);
                if (publicKey != null) {
                    String rawKeyType = publicKey.getRawKeyType();

                    if (log.isDebugEnabled()) {
                        log.debug("getHostKey({}) using certified key {}/{} with ID={}",
                                this, keyType, rawKeyType, publicKey.getId());
                    }

                    KeyPair keyPair = provider.loadKey(this, rawKeyType);
                    ValidateUtils.checkNotNull(keyPair, "No certified private key of type=%s available", rawKeyType);
                    return new KeyPair(publicKey, keyPair.getPrivate());
                }
            }

            return provider.loadKey(this, keyType);
        } catch (IOException | GeneralSecurityException | Error e) {
            warn("getHostKey({}) failed ({}) to load key of type={}[{}]: {}",
                    this, e.getClass().getSimpleName(), proposedKey, keyType, e.getMessage(), e);

            throw new RuntimeSshException(e);
        }
    }

    @Override
    public int getActiveSessionCountForUser(String userName) {
        if (GenericUtils.isEmpty(userName)) {
            return 0;
        }

        IoSession networkSession = getIoSession();
        IoService service = networkSession.getService();
        Map<?, IoSession> sessionsMap = service.getManagedSessions();
        if (GenericUtils.isEmpty(sessionsMap)) {
            return 0;
        }

        int totalCount = 0;
        for (IoSession is : sessionsMap.values()) {
            ServerSession session = (ServerSession) getSession(is, true);
            if (session == null) {
                continue;
            }

            String sessionUser = session.getUsername();
            if ((!GenericUtils.isEmpty(sessionUser))
                    && Objects.equals(sessionUser, userName)) {
                totalCount++;
            }
        }

        return totalCount;
    }

    /**
     * @return The underlying {@link IoSession} id.
     */
    public long getId() {
        IoSession networkSession = getIoSession();
        return networkSession.getId();
    }

    @Override
    protected ConnectionService getConnectionService() {
        return (this.currentService instanceof ConnectionService)
                ? (ConnectionService) this.currentService
                : null;
    }
}
