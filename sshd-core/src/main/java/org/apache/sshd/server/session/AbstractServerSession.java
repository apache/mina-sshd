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
import java.security.KeyPair;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.UserAuth;
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
    private List<NamedFactory<UserAuth>> userAuthFactories;

    protected AbstractServerSession(ServerFactoryManager factoryManager, IoSession ioSession) {
        super(true, factoryManager, ioSession);
    }

    @Override
    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager) super.getFactoryManager();
    }

    @Override
    public ServerProxyAcceptor getServerProxyAcceptor() {
        return resolveEffectiveProvider(ServerProxyAcceptor.class, proxyAcceptor, getFactoryManager().getServerProxyAcceptor());
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
        return resolveEffectiveProvider(PasswordAuthenticator.class, passwordAuthenticator, getFactoryManager().getPasswordAuthenticator());
    }

    @Override
    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public PublickeyAuthenticator getPublickeyAuthenticator() {
        return resolveEffectiveProvider(PublickeyAuthenticator.class, publickeyAuthenticator, getFactoryManager().getPublickeyAuthenticator());
    }

    @Override
    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
        return resolveEffectiveProvider(KeyboardInteractiveAuthenticator.class, interactiveAuthenticator, getFactoryManager().getKeyboardInteractiveAuthenticator());
    }

    @Override
    public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
        this.interactiveAuthenticator = interactiveAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public GSSAuthenticator getGSSAuthenticator() {
        return resolveEffectiveProvider(GSSAuthenticator.class, gssAuthenticator, getFactoryManager().getGSSAuthenticator());
    }

    @Override
    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
        this.gssAuthenticator = gssAuthenticator; // OK if null - inherit from parent
    }

    @Override
    public HostBasedAuthenticator getHostBasedAuthenticator() {
        return resolveEffectiveProvider(HostBasedAuthenticator.class, hostBasedAuthenticator, getFactoryManager().getHostBasedAuthenticator());
    }

    @Override
    public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
        this.hostBasedAuthenticator = hostBasedAuthenticator;
    }

    @Override
    public List<NamedFactory<UserAuth>> getUserAuthFactories() {
        return resolveEffectiveFactories(UserAuth.class, userAuthFactories, getFactoryManager().getUserAuthFactories());
    }

    @Override
    public void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories) {
        this.userAuthFactories = userAuthFactories; // OK if null/empty - inherit from parent
    }

    /**
     * Sends the server identification + any extra header lines
     *
     * @param headerLines Extra header lines to be prepended to the actual
     * identification string - ignored if {@code null}/empty
     * @return An {@link IoWriteFuture} that can be used to be notified of
     * identification data being written successfully or failing
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2</A>
     */
    protected IoWriteFuture sendServerIdentification(String ... headerLines) {
        serverVersion = resolveIdentificationString(ServerFactoryManager.SERVER_IDENTIFICATION);

        String ident = serverVersion;
        if (GenericUtils.length(headerLines) > 0) {
            ident = GenericUtils.join(headerLines, "\r\n") + "\r\n" + serverVersion;
        }
        return sendIdentification(ident);
    }

    @Override
    protected void checkKeys() {
        // nothing
    }

    @Override
    public void startService(String name) throws Exception {
        currentService = ServiceFactory.Utils.create(
                        getFactoryManager().getServiceFactories(),
                        ValidateUtils.checkNotNullAndNotEmpty(name, "No service name"),
                        this);
        /*
         * According to RFC4253:
         *
         *      If the server rejects the service request, it SHOULD send an
         *      appropriate SSH_MSG_DISCONNECT message and MUST disconnect.
         */
        if (currentService == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Unknown service: " + name);
        }
    }

    @Override
    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        super.handleServiceAccept(serviceName, buffer);
        // TODO: can services be initiated by the server-side ?
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Unsupported packet: SSH_MSG_SERVICE_ACCEPT for " + serviceName);
    }

    @Override
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws IOException {
        mergeProposals(serverProposal, proposal);
        return super.sendKexInit(proposal);
    }

    @Override
    protected void setKexSeed(byte... seed) {
        i_s = ValidateUtils.checkNotNullAndNotEmpty(seed, "No KEX seed");
    }

    @Override
    protected String resolveAvailableSignaturesProposal(FactoryManager proposedManager) {
        /*
         * Make sure we can provide key(s) for the available signatures
         */
        ValidateUtils.checkTrue(proposedManager == getFactoryManager(), "Mismatched signatures proposed factory manager");

        KeyPairProvider kpp = getKeyPairProvider();
        Collection<String> supported = NamedResource.Utils.getNameList(getSignatureFactories());
        Iterable<String> provided;
        try {
            provided = (kpp == null) ? null : kpp.getKeyTypes();
        } catch (Error e) {
            log.warn("resolveAvailableSignaturesProposal({}) failed ({}) to get key types: {}",
                     this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("resolveAvailableSignaturesProposal(" + this + ") fetch key types failure details", e);
            }

            throw new RuntimeSshException(e);
        }

        if ((provided == null) || GenericUtils.isEmpty(supported)) {
            return resolveEmptySignaturesProposal(supported, provided);
        }

        StringBuilder resolveKeys = null;
        for (String keyType : provided) {
            if (!supported.contains(keyType)) {
                if (log.isDebugEnabled()) {
                    log.debug("resolveAvailableSignaturesProposal({})[{}] {} not in suppored list: {}",
                              this, provided, keyType, supported);
                }
                continue;
            }

            if (resolveKeys == null) {
                resolveKeys = new StringBuilder(supported.size() * 16 /* ecdsa-sha2-xxxx */);
            }

            if (resolveKeys.length() > 0) {
                resolveKeys.append(',');
            }

            resolveKeys.append(keyType);
        }

        if (GenericUtils.isEmpty(resolveKeys)) {
            return resolveEmptySignaturesProposal(supported, provided);
        } else {
            return resolveKeys.toString();
        }
    }

    /**
     * Called by {@link #resolveAvailableSignaturesProposal(FactoryManager)}
     * if none of the provided keys is supported - last chance for the derived
     * implementation to do something
     *
     * @param supported The supported key types - may be {@code null}/empty
     * @param provided  The available signature types - may be {@code null}/empty
     * @return The resolved proposal - {@code null} by default
     */
    protected String resolveEmptySignaturesProposal(Iterable<String> supported, Iterable<String> provided) {
        if (log.isDebugEnabled()) {
            log.debug("resolveEmptySignaturesProposal({})[{}] none of the keys appears in supported list: {}",
                      this, provided, supported);
        }
        return null;
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws IOException {
        ServerProxyAcceptor acceptor = getServerProxyAcceptor();
        int rpos = buffer.rpos();
        if (acceptor != null) {
            try {
                boolean completed = acceptor.acceptServerProxyMetadata(this, buffer);
                if (!completed) {
                    buffer.rpos(rpos);  // restore original buffer position
                    return false;   // more data required
                }
            } catch (Throwable t) {
                log.warn("readIdentification({}) failed ({}) to accept proxy metadata: {}",
                         this, t.getClass().getSimpleName(), t.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("readIdentification(" + this + ") proxy metadata acceptance failure details", t);
                }

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
            buffer.rpos(rpos);  // restore original buffer position
            return false;   // more data required
        }

        if (log.isDebugEnabled()) {
            log.debug("readIdentification({}) client version string: {}", this, clientVersion);
        }

        String errorMessage = null;
        if ((errorMessage == null) && (!clientVersion.startsWith(DEFAULT_SSH_VERSION_PREFIX))) {
            errorMessage = "Unsupported protocol version: " + clientVersion;
        }

        /*
         * NOTE: because of the way that "doReadIdentification" works we are
         * assured that there are no extra lines beyond the version one, but
         * we check this nevertheless
         */
        if ((errorMessage == null) && (numLines > 1)) {
            errorMessage = "Unexpected extra " + (numLines - 1) + " lines from client=" + clientVersion;
        }

        if (GenericUtils.length(errorMessage) > 0) {
            ioSession.write(new ByteArrayBuffer((errorMessage + "\n").getBytes(StandardCharsets.UTF_8)))
                     .addListener(new SshFutureListener<IoWriteFuture>() {
                         @Override
                         public void operationComplete(IoWriteFuture future) {
                             close(true);
                         }
                     });
            throw new SshException(errorMessage);
        }

        kexState.set(KexState.INIT);
        sendKexInit();
        return true;
    }

    @Override
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        mergeProposals(clientProposal, proposal);
        i_c = seed;
    }

    @Override
    public KeyPair getHostKey() {
        String keyType = getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
        KeyPairProvider provider = ValidateUtils.checkNotNull(getKeyPairProvider(), "No host keys provider");
        try {
            return provider.loadKey(keyType);
        } catch (Error e) {
            log.warn("getHostKey({}) failed ({}) to load key of type={}: {}",
                     this, e.getClass().getSimpleName(), keyType, e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("getHostKey(" + this + ") " + keyType + " key load failure details", e);
            }

            throw new RuntimeSshException(e);
        }
    }

    @Override
    public int getActiveSessionCountForUser(String userName) {
        if (GenericUtils.isEmpty(userName)) {
            return 0;
        }

        IoService service = ioSession.getService();
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
            if ((!GenericUtils.isEmpty(sessionUser)) && Objects.equals(sessionUser, userName)) {
                totalCount++;
            }
        }

        return totalCount;
    }

    /**
     * Returns the session id.
     *
     * @return The session id.
     */
    public long getId() {
        return ioSession.getId();
    }
}
