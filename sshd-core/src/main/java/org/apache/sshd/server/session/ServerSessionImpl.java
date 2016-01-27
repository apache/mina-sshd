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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolverUtils;
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
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerFactoryManager;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerSessionImpl extends AbstractServerSession {
    public ServerSessionImpl(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(server, ioSession);

        if (log.isDebugEnabled()) {
            log.debug("Server session created {}", ioSession);
        }

        // Inform the listener of the newly created session
        SessionListener listener = getSessionListenerProxy();
        try {
            listener.sessionCreated(this);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            if (e instanceof Exception) {
                throw (Exception) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }

        sendServerIdentification();
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
    protected void serviceAccept() throws IOException {
        // TODO: can services be initiated by the server-side ?
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Unsupported packet: SSH_MSG_SERVICE_ACCEPT");
    }

    protected void sendServerIdentification() {
        FactoryManager manager = getFactoryManager();
        String ident = PropertyResolverUtils.getString(manager, ServerFactoryManager.SERVER_IDENTIFICATION);
        if (GenericUtils.isEmpty(ident)) {
            serverVersion = DEFAULT_SSH_VERSION_PREFIX + manager.getVersion();
        } else {
            serverVersion = DEFAULT_SSH_VERSION_PREFIX + ident;
        }
        sendIdentification(serverVersion);
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
        clientVersion = doReadIdentification(buffer, true);
        if (GenericUtils.isEmpty(clientVersion)) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("readIdentification({}) client version string: {}", this, clientVersion);
        }

        if (!clientVersion.startsWith(DEFAULT_SSH_VERSION_PREFIX)) {
            String msg = "Unsupported protocol version: " + clientVersion;
            ioSession.write(new ByteArrayBuffer((msg + "\n").getBytes(StandardCharsets.UTF_8))).addListener(new SshFutureListener<IoWriteFuture>() {
                @Override
                public void operationComplete(IoWriteFuture future) {
                    close(true);
                }
            });
            throw new SshException(msg);
        } else {
            kexState.set(KexState.INIT);
            sendKexInit();
        }
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
