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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractClientSession {
    private AuthFuture authFuture;

    /**
     * For clients to store their own metadata
     */
    private Map<Object, Object> metadataMap = new HashMap<>();

    // TODO: clean service support a bit
    private boolean initialServiceRequestSent;
    private ServiceFactory currentServiceFactory;
    private Service nextService;
    private ServiceFactory nextServiceFactory;

    public ClientSessionImpl(ClientFactoryManager client, IoSession session) throws Exception {
        super(client, session);
        if (log.isDebugEnabled()) {
            log.debug("Client session created: {}", session);
        }
        // Need to set the initial service early as calling code likes to start trying to
        // manipulate it before the connection has even been established.  For instance, to
        // set the authPassword.
        List<ServiceFactory> factories = client.getServiceFactories();
        int numFactories = GenericUtils.size(factories);
        ValidateUtils.checkTrue((numFactories > 0) && (numFactories <= 2), "One or two services must be configured: %d", numFactories);

        currentServiceFactory = factories.get(0);
        currentService = currentServiceFactory.create(this);
        if (numFactories > 1) {
            nextServiceFactory = factories.get(1);
            nextService = nextServiceFactory.create(this);
        } else {
            nextServiceFactory = null;
        }

        authFuture = new DefaultAuthFuture(lock);
        authFuture.setAuthed(false);

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

        sendClientIdentification();
        kexState.set(KexState.INIT);
        sendKexInit();
    }

    @Override
    protected List<Service> getServices() {
        if (nextService != null) {
            return Arrays.asList(currentService, nextService);
        } else {
            return super.getServices();
        }
    }

    @Override
    public AuthFuture auth() throws IOException {
        if (username == null) {
            throw new IllegalStateException("No username specified when the session was created");
        }

        ClientUserAuthService authService = getUserAuthService();
        synchronized (lock) {
            String serviceName = nextServiceName();
            authFuture = ValidateUtils.checkNotNull(authService.auth(serviceName), "No auth future generated by service=%s", serviceName);
            return authFuture;
        }
    }

    @Override
    public void exceptionCaught(Throwable t) {
        signalAuthFailure(authFuture, t);
        super.exceptionCaught(t);
    }

    @Override
    protected void preClose() {
        signalAuthFailure(authFuture, new SshException("Session is being closed"));
        super.preClose();
    }

    @Override
    protected void handleDisconnect(int code, String msg, String lang, Buffer buffer) throws Exception {
        signalAuthFailure(authFuture, new SshException(code, msg));
        super.handleDisconnect(code, msg, lang, buffer);
    }

    protected void signalAuthFailure(AuthFuture future, Throwable t) {
        boolean signalled = false;
        synchronized (lock) {
            if ((future != null) && (!future.isDone())) {
                future.setException(t);
                signalled = true;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("signalAuthFailure({}) type={}, signalled={}, message=\"{}\"",
                      this, t.getClass().getSimpleName(), signalled, t.getMessage());
        }
    }

    protected String nextServiceName() {
        synchronized (lock) {
            return nextServiceFactory.getName();
        }
    }

    public void switchToNextService() throws IOException {
        synchronized (lock) {
            if (nextService == null) {
                throw new IllegalStateException("No service available");
            }
            currentServiceFactory = nextServiceFactory;
            currentService = nextService;
            nextServiceFactory = null;
            nextService = null;
            currentService.start();
        }
    }

    @Override
    public KeyExchangeFuture switchToNoneCipher() throws IOException {
        if (!(currentService instanceof AbstractConnectionService<?>)
                || !GenericUtils.isEmpty(((AbstractConnectionService<?>) currentService).getChannels())) {
            throw new IllegalStateException("The switch to the none cipher must be done immediately after authentication");
        }

        if (kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
            DefaultKeyExchangeFuture kexFuture = new DefaultKeyExchangeFuture(null);
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

                Map<KexProposalOption, String> proposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
                synchronized (clientProposal) {
                    proposal.putAll(clientProposal);
                }

                proposal.put(KexProposalOption.C2SENC, BuiltinCiphers.Constants.NONE);
                proposal.put(KexProposalOption.S2CENC, BuiltinCiphers.Constants.NONE);

                byte[] seed = sendKexInit(proposal);
                setKexSeed(seed);
            }

            return ValidateUtils.checkNotNull(kexFutureHolder.get(), "No current KEX future");
        } else {
            throw new SshException("In flight key exchange");
        }
    }

    @Override
    public ChannelShell createShellChannel() throws IOException {
        if ((inCipher instanceof CipherNone) || (outCipher instanceof CipherNone)) {
            throw new IllegalStateException("Interactive channels are not supported with none cipher");
        }
        ChannelShell channel = new ChannelShell();
        ConnectionService service = getConnectionService();
        int id = service.registerChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("createShellChannel({}) created id={}", this, id);
        }
        return channel;
    }

    @Override
    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            super.handleMessage(buffer);
        }
    }

    @Override
    public Set<ClientSessionEvent> waitFor(Collection<ClientSessionEvent> mask, long timeout) {
        ValidateUtils.checkNotNull(mask, "No mask specified");
        long t = 0L;
        synchronized (lock) {
            for (Set<ClientSessionEvent> cond = EnumSet.noneOf(ClientSessionEvent.class);; cond.clear()) {
                if (closeFuture.isClosed()) {
                    cond.add(ClientSessionEvent.CLOSED);
                }
                if (authed) { // authFuture.isSuccess()
                    cond.add(ClientSessionEvent.AUTHED);
                }
                if (KexState.DONE.equals(kexState.get()) && authFuture.isFailure()) {
                    cond.add(ClientSessionEvent.WAIT_AUTH);
                }

                boolean nothingInCommon = Collections.disjoint(cond, mask);
                if (!nothingInCommon) {
                    if (log.isTraceEnabled()) {
                        log.trace("waitFor(}{}) call return mask={}, cond={}", this, mask, cond);
                    }
                    return cond;
                }

                if (timeout > 0L) {
                    if (t == 0L) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0L) {
                            if (log.isTraceEnabled()) {
                                log.trace("WaitFor({}) call timeout mask={}", this, mask);
                            }
                            cond.add(ClientSessionEvent.TIMEOUT);
                            return cond;
                        }
                    }
                }

                if (log.isTraceEnabled()) {
                    log.trace("waitFor({}) Waiting {} millis for lock on mask={}, cond={}", this, timeout, mask, cond);
                }

                long nanoStart = System.nanoTime();
                try {
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }

                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("waitFor({}) Lock notified after {} nanos", this, nanoDuration);
                    }
                } catch (InterruptedException e) {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (log.isTraceEnabled()) {
                        log.trace("waitFor({}) mask={} - ignoring interrupted exception after {} nanos", this, mask, nanoDuration);
                    }
                }
            }
        }
    }

    @Override
    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer, false);
        if (serverVersion == null) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("readIdentification({}) Server version string: {}", this, serverVersion);
        }

        if (!(serverVersion.startsWith(DEFAULT_SSH_VERSION_PREFIX) || serverVersion.startsWith("SSH-1.99-"))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Unsupported protocol version: " + serverVersion);
        }

        return true;
    }

    protected void sendClientIdentification() {
        FactoryManager manager = getFactoryManager();
        clientVersion = DEFAULT_SSH_VERSION_PREFIX + manager.getVersion();
        sendIdentification(clientVersion);
    }

    @Override
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws IOException {
        mergeProposals(clientProposal, proposal);
        return super.sendKexInit(proposal);
    }

    @Override
    protected void setKexSeed(byte... seed) {
        i_c = ValidateUtils.checkNotNullAndNotEmpty(seed, "No KEX seed");
    }

    @Override
    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        mergeProposals(serverProposal, proposal);
        i_s = seed;
    }

    @Override
    protected void checkKeys() throws SshException {
        ServerKeyVerifier serverKeyVerifier = ValidateUtils.checkNotNull(getServerKeyVerifier(), "No server key verifier");
        SocketAddress remoteAddress = ioSession.getRemoteAddress();

        if (!serverKeyVerifier.verifyServerKey(this, remoteAddress, kex.getServerKey())) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "Server key did not validate");
        }
    }

    @Override
    protected void sendSessionEvent(SessionListener.Event event) throws IOException {
        if (SessionListener.Event.KeyEstablished.equals(event)) {
            sendInitialServiceRequest();
        }
        synchronized (lock) {
            lock.notifyAll();
        }
        super.sendSessionEvent(event);
    }

    protected void sendInitialServiceRequest() throws IOException {
        if (initialServiceRequestSent) {
            return;
        }
        initialServiceRequestSent = true;
        String serviceName = currentServiceFactory.getName();
        if (log.isDebugEnabled()) {
            log.debug("sendInitialServiceRequest({}) Send SSH_MSG_SERVICE_REQUEST for {}", this, serviceName);
        }

        Buffer request = createBuffer(SshConstants.SSH_MSG_SERVICE_REQUEST, serviceName.length() + Byte.SIZE);
        request.putString(serviceName);
        writePacket(request);
        // Assuming that MINA-SSHD only implements "explicit server authentication" it is permissible
        // for the client's service to start sending data before the service-accept has been received.
        // If "implicit authentication" were to ever be supported, then this would need to be
        // called after service-accept comes back.  See SSH-TRANSPORT.
        currentService.start();
    }

    @Override
    public Map<Object, Object> getMetadataMap() {
        return metadataMap;
    }
}
