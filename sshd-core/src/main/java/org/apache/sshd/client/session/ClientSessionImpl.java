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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.helpers.CurrentService;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * The default implementation of a {@link ClientSession}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractClientSession {

    /**
     * The authentication future created by the last call to {@link #auth()}; {@code null} before the first call to
     * {@link #auth()}.
     *
     * Volatile because of unsynchronized access in {@link #updateCurrentSessionState(Collection)}.
     */
    private volatile AuthFuture authFuture;

    private final AtomicReference<Throwable> beforeAuthErrorHolder = new AtomicReference<>();
    /** Also guards setting an earlyError and the authFuture together. */
    private final AtomicReference<Throwable> authErrorHolder = new AtomicReference<>();

    private final AtomicBoolean initialServiceRequestSent = new AtomicBoolean();

    /**
     * For clients to store their own metadata
     */
    private Map<Object, Object> metadataMap = new HashMap<>();

    public ClientSessionImpl(ClientFactoryManager client, IoSession ioSession) throws Exception {
        super(client, ioSession);
        if (log.isDebugEnabled()) {
            log.debug("Client session created: {}", ioSession);
        }
        // Need to set the initial service early as calling code likes to start trying to
        // manipulate it before the connection has even been established. For instance, to
        // set the authPassword.
        getCurrentServices().initialize(client.getServiceFactories());

        signalSessionCreated(ioSession);

        /*
         * Must be called regardless of whether the client identification is sent or not immediately in order to allow
         * opening any underlying proxy protocol - e.g., SOCKS or HTTP CONNECT - otherwise the server's identification
         * will never arrive
         */
        initializeProxyConnector();

        if (sendImmediateClientIdentification) {
            sendClientIdentification();

            if (sendImmediateKexInit) {
                initializeKeyExchangePhase();
            }
        }
    }

    @Override
    protected CurrentService initializeCurrentService() {
        return new Services(this);
    }

    private Services getCurrentServices() {
        return (Services) currentService;
    }

    @Override
    protected List<Service> getServices() {
        Services services = getCurrentServices();
        Service nextService = services.getNext();
        if (nextService != null) {
            return Arrays.asList(services.getService(), nextService);
        } else {
            return super.getServices();
        }
    }

    @Override
    public AuthFuture auth() throws IOException {
        if (getUsername() == null) {
            throw new IllegalStateException("No username specified when the session was created");
        }

        ClientUserAuthService authService = getUserAuthService();
        String serviceName = nextServiceName();
        Throwable earlyError;
        AuthFuture future;
        // Guard both getting early errors and setting authFuture
        synchronized (authErrorHolder) {
            future = ValidateUtils.checkNotNull(
                    authService.auth(serviceName), "No auth future generated by service=%s", serviceName);
            // If have an error before the 1st auth then make it "sticky"
            Throwable beforeAuthError = beforeAuthErrorHolder.get();
            if (authFuture != null) {
                earlyError = authErrorHolder.getAndSet(beforeAuthError);
            } else {
                earlyError = beforeAuthError;
            }
            authFuture = future;
        }

        if (earlyError != null) {
            future.setException(earlyError);
            if (log.isDebugEnabled()) {
                log.debug("auth({}) early exception type={}: {}",
                        this, earlyError.getClass().getSimpleName(),
                        earlyError.getMessage());
            }
            // TODO consider throw directly:
            // throw new IOException(earlyError.getMessage(), earlyError);
        }

        return future;
    }

    @Override
    public void exceptionCaught(Throwable t) {
        signalAuthFailure(t);
        super.exceptionCaught(t);
    }

    @Override
    protected void preClose() {
        signalAuthFailure(new SshException("Session is being closed"));
        super.preClose();
    }

    @Override
    protected void handleDisconnect(int code, String msg, String lang, Buffer buffer) throws Exception {
        signalAuthFailure(new SshException(code, msg));
        super.handleDisconnect(code, msg, lang, buffer);
    }

    protected void signalAuthFailure(Throwable t) {
        AuthFuture future = authFuture;
        boolean firstError = false;
        if (future == null) {
            synchronized (authErrorHolder) {
                // save only the 1st newly signaled exception
                firstError = authErrorHolder.compareAndSet(null, t);
                future = authFuture;
                // save in special location errors before the 1st auth attempt
                if (future == null) {
                    beforeAuthErrorHolder.compareAndSet(null, t);
                }
            }
        }

        if (future != null) {
            future.setException(t);
        }

        if (log.isDebugEnabled()) {
            boolean signalled = (future != null) && (t == future.getException());
            log.debug("signalAuthFailure({}) type={}, signalled={}, first={}: {}",
                    this, t.getClass().getSimpleName(), signalled, firstError, t.getMessage());
        }
    }

    protected String nextServiceName() {
        return getCurrentServices().getNextName();
    }

    public void switchToNextService() throws IOException {
        getCurrentServices().switchServices();
    }

    @Override
    protected void signalSessionEvent(SessionListener.Event event) throws Exception {
        if (SessionListener.Event.KeyEstablished.equals(event)) {
            sendInitialServiceRequest();
        }
        synchronized (futureLock) {
            futureLock.notifyAll();
        }
        super.signalSessionEvent(event);
    }

    protected void sendInitialServiceRequest() throws IOException {
        if (initialServiceRequestSent.getAndSet(true)) {
            return;
        }
        Services services = getCurrentServices();
        String serviceName = services.getName();
        if (log.isDebugEnabled()) {
            log.debug("sendInitialServiceRequest({}) Send SSH_MSG_SERVICE_REQUEST for {}", this, serviceName);
        }

        Buffer request = createBuffer(SshConstants.SSH_MSG_SERVICE_REQUEST, serviceName.length() + Byte.SIZE);
        request.putString(serviceName);
        writePacket(request);
        // Assuming that MINA-SSHD only implements "explicit server authentication" it is permissible
        // for the client's service to start sending data before the service-accept has been received.
        // If "implicit authentication" were to ever be supported, then this would need to be
        // called after service-accept comes back. See SSH-TRANSPORT.
        services.start();
    }

    @Override
    public Set<ClientSessionEvent> waitFor(Collection<ClientSessionEvent> mask, long timeout) {
        Objects.requireNonNull(mask, "No mask specified");
        boolean traceEnabled = log.isTraceEnabled();
        long startTime = System.currentTimeMillis();
        /*
         * NOTE: we need to use the futureLock since some of the events depend on auth/kex/close future(s)
         */
        synchronized (futureLock) {
            long remWait = timeout;
            for (Set<ClientSessionEvent> cond = EnumSet.noneOf(ClientSessionEvent.class);; cond.clear()) {
                updateCurrentSessionState(cond);

                boolean nothingInCommon = Collections.disjoint(cond, mask);
                if (!nothingInCommon) {
                    if (traceEnabled) {
                        log.trace("waitFor({}) call return mask={}, cond={}", this, mask, cond);
                    }
                    return cond;
                }

                if (timeout > 0L) {
                    long now = System.currentTimeMillis();
                    long usedTime = now - startTime;
                    if ((usedTime >= timeout) || (remWait <= 0L)) {
                        if (traceEnabled) {
                            log.trace("waitFor({}) call timeout {}/{} for mask={}: {}",
                                    this, usedTime, timeout, mask, cond);
                        }
                        cond.add(ClientSessionEvent.TIMEOUT);
                        return cond;
                    }
                }

                if (traceEnabled) {
                    log.trace("waitFor({}) Waiting {} millis for lock on mask={}, cond={}",
                            this, timeout, mask, cond);
                }

                long nanoStart = System.nanoTime();
                try {
                    if (timeout > 0L) {
                        futureLock.wait(remWait);
                    } else {
                        futureLock.wait();
                    }

                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (traceEnabled) {
                        log.trace("waitFor({}) Lock notified after {} nanos", this, nanoDuration);
                    }

                    if (timeout > 0L) {
                        long waitDuration = TimeUnit.MILLISECONDS.convert(nanoDuration, TimeUnit.NANOSECONDS);
                        if (waitDuration <= 0L) {
                            waitDuration = 123L;
                        }
                        remWait -= waitDuration;
                    }
                } catch (InterruptedException e) {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    if (traceEnabled) {
                        log.trace("waitFor({}) mask={} - ignoring interrupted exception after {} nanos", this, mask,
                                nanoDuration);
                    }
                }
            }
        }
    }

    @Override
    public Set<ClientSessionEvent> getSessionState() {
        Set<ClientSessionEvent> state = EnumSet.noneOf(ClientSessionEvent.class);
        synchronized (futureLock) {
            return updateCurrentSessionState(state);
        }
    }

    // NOTE: assumed to be called under lock
    protected <C extends Collection<ClientSessionEvent>> C updateCurrentSessionState(C state) {
        if (closeFuture.isClosed()) {
            state.add(ClientSessionEvent.CLOSED);
        }
        if (isAuthenticated()) { // authFuture.isSuccess()
            state.add(ClientSessionEvent.AUTHED);
        }
        if (KexState.DONE.equals(kexState.get())) {
            AuthFuture future = authFuture;
            if (future == null || future.isFailure()) {
                state.add(ClientSessionEvent.WAIT_AUTH);
            }
        }

        return state;
    }

    @Override
    public Map<Object, Object> getMetadataMap() {
        return metadataMap;
    }

    /**
     * Encapsulates and protects against concurrent access the service switching.
     */
    private static class Services extends CurrentService {

        private String nextName;

        private Service next;

        Services(ClientSessionImpl session) {
            super(session);
        }

        synchronized void initialize(List<? extends ServiceFactory> factories) throws IOException {
            int numFactories = GenericUtils.size(factories);
            ValidateUtils.checkTrue((numFactories > 0) && (numFactories <= 2), "One or two services must be configured: %d",
                    numFactories);
            ServiceFactory currentFactory = factories.get(0);
            // Delay starting the service until after the initial request has been sent.
            set(currentFactory.create(session), currentFactory.getName(), false);
            if (numFactories > 1) {
                ServiceFactory nextFactory = factories.get(1);
                nextName = nextFactory.getName();
                next = nextFactory.create(session);
            }
        }

        synchronized void switchServices() throws IOException {
            if (next == null) {
                throw new IllegalStateException("No service available");
            }
            try {
                set(next, nextName, true);
            } finally {
                next = null;
                nextName = null;
            }
        }

        synchronized String getNextName() {
            return nextName;
        }

        synchronized Service getNext() {
            return next;
        }
    }
}
