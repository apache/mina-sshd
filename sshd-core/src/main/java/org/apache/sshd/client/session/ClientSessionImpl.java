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
import java.util.Set;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * The default implementation of a {@link ClientSession}
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

    public ClientSessionImpl(ClientFactoryManager client, IoSession ioSession) throws Exception {
        super(client, ioSession);
        if (log.isDebugEnabled()) {
            log.debug("Client session created: {}", ioSession);
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
            if (log.isDebugEnabled()) {
                log.debug("Failed ({}) to announce session={} created: {}",
                          e.getClass().getSimpleName(), ioSession, e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("Session=" + ioSession + " creation failure details", e);
            }
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
    public Map<Object, Object> getMetadataMap() {
        return metadataMap;
    }
}
