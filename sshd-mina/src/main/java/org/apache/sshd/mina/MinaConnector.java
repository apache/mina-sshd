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
package org.apache.sshd.mina;

import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.io.DefaultIoConnectFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MinaConnector extends MinaService implements org.apache.sshd.common.io.IoConnector {

    /**
     * Closing a MINA IoSession first fulfills the CloseFuture and later calls {@link #sessionClosed(IoSession)}. But it
     * is only within that method that we close the SSH session atop the MINA IoSession. So we cannot use a listener on
     * the MINA CloseFuture to fulfill the cancellation of the user-visible IoConnectFuture: client code might see the
     * future fulfilled while the SSH session is not yet closing or closed. Therefore we add our own IoConnectFuture as
     * a session attribute, and fulfill it only in sessionClosed.
     */
    private static final Object CONNECT_FUTURE_KEY = new Object();

    protected final AtomicReference<IoConnector> connectorHolder = new AtomicReference<>(null);

    public MinaConnector(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler,
                         IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);
    }

    protected IoConnector createConnector() {
        NioSocketConnector connector = new NioSocketConnector(ioProcessor);
        configure(connector.getSessionConfig());
        CoreModuleProperties.IO_CONNECT_TIMEOUT.get(manager).ifPresent(d -> {
            if (d.isZero() || d.isNegative()) {
                return;
            }
            long millis;
            try {
                millis = d.toMillis();
            } catch (ArithmeticException e) {
                millis = Long.MAX_VALUE;
            }
            connector.setConnectTimeoutMillis(millis);
        });
        return connector;
    }

    protected IoConnector getConnector() {
        IoConnector connector;
        synchronized (connectorHolder) {
            connector = connectorHolder.get();
            if (connector != null) {
                return connector;
            }

            connector = createConnector();
            connector.setHandler(this);
            connectorHolder.set(connector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created IoConnector: {}", connector);
        }
        return connector;
    }

    @Override
    protected org.apache.mina.core.service.IoService getIoService() {
        return getConnector();
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        IoServiceEventListener listener = getIoServiceEventListener();
        SocketAddress local = session.getLocalAddress();
        SocketAddress remote = session.getRemoteAddress();
        AttributeRepository context = (AttributeRepository) session.getAttribute(AttributeRepository.class);
        try {
            if (listener != null) {
                try {
                    listener.connectionEstablished(this, local, context, remote);
                } catch (Exception e) {
                    session.closeNow();
                    throw e;
                }
            }

            sessionCreated(session, null);
        } catch (Exception e) {
            if (listener != null) {
                try {
                    listener.abortEstablishedConnection(this, local, context, remote, e);
                } catch (Exception exc) {
                    debug("sessionCreated({}) ignoring abort connection failure={}: {}",
                            session, exc.getClass().getSimpleName(), exc.getMessage(), exc);
                }
            }

            throw e;
        }
    }

    @Override
    public void sessionClosed(IoSession ioSession) throws Exception {
        try {
            super.sessionClosed(ioSession);
        } finally {
            IoConnectFuture future = (IoConnectFuture) ioSession.removeAttribute(CONNECT_FUTURE_KEY);
            if (future != null) {
                CancelFuture cancellation = future.cancel();
                if (cancellation != null) {
                    cancellation.setCanceled();
                }
            }
        }
    }

    @Override
    public IoConnectFuture connect(SocketAddress address, AttributeRepository context, SocketAddress localAddress) {
        IoConnectFuture future = new DefaultIoConnectFuture(address, null) {

            @Override
            public void setSession(org.apache.sshd.common.io.IoSession session) {
                if (context != null) {
                    session.setAttribute(AttributeRepository.class, context);
                }
                super.setSession(session);
            }

        };
        IoConnector connector = getConnector();
        AtomicReference<IoSession> createdSession = new AtomicReference<>();
        ConnectFuture connectFuture = connector.connect(
                address, localAddress,
                (s, f) -> {
                    s.setAttribute(CONNECT_FUTURE_KEY, future);
                    if (f.isCanceled()) {
                        s.closeNow();
                    } else {
                        createdSession.set(s);
                    }
                    if (context != null) {
                        s.setAttribute(AttributeRepository.class, context);
                    }
                });
        future.addListener(f -> {
            if (f.isCanceled()) {
                connectFuture.cancel();
                IoSession ioSession = connectFuture.getSession();
                if (ioSession != null) {
                    ioSession.setAttribute(CONNECT_FUTURE_KEY, future);
                    ioSession.closeNow();
                }
            }
        });
        connectFuture.addListener((IoFutureListener<ConnectFuture>) cf -> {
            Throwable t = cf.getException();
            if (t != null) {
                future.setException(t);
            } else if (cf.isCanceled() || !isOpen()) {
                IoSession ioSession = createdSession.getAndSet(null);
                CancelFuture cancellation = future.cancel();
                if (ioSession != null) {
                    ioSession.setAttribute(CONNECT_FUTURE_KEY, future);
                    ioSession.closeNow();
                } else if (cancellation != null) {
                    cancellation.setCanceled();
                }
            } else {
                IoSession ioSession = cf.getSession();
                org.apache.sshd.common.io.IoSession sshSession = getSession(ioSession);
                if (context != null) {
                    sshSession.setAttribute(AttributeRepository.class, context);
                }
                future.setSession(sshSession);
                if (future.getSession() != sshSession) {
                    // Must have been canceled
                    try {
                        sshSession.close(true);
                    } finally {
                        CancelFuture cancellation = future.getCancellation();
                        if (cancellation != null) {
                            cancellation.setCanceled();
                        }
                    }
                } else {
                    ioSession.removeAttribute(CONNECT_FUTURE_KEY);
                }
            }
        });
        return future;
    }
}
