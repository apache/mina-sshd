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
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoServiceEventListener;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MinaConnector extends MinaService implements org.apache.sshd.common.io.IoConnector, IoHandler {
    protected final AtomicReference<IoConnector> connectorHolder = new AtomicReference<>(null);

    public MinaConnector(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler,
                         IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);
    }

    protected IoConnector createConnector() {
        NioSocketConnector connector = new NioSocketConnector(ioProcessor);
        configure(connector.getSessionConfig());
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
    public IoConnectFuture connect(SocketAddress address, AttributeRepository context, SocketAddress localAddress) {
        class Future extends DefaultSshFuture<IoConnectFuture> implements IoConnectFuture {
            Future(Object lock) {
                super(address, lock);
            }

            @Override
            public org.apache.sshd.common.io.IoSession getSession() {
                Object v = getValue();
                return v instanceof org.apache.sshd.common.io.IoSession ? (org.apache.sshd.common.io.IoSession) v : null;
            }

            @Override
            public Throwable getException() {
                Object v = getValue();
                return v instanceof Throwable ? (Throwable) v : null;
            }

            @Override
            public boolean isConnected() {
                return getValue() instanceof org.apache.sshd.common.io.IoSession;
            }

            @Override
            public void setSession(org.apache.sshd.common.io.IoSession session) {
                if (context != null) {
                    session.setAttribute(AttributeRepository.class, context);
                }

                setValue(session);
            }

            @Override
            public void setException(Throwable exception) {
                setValue(exception);
            }
        }

        IoConnectFuture future = new Future(null);
        IoConnector connector = getConnector();
        ConnectFuture connectFuture = connector.connect(
                address, localAddress,
                (s, f) -> {
                    if (context != null) {
                        s.setAttribute(AttributeRepository.class, context);
                    }
                });
        connectFuture.addListener((IoFutureListener<ConnectFuture>) cf -> {
            Throwable t = cf.getException();
            if (t != null) {
                future.setException(t);
            } else if (cf.isCanceled()) {
                future.cancel();
            } else {
                IoSession ioSession = cf.getSession();
                org.apache.sshd.common.io.IoSession sshSession = getSession(ioSession);
                if (context != null) {
                    sshSession.setAttribute(AttributeRepository.class, context);
                }
                future.setSession(sshSession);
            }
        });
        return future;
    }
}
