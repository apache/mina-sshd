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

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MinaAcceptor extends MinaService implements org.apache.sshd.common.io.IoAcceptor, IoHandler {
    protected final AtomicReference<IoAcceptor> acceptorHolder = new AtomicReference<>(null);

    // Acceptor
    protected int backlog;
    protected boolean reuseAddress;

    public MinaAcceptor(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler,
                        IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);

        backlog = CoreModuleProperties.SOCKET_BACKLOG.getRequired(manager);
        reuseAddress = CoreModuleProperties.SOCKET_REUSEADDR.getRequired(manager);
    }

    protected IoAcceptor createAcceptor() {
        NioSocketAcceptor acceptor = new NioSocketAcceptor(ioProcessor);
        acceptor.setCloseOnDeactivation(false);
        acceptor.setReuseAddress(reuseAddress);
        acceptor.setBacklog(backlog);
        configure(acceptor.getSessionConfig());
        return acceptor;
    }

    protected IoAcceptor getAcceptor() {
        IoAcceptor acceptor;
        synchronized (acceptorHolder) {
            acceptor = acceptorHolder.get();
            if (acceptor != null) {
                return acceptor;
            }

            acceptor = createAcceptor();
            acceptor.setHandler(this);
            acceptorHolder.set(acceptor);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created IoAcceptor: {}", this);
        }
        return acceptor;
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        IoServiceEventListener listener = getIoServiceEventListener();
        SocketAddress local = session.getLocalAddress();
        SocketAddress remote = session.getRemoteAddress();
        SocketAddress service = session.getServiceAddress();
        try {
            if (listener != null) {
                try {
                    listener.connectionAccepted(this, local, remote, service);
                } catch (Exception e) {
                    session.closeNow();
                    throw e;
                }
            }

            sessionCreated(session, service);
        } catch (Exception e) {
            if (listener != null) {
                try {
                    listener.abortAcceptedConnection(this, local, remote, service, e);
                } catch (Exception exc) {
                    debug("sessionCreated({})[{}] ignoring abort event failure={}: {}",
                            session, listener, exc.getClass().getSimpleName(), exc.getMessage(), exc);
                }
            }

            throw e;
        }
    }

    @Override
    protected IoService getIoService() {
        return getAcceptor();
    }

    @Override
    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        IoAcceptor acceptor = getAcceptor();
        acceptor.bind(addresses);
    }

    @Override
    public void bind(SocketAddress address) throws IOException {
        IoAcceptor acceptor = getAcceptor();
        acceptor.bind(address);
    }

    @Override
    public void unbind() {
        IoAcceptor acceptor = getAcceptor();
        acceptor.unbind();
    }

    @Override
    public void unbind(Collection<? extends SocketAddress> addresses) {
        IoAcceptor acceptor = getAcceptor();
        acceptor.unbind(addresses);
    }

    @Override
    public void unbind(SocketAddress address) {
        IoAcceptor acceptor = getAcceptor();
        acceptor.unbind(address);
    }

    @Override
    public Set<SocketAddress> getBoundAddresses() {
        IoAcceptor acceptor = getAcceptor();
        return acceptor.getLocalAddresses();
    }
}
