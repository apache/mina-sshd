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
package org.apache.sshd.common.io.mina;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;

/**
 */
public class MinaAcceptor extends MinaService implements org.apache.sshd.common.io.IoAcceptor, IoHandler {
    public static final int DEFAULT_BACKLOG = 0;
    public static final boolean DEFAULT_REUSE_ADDRESS = true;

    protected final AtomicReference<IoAcceptor> acceptorHolder = new AtomicReference<>(null);

    // Acceptor
    protected int backlog = DEFAULT_BACKLOG;
    protected boolean reuseAddress = DEFAULT_REUSE_ADDRESS;

    public MinaAcceptor(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler, IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);

        backlog = PropertyResolverUtils.getIntProperty(manager, FactoryManager.SOCKET_BACKLOG, DEFAULT_BACKLOG);
        reuseAddress = PropertyResolverUtils.getBooleanProperty(manager, FactoryManager.SOCKET_REUSEADDR, DEFAULT_REUSE_ADDRESS);
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

        log.debug("Created IoAcceptor");
        return acceptor;
    }

    @Override
    protected IoService getIoService() {
        return getAcceptor();
    }

    @Override
    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        getAcceptor().bind(addresses);
    }

    @Override
    public void bind(SocketAddress address) throws IOException {
        getAcceptor().bind(address);
    }

    @Override
    public void unbind() {
        getAcceptor().unbind();
    }

    @Override
    public void unbind(Collection<? extends SocketAddress> addresses) {
        getAcceptor().unbind(addresses);
    }

    @Override
    public void unbind(SocketAddress address) {
        getAcceptor().unbind(address);
    }

    @Override
    public Set<SocketAddress> getBoundAddresses() {
        return getAcceptor().getLocalAddresses();
    }

}
