/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.io.mina;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Set;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.FactoryManager;

/**
 */
public class MinaAcceptor extends MinaService implements org.apache.sshd.common.io.IoAcceptor, IoHandler {

    protected volatile IoAcceptor acceptor;
    // Acceptor
    protected int backlog = 0;
    protected boolean reuseAddress = true;

    public MinaAcceptor(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler, IoProcessor<NioSession> ioProcessor) {
        super(manager, handler, ioProcessor);

        String valStr = manager.getProperties().get(FactoryManager.SOCKET_BACKLOG);
        if (valStr != null) {
            backlog = Integer.parseInt(valStr);
        }
        valStr = manager.getProperties().get(FactoryManager.SOCKET_REUSEADDR);
        if (valStr != null) {
            reuseAddress = Boolean.parseBoolean(valStr);
        }
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
        if (acceptor == null) {
            synchronized (this) {
                if (acceptor == null) {
                    acceptor = createAcceptor();
                    acceptor.setHandler(this);
                }
            }
        }
        return acceptor;
    }

    @Override
    protected IoService getIoService() {
        return getAcceptor();
    }

    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        getAcceptor().bind(addresses);
    }

    public void bind(SocketAddress address) throws IOException {
        getAcceptor().bind(address);
    }

    public void unbind() {
        getAcceptor().unbind();
    }

    public void unbind(Collection<? extends SocketAddress> addresses) {
        getAcceptor().unbind(addresses);
    }

    public void unbind(SocketAddress address) {
        getAcceptor().unbind(address);
    }

    public Set<SocketAddress> getBoundAddresses() {
        return getAcceptor().getLocalAddresses();
    }

}
