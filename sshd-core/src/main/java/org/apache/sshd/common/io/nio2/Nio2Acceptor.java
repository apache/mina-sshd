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
package org.apache.sshd.common.io.nio2;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;

/**
 */
public class Nio2Acceptor extends Nio2Service implements IoAcceptor {

    private final Map<SocketAddress, AsynchronousServerSocketChannel> channels;
    private int backlog = 0;

    public Nio2Acceptor(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
        channels = new ConcurrentHashMap<SocketAddress, AsynchronousServerSocketChannel>();

        String valStr = manager.getProperties().get(FactoryManager.SOCKET_BACKLOG);
        if (valStr != null) {
            backlog = Integer.parseInt(valStr);
        }
    }

    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        for (SocketAddress address : addresses) {
            logger.debug("Binding Nio2Acceptor to address {}", address);
            AsynchronousServerSocketChannel socket = AsynchronousServerSocketChannel.open(group);
            setOption(socket, FactoryManager.SOCKET_KEEPALIVE, StandardSocketOptions.SO_KEEPALIVE, null);
            setOption(socket, FactoryManager.SOCKET_LINGER, StandardSocketOptions.SO_LINGER, null);
            setOption(socket, FactoryManager.SOCKET_RCVBUF, StandardSocketOptions.SO_RCVBUF, null);
            setOption(socket, FactoryManager.SOCKET_REUSEADDR, StandardSocketOptions.SO_REUSEADDR, Boolean.TRUE);
            setOption(socket, FactoryManager.SOCKET_SNDBUF, StandardSocketOptions.SO_SNDBUF, null);
            setOption(socket, FactoryManager.TCP_NODELAY, StandardSocketOptions.TCP_NODELAY, null);
            socket.bind(address, backlog);
            SocketAddress local = socket.getLocalAddress();
            channels.put(local, socket);
            socket.accept(local, new AcceptCompletionHandler(socket));
        }
    }

    public void bind(SocketAddress address) throws IOException {
        bind(Collections.singleton(address));
    }

    public void unbind() {
        logger.debug("Unbinding");
        unbind(getBoundAddresses());
    }

    public void unbind(Collection<? extends SocketAddress> addresses) {
        for (SocketAddress address : addresses) {
            AsynchronousServerSocketChannel channel = channels.remove(address);
            if (channel != null) {
                try {
                    channel.close();
                } catch (IOException e) {
                    log.warn("Error unbinding socket", e);
                }
            }
        }
    }

    public void unbind(SocketAddress address) {
        unbind(Collections.singleton(address));
    }

    public Set<SocketAddress> getBoundAddresses() {
        return new HashSet<SocketAddress>(channels.keySet());
    }

    @Override
    public CloseFuture close(boolean immediately) {
        unbind();
        return super.close(immediately);
    }

    public void doCloseImmediately() {
        for (SocketAddress address : channels.keySet()) {
            try {
                channels.get(address).close();
            } catch (IOException e) {
                logger.debug("Exception caught while closing channel", e);
            }
        }
        super.doCloseImmediately();
    }

    class AcceptCompletionHandler extends Nio2CompletionHandler<AsynchronousSocketChannel, SocketAddress> {
        private final AsynchronousServerSocketChannel socket;
        AcceptCompletionHandler(AsynchronousServerSocketChannel socket) {
            this.socket = socket;
        }
        protected void onCompleted(AsynchronousSocketChannel result, SocketAddress address) {
            // Verify that the address has not been unbound
            if (!channels.containsKey(address)) {
                return;
            }
            try {
                // Create a session
                Nio2Session session = new Nio2Session(Nio2Acceptor.this, handler, result);
                handler.sessionCreated(session);
                sessions.put(session.getId(), session);
                session.startReading();
                // Accept new connections
                socket.accept(address, this);
            } catch (Throwable exc) {
                failed(exc, address);
            }
        }
        protected void onFailed(final Throwable exc, final SocketAddress address) {
            if (channels.containsKey(address) && !disposing.get()) {
                logger.warn("Caught exception while accepting incoming connection", exc);
            }
        }
    }
}
