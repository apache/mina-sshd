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
package org.apache.sshd.common.io.nio2;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2Acceptor extends Nio2Service implements IoAcceptor {
    protected final Map<SocketAddress, AsynchronousServerSocketChannel> channels = new ConcurrentHashMap<>();
    private int backlog = DEFAULT_BACKLOG;

    public Nio2Acceptor(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
        backlog = manager.getIntProperty(FactoryManager.SOCKET_BACKLOG, DEFAULT_BACKLOG);
    }

    @Override
    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        AsynchronousChannelGroup group = getChannelGroup();
        for (SocketAddress address : addresses) {
            if (log.isDebugEnabled()) {
                log.debug("Binding Nio2Acceptor to address {}", address);
            }

            AsynchronousServerSocketChannel asyncChannel = openAsynchronousServerSocketChannel(address, group);
            AsynchronousServerSocketChannel socket = setSocketOptions(asyncChannel);
            socket.bind(address, backlog);
            SocketAddress local = socket.getLocalAddress();
            channels.put(local, socket);

            CompletionHandler<AsynchronousSocketChannel, ? super SocketAddress> handler =
                ValidateUtils.checkNotNull(createSocketCompletionHandler(channels, socket),
                    "No completion handler created for address=%s",
                    address);
            socket.accept(local, handler);
        }
    }

    protected AsynchronousServerSocketChannel openAsynchronousServerSocketChannel(
            SocketAddress address, AsynchronousChannelGroup group) throws IOException {
        return AsynchronousServerSocketChannel.open(group);
    }

    protected CompletionHandler<AsynchronousSocketChannel, ? super SocketAddress> createSocketCompletionHandler(
            Map<SocketAddress, AsynchronousServerSocketChannel> channelsMap, AsynchronousServerSocketChannel socket) throws IOException {
        return new AcceptCompletionHandler(socket);
    }

    @Override
    public void bind(SocketAddress address) throws IOException {
        bind(Collections.singleton(address));
    }

    @Override
    public void unbind() {
        Collection<SocketAddress> addresses = getBoundAddresses();
        if (log.isDebugEnabled()) {
            log.debug("Unbinding {}", addresses);
        }

        unbind(addresses);
    }

    @Override
    public void unbind(Collection<? extends SocketAddress> addresses) {
        for (SocketAddress address : addresses) {
            AsynchronousServerSocketChannel channel = channels.remove(address);
            if (channel != null) {
                try {
                    if (log.isTraceEnabled()) {
                        log.trace("unbind({})", address);
                    }
                    channel.close();
                } catch (IOException e) {
                    log.warn("unbind({}) {} while unbinding channel: {}",
                         address, e.getClass().getSimpleName(), e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("unbind(" + address + ") failure details", e);
                    }
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("No active channel to unbind for {}", address);
                }
            }
        }
    }

    @Override
    public void unbind(SocketAddress address) {
        unbind(Collections.singleton(address));
    }

    @Override
    public Set<SocketAddress> getBoundAddresses() {
        return new HashSet<>(channels.keySet());
    }

    @Override
    public CloseFuture close(boolean immediately) {
        unbind();
        return super.close(immediately);
    }

    @Override
    public void doCloseImmediately() {
        Collection<SocketAddress> boundAddresses = getBoundAddresses();
        for (SocketAddress address : boundAddresses) {
            AsynchronousServerSocketChannel asyncChannel = channels.remove(address);
            if (asyncChannel == null) {
                continue;   // debug breakpoint
            }

            try {
                asyncChannel.close();
                if (log.isDebugEnabled()) {
                    log.debug("doCloseImmediately({}) closed channel", address);
                }
            } catch (IOException e) {
                log.debug("Exception caught while closing channel of " + address, e);
            }
        }
        super.doCloseImmediately();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getBoundAddresses() + "]";
    }

    protected class AcceptCompletionHandler extends Nio2CompletionHandler<AsynchronousSocketChannel, SocketAddress> {
        protected final AsynchronousServerSocketChannel socket;

        AcceptCompletionHandler(AsynchronousServerSocketChannel socket) {
            this.socket = socket;
        }

        @Override
        @SuppressWarnings("synthetic-access")
        protected void onCompleted(AsynchronousSocketChannel result, SocketAddress address) {
            // Verify that the address has not been unbound
            if (!channels.containsKey(address)) {
                if (log.isDebugEnabled()) {
                    log.debug("onCompleted({}) unbound address", address);
                }
                return;
            }

            Nio2Session session = null;
            try {
                // Create a session
                IoHandler handler = getIoHandler();
                setSocketOptions(result);
                session = Objects.requireNonNull(createSession(Nio2Acceptor.this, address, result, handler), "No NIO2 session created");
                handler.sessionCreated(session);
                sessions.put(session.getId(), session);
                session.startReading();
            } catch (Throwable exc) {
                failed(exc, address);

                // fail fast the accepted connection
                if (session != null) {
                    try {
                        session.close();
                    } catch (Throwable t) {
                        log.warn("onCompleted(" + address + ") Failed (" + t.getClass().getSimpleName() + ")"
                               + " to close accepted connection from " + address
                               + ": " + t.getMessage(),
                                 t);
                    }
                }
            }

            try {
                // Accept new connections
                socket.accept(address, this);
            } catch (Throwable exc) {
                failed(exc, address);
            }
        }

        @SuppressWarnings("synthetic-access")
        protected Nio2Session createSession(Nio2Acceptor acceptor, SocketAddress address, AsynchronousSocketChannel channel, IoHandler handler) throws Throwable {
            if (log.isTraceEnabled()) {
                log.trace("createNio2Session({}) address={}", acceptor, address);
            }
            return new Nio2Session(acceptor, getFactoryManager(), handler, channel);
        }

        @Override
        @SuppressWarnings("synthetic-access")
        protected void onFailed(Throwable exc, SocketAddress address) {
            AsynchronousServerSocketChannel channel = channels.get(address);
            if (channel == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Caught {} for untracked channel of {}: {}",
                        exc.getClass().getSimpleName(), address, exc.getMessage());
                }
                return;
            }

            if (disposing.get()) {
                if (log.isDebugEnabled()) {
                    log.debug("Caught {} for tracked channel of {} while disposing: {}",
                        exc.getClass().getSimpleName(), address, exc.getMessage());
                }
                return;
            }

            log.warn("Caught " + exc.getClass().getSimpleName()
                   + " while accepting incoming connection from " + address
                   + ": " + exc.getMessage(), exc);

            try {
                // Accept new connections
                socket.accept(address, this);
            } catch (Throwable t) {
                // Do not call failed(t, address) to avoid infinite recursion
                log.error("Failed (" + t.getClass().getSimpleName()
                    + " to re-accept new connections on " + address
                    + ": " + t.getMessage(), t);
            }
        }
    }
}
