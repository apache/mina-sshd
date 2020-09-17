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
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2Acceptor extends Nio2Service implements IoAcceptor {
    protected final Map<SocketAddress, AsynchronousServerSocketChannel> channels = new ConcurrentHashMap<>();
    private int backlog;

    public Nio2Acceptor(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
        backlog = CoreModuleProperties.SOCKET_BACKLOG.getRequired(manager);
    }

    @Override
    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        if (GenericUtils.isEmpty(addresses)) {
            return;
        }

        AsynchronousChannelGroup group = getChannelGroup();
        Collection<java.io.Closeable> bound = new ArrayList<>(addresses.size());
        try {
            boolean debugEnabled = log.isDebugEnabled();
            for (SocketAddress address : addresses) {
                if (debugEnabled) {
                    log.debug("bind({}) binding to address", address);
                }

                try {
                    AsynchronousServerSocketChannel asyncChannel = openAsynchronousServerSocketChannel(address, group);
                    // In case it or the other bindings fail
                    java.io.Closeable protector = protectInProgressBinding(address, asyncChannel);
                    bound.add(protector);

                    AsynchronousServerSocketChannel socket = setSocketOptions(asyncChannel);
                    socket.bind(address, backlog);

                    SocketAddress local = socket.getLocalAddress();
                    if (debugEnabled) {
                        log.debug("bind({}) bound to {}", address, local);
                    }

                    AsynchronousServerSocketChannel prev = channels.put(local, socket);
                    if (prev != null) {
                        if (debugEnabled) {
                            log.debug("bind({}) replaced previous channel ({}) for {}",
                                    address, prev.getLocalAddress(), local);
                        }
                    }

                    CompletionHandler<AsynchronousSocketChannel, ? super SocketAddress> handler
                            = ValidateUtils.checkNotNull(createSocketCompletionHandler(channels, socket),
                                    "No completion handler created for address=%s[%s]",
                                    address, local);
                    socket.accept(local, handler);
                } catch (IOException | RuntimeException e) {
                    error("bind({}) - failed ({}) to bind: {}",
                            address, e.getClass().getSimpleName(), e.getMessage(), e);
                    throw e;
                }
            }

            bound.clear(); // avoid auto-close at finally clause
        } finally {
            IOException err = IoUtils.closeQuietly(bound);
            if (err != null) {
                throw err;
            }
        }
    }

    protected java.io.Closeable protectInProgressBinding(
            SocketAddress address, AsynchronousServerSocketChannel asyncChannel) {
        boolean debugEnabled = log.isDebugEnabled();

        return new java.io.Closeable() {
            @Override
            @SuppressWarnings("synthetic-access")
            public void close() throws IOException {
                try {
                    try {
                        SocketAddress local = asyncChannel.getLocalAddress();
                        // make sure bound channel
                        if (local != null) {
                            if (debugEnabled) {
                                log.debug("protectInProgressBinding({}) remove {} binding", address, local);
                            }
                            channels.remove(local);
                        }
                    } finally {
                        if (debugEnabled) {
                            log.debug("protectInProgressBinding({}) auto-close", address);
                        }

                        asyncChannel.close();
                    }
                } catch (ClosedChannelException e) {
                    // ignore if already closed
                    if (debugEnabled) {
                        log.debug("protectInProgressBinding(" + address + ") ignore close channel exception", e);
                    }
                }
            }

            @Override
            public String toString() {
                return "protectInProgressBinding(" + address + ")";
            }
        };
    }

    protected AsynchronousServerSocketChannel openAsynchronousServerSocketChannel(
            SocketAddress address, AsynchronousChannelGroup group)
            throws IOException {
        return AsynchronousServerSocketChannel.open(group);
    }

    protected CompletionHandler<AsynchronousSocketChannel, ? super SocketAddress> createSocketCompletionHandler(
            Map<SocketAddress, AsynchronousServerSocketChannel> channelsMap, AsynchronousServerSocketChannel socket)
            throws IOException {
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
        boolean traceEnabled = log.isTraceEnabled();
        for (SocketAddress address : addresses) {
            AsynchronousServerSocketChannel channel = channels.remove(address);
            if (channel != null) {
                try {
                    if (traceEnabled) {
                        log.trace("unbind({})", address);
                    }
                    channel.close();
                } catch (IOException e) {
                    warn("unbind({}) {} while unbinding channel: {}",
                            address, e.getClass().getSimpleName(), e.getMessage(), e);
                }
            } else {
                if (traceEnabled) {
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
    protected void preClose() {
        unbind();
        super.preClose();
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .close(super.getInnerCloseable())
                .run(toString(), this::closeImmediately0)
                .build();
    }

    protected void closeImmediately0() {
        Collection<SocketAddress> boundAddresses = getBoundAddresses();
        boolean debugEnabled = log.isDebugEnabled();
        for (SocketAddress address : boundAddresses) {
            AsynchronousServerSocketChannel asyncChannel = channels.remove(address);
            if (asyncChannel == null) {
                continue; // debug breakpoint
            }

            try {
                asyncChannel.close();
                if (debugEnabled) {
                    log.debug("doCloseImmediately({}) closed channel", address);
                }
            } catch (IOException e) {
                if (debugEnabled) {
                    log.debug("Exception caught while closing channel of " + address, e);
                }
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getBoundAddresses() + "]";
    }

    @SuppressWarnings("synthetic-access")
    protected class AcceptCompletionHandler extends Nio2CompletionHandler<AsynchronousSocketChannel, SocketAddress> {
        protected final AsynchronousServerSocketChannel socket;

        AcceptCompletionHandler(AsynchronousServerSocketChannel socket) {
            this.socket = socket;
        }

        @Override
        protected void onCompleted(AsynchronousSocketChannel result, SocketAddress address) {
            // Verify that the address has not been unbound
            if (!channels.containsKey(address)) {
                if (log.isDebugEnabled()) {
                    log.debug("onCompleted({}) unbound address", address);
                }
                return;
            }

            Nio2Session session = null;
            Long sessionId = null;
            boolean keepAccepting;
            IoServiceEventListener listener = getIoServiceEventListener();
            try {
                if (listener != null) {
                    SocketAddress localAddress = result.getLocalAddress();
                    SocketAddress remoteAddress = result.getRemoteAddress();
                    listener.connectionAccepted(Nio2Acceptor.this, localAddress, remoteAddress, address);
                }

                // Create a session
                IoHandler handler = getIoHandler();
                setSocketOptions(result);
                session = Objects.requireNonNull(
                        createSession(Nio2Acceptor.this, address, result, handler),
                        "No NIO2 session created");
                sessionId = session.getId();
                handler.sessionCreated(session);
                sessions.put(sessionId, session);
                if (session.isClosing()) {
                    try {
                        handler.sessionClosed(session);
                    } finally {
                        unmapSession(sessionId);
                    }
                } else {
                    session.startReading();
                }

                keepAccepting = true;
            } catch (Throwable exc) {
                if (listener != null) {
                    try {
                        SocketAddress localAddress = result.getLocalAddress();
                        SocketAddress remoteAddress = result.getRemoteAddress();
                        listener.abortAcceptedConnection(Nio2Acceptor.this, localAddress, remoteAddress, address, exc);
                    } catch (Exception e) {
                        if (log.isDebugEnabled()) {
                            log.debug("onCompleted(" + address + ") listener=" + listener + " ignoring abort event exception",
                                    e);
                        }
                    }
                }
                keepAccepting = okToReaccept(exc, address);

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

                unmapSession(sessionId);
            }

            if (keepAccepting) {
                try {
                    // Accept new connections
                    socket.accept(address, this);
                } catch (Throwable exc) {
                    failed(exc, address);
                }
            } else {
                log.error("=====> onCompleted({}) no longer accepting incoming connections <====", address);
            }
        }

        protected Nio2Session createSession(
                Nio2Acceptor acceptor, SocketAddress address, AsynchronousSocketChannel channel, IoHandler handler)
                throws Throwable {
            if (log.isTraceEnabled()) {
                log.trace("createNio2Session({}) address={}", acceptor, address);
            }
            return new Nio2Session(acceptor, getFactoryManager(), handler, channel, address);
        }

        @Override
        protected void onFailed(Throwable exc, SocketAddress address) {
            if (okToReaccept(exc, address)) {
                try {
                    // Accept new connections
                    socket.accept(address, this);
                } catch (Throwable t) {
                    // Do not call failed(t, address) to avoid infinite recursion
                    log.error("Failed (" + t.getClass().getSimpleName()
                              + " to re-accept new connections on " + address
                              + ": " + t.getMessage(),
                            t);
                }
            }
        }

        protected boolean okToReaccept(Throwable exc, SocketAddress address) {
            AsynchronousServerSocketChannel channel = channels.get(address);
            boolean debugEnabled = log.isDebugEnabled();
            if (channel == null) {
                if (debugEnabled) {
                    log.debug("Caught {} for untracked channel of {}: {}",
                            exc.getClass().getSimpleName(), address, exc.getMessage());
                }
                return false;
            }

            if (disposing.get()) {
                if (debugEnabled) {
                    log.debug("Caught {} for tracked channel of {} while disposing: {}",
                            exc.getClass().getSimpleName(), address, exc.getMessage());
                }
                return false;
            }

            debug("Caught {} while accepting incoming connection from {}: {}",
                    exc.getClass().getSimpleName(), address, exc.getMessage(), exc);
            return true;
        }
    }
}
