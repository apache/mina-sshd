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
import java.nio.channels.AsynchronousSocketChannel;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2Connector extends Nio2Service implements IoConnector {
    public Nio2Connector(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
    }

    @Override
    public IoConnectFuture connect(
            SocketAddress address, AttributeRepository context, SocketAddress localAddress) {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Connecting to {}", address);
        }

        IoConnectFuture future = new DefaultIoConnectFuture(address, null);
        AsynchronousSocketChannel channel = null;
        AsynchronousSocketChannel socket = null;
        try {
            AsynchronousChannelGroup group = getChannelGroup();
            channel = openAsynchronousSocketChannel(address, group);
            socket = setSocketOptions(channel);
            if (localAddress != null) {
                socket.bind(localAddress);
            }
            Nio2CompletionHandler<Void, Object> completionHandler = ValidateUtils.checkNotNull(
                    createConnectionCompletionHandler(
                            future, socket, context, getFactoryManager(), getIoHandler()),
                    "No connection completion handler created for %s",
                    address);
            socket.connect(address, null, completionHandler);
        } catch (Throwable exc) {
            Throwable t = GenericUtils.peelException(exc);
            debug("connect({}) failed ({}) to schedule connection: {}",
                    address, t.getClass().getSimpleName(), t.getMessage(), t);

            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException err) {
                if (debugEnabled) {
                    log.debug("connect({}) - failed ({}) to close socket: {}",
                            address, err.getClass().getSimpleName(), err.getMessage());
                }
            }

            try {
                if (channel != null) {
                    channel.close();
                }
            } catch (IOException err) {
                if (debugEnabled) {
                    log.debug("connect({}) - failed ({}) to close channel: {}",
                            address, err.getClass().getSimpleName(), err.getMessage());
                }
            }

            future.setException(t);
        }

        return future;
    }

    protected AsynchronousSocketChannel openAsynchronousSocketChannel(
            SocketAddress address, AsynchronousChannelGroup group)
            throws IOException {
        return AsynchronousSocketChannel.open(group);
    }

    protected Nio2CompletionHandler<Void, Object> createConnectionCompletionHandler(
            IoConnectFuture future, AsynchronousSocketChannel socket,
            AttributeRepository context, FactoryManager manager, IoHandler handler) {
        return new ConnectionCompletionHandler(future, socket, context, manager, handler);
    }

    protected class ConnectionCompletionHandler extends Nio2CompletionHandler<Void, Object> {
        protected final IoConnectFuture future;
        protected final AsynchronousSocketChannel socket;
        protected final AttributeRepository context;
        protected final FactoryManager manager;
        protected final IoHandler handler;

        protected ConnectionCompletionHandler(
                                              IoConnectFuture future, AsynchronousSocketChannel socket,
                                              AttributeRepository context, FactoryManager manager, IoHandler handler) {
            this.future = future;
            this.socket = socket;
            this.context = context;
            this.manager = manager;
            this.handler = handler;
        }

        @Override
        @SuppressWarnings("synthetic-access")
        protected void onCompleted(Void result, Object attachment) {
            Long sessionId = null;
            IoServiceEventListener listener = getIoServiceEventListener();
            try {
                if (listener != null) {
                    SocketAddress local = socket.getLocalAddress();
                    SocketAddress remote = socket.getRemoteAddress();
                    listener.connectionEstablished(Nio2Connector.this, local, context, remote);
                }

                Nio2Session session = createSession(manager, handler, socket);
                if (context != null) {
                    session.setAttribute(AttributeRepository.class, context);
                }

                handler.sessionCreated(session);
                sessionId = session.getId();
                sessions.put(sessionId, session);
                future.setSession(session);
                if (session.isClosing()) {
                    try {
                        handler.sessionClosed(session);
                    } finally {
                        unmapSession(sessionId);
                    }
                } else {
                    session.startReading();
                }
            } catch (Throwable exc) {
                Throwable t = GenericUtils.peelException(exc);
                boolean debugEnabled = log.isDebugEnabled();
                if (listener != null) {
                    try {
                        SocketAddress localAddress = socket.getLocalAddress();
                        SocketAddress remoteAddress = socket.getRemoteAddress();
                        listener.abortEstablishedConnection(
                                Nio2Connector.this, localAddress, context, remoteAddress, t);
                    } catch (Exception e) {
                        if (debugEnabled) {
                            log.debug("onCompleted() listener=" + listener + " ignoring abort event exception", e);
                        }
                    }
                }

                debug("onCompleted - failed {} to start session: {}",
                        t.getClass().getSimpleName(), t.getMessage(), t);

                try {
                    socket.close();
                } catch (IOException err) {
                    if (debugEnabled) {
                        log.debug("onCompleted - failed {} to close socket: {}",
                                err.getClass().getSimpleName(), err.getMessage());
                    }
                }

                future.setException(t);
                unmapSession(sessionId);
            }
        }

        @Override
        protected void onFailed(Throwable exc, Object attachment) {
            future.setException(exc);
        }
    }

    protected Nio2Session createSession(
            FactoryManager manager, IoHandler handler, AsynchronousSocketChannel socket)
            throws Throwable {
        return new Nio2Session(this, manager, handler, socket, null);
    }

    public static class DefaultIoConnectFuture extends DefaultSshFuture<IoConnectFuture> implements IoConnectFuture {
        public DefaultIoConnectFuture(Object id, Object lock) {
            super(id, lock);
        }

        @Override
        public IoSession getSession() {
            Object v = getValue();
            return v instanceof IoSession ? (IoSession) v : null;
        }

        @Override
        public Throwable getException() {
            Object v = getValue();
            return v instanceof Throwable ? (Throwable) v : null;
        }

        @Override
        public boolean isConnected() {
            return getValue() instanceof IoSession;
        }

        @Override
        public void setSession(IoSession session) {
            setValue(session);
        }

        @Override
        public void setException(Throwable exception) {
            setValue(exception);
        }
    }
}
