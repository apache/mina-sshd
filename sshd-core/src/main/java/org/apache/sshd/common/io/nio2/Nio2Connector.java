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
import java.net.StandardSocketOptions;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 */
public class Nio2Connector extends Nio2Service implements IoConnector {
    public Nio2Connector(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
    }

    @Override
    public IoConnectFuture connect(SocketAddress address) {
        if (log.isDebugEnabled()) {
            log.debug("Connecting to {}", address);
        }

        IoConnectFuture future = new DefaultIoConnectFuture(null);
        try {
            AsynchronousChannelGroup group = getChannelGroup();
            AsynchronousSocketChannel socket = openAsynchronousSocketChannel(address, group);
            setOption(socket, FactoryManager.SOCKET_KEEPALIVE, StandardSocketOptions.SO_KEEPALIVE, null);
            setOption(socket, FactoryManager.SOCKET_LINGER, StandardSocketOptions.SO_LINGER, null);
            setOption(socket, FactoryManager.SOCKET_RCVBUF, StandardSocketOptions.SO_RCVBUF, null);
            setOption(socket, FactoryManager.SOCKET_REUSEADDR, StandardSocketOptions.SO_REUSEADDR, Boolean.TRUE);
            setOption(socket, FactoryManager.SOCKET_SNDBUF, StandardSocketOptions.SO_SNDBUF, null);
            setOption(socket, FactoryManager.TCP_NODELAY, StandardSocketOptions.TCP_NODELAY, null);

            Nio2CompletionHandler<Void, Object> completionHandler =
                    ValidateUtils.checkNotNull(createConnectionCompletionHandler(future, socket, getFactoryManager(), getIoHandler()),
                                               "No connection completion handler created for %s",
                                               address);
            socket.connect(address, null, completionHandler);
        } catch (Throwable exc) {
            Throwable t = GenericUtils.peelException(exc);
            if (log.isDebugEnabled()) {
                log.debug("connect({}) failed ({}) to schedule connection: {}",
                          address, t.getClass().getSimpleName(), t.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("connect(" + address + ") connection failure details", t);
            }
            future.setException(t);
        }
        return future;
    }

    protected AsynchronousSocketChannel openAsynchronousSocketChannel(
            SocketAddress address, AsynchronousChannelGroup group) throws IOException {
        return AsynchronousSocketChannel.open(group);
    }

    protected Nio2CompletionHandler<Void, Object> createConnectionCompletionHandler(
            final IoConnectFuture future, final AsynchronousSocketChannel socket, final FactoryManager manager, final IoHandler handler) {
        return new Nio2CompletionHandler<Void, Object>() {
            @Override
            @SuppressWarnings("synthetic-access")
            protected void onCompleted(Void result, Object attachment) {
                try {
                    Nio2Session session = createSession(manager, handler, socket);
                    handler.sessionCreated(session);
                    sessions.put(session.getId(), session);
                    future.setSession(session);
                    session.startReading();
                } catch (Throwable exc) {
                    Throwable t = GenericUtils.peelException(exc);
                    if (log.isDebugEnabled()) {
                        log.debug("onCompleted - failed {} to start session: {}",
                                  t.getClass().getSimpleName(), t.getMessage());
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("onCompleted - session creation failure details", t);
                    }
                    try {
                        socket.close();
                    } catch (IOException err) {
                        if (log.isDebugEnabled()) {
                            log.debug("onCompleted - failed {} to close socket: {}", err.getClass().getSimpleName(), err.getMessage());
                        }
                    }
                    future.setException(t);
                }
            }

            @Override
            protected void onFailed(final Throwable exc, final Object attachment) {
                future.setException(exc);
            }
        };
    }

    protected Nio2Session createSession(FactoryManager manager, IoHandler handler, AsynchronousSocketChannel socket) throws Throwable {
        return new Nio2Session(this, manager, handler, socket);
    }

    public static class DefaultIoConnectFuture extends DefaultSshFuture<IoConnectFuture> implements IoConnectFuture {
        public DefaultIoConnectFuture(Object lock) {
            super(lock);
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
