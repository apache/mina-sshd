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
import java.nio.channels.AsynchronousSocketChannel;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;

/**
 */
public class Nio2Connector extends Nio2Service implements IoConnector {

    public Nio2Connector(FactoryManager manager, IoHandler handler, AsynchronousChannelGroup group) {
        super(manager, handler, group);
    }

    public IoConnectFuture connect(SocketAddress address) {
        logger.debug("Connecting to {}", address);
        final IoConnectFuture future = new DefaultIoConnectFuture(null);
        try {
            final AsynchronousSocketChannel socket = AsynchronousSocketChannel.open(group);
            setOption(socket, FactoryManager.SOCKET_KEEPALIVE, StandardSocketOptions.SO_KEEPALIVE, null);
            setOption(socket, FactoryManager.SOCKET_LINGER, StandardSocketOptions.SO_LINGER, null);
            setOption(socket, FactoryManager.SOCKET_RCVBUF, StandardSocketOptions.SO_RCVBUF, null);
            setOption(socket, FactoryManager.SOCKET_REUSEADDR, StandardSocketOptions.SO_REUSEADDR, Boolean.TRUE);
            setOption(socket, FactoryManager.SOCKET_SNDBUF, StandardSocketOptions.SO_SNDBUF, null);
            setOption(socket, FactoryManager.TCP_NODELAY, StandardSocketOptions.TCP_NODELAY, null);
            socket.connect(address, null, new Nio2CompletionHandler<Void, Object>() {
                protected void onCompleted(Void result, Object attachment) {
                    try {
                        Nio2Session session = new Nio2Session(Nio2Connector.this, handler, socket);
                        handler.sessionCreated(session);
                        sessions.put(session.getId(), session);
                        future.setSession(session);
                        session.startReading();
                    } catch (Throwable e) {
                        try {
                            socket.close();
                        } catch (IOException t) {
                            // Ignore
                        }
                        future.setException(e);
                    }
                }
                protected void onFailed(final Throwable exc, final Object attachment) {
                    future.setException(exc);
                }
            });
        } catch (IOException exc) {
            future.setException(exc);
        }
        return future;
    }

    static class DefaultIoConnectFuture extends DefaultSshFuture<IoConnectFuture> implements IoConnectFuture {
        DefaultIoConnectFuture(Object lock) {
            super(lock);
        }
        public IoSession getSession() {
            Object v = getValue();
            return v instanceof IoSession ? (IoSession) v : null;
        }
        public Throwable getException() {
            Object v = getValue();
            return v instanceof Throwable ? (Throwable) v : null;
        }
        public boolean isConnected() {
            return getValue() instanceof IoSession;
        }
        public void setSession(IoSession session) {
            setValue(session);
        }
        public void setException(Throwable exception) {
            setValue(exception);
        }
    }

}
