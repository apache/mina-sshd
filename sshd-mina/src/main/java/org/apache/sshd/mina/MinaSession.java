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
import java.lang.reflect.Field;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.Channel;
import java.nio.channels.SocketChannel;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MinaSession extends AbstractInnerCloseable implements IoSession {
    public static final Field NIO_SESSION_CHANNEL_FIELD = Stream.of(NioSession.class.getDeclaredFields())
            .filter(f -> "channel".equals(f.getName()))
            .map(f -> {
                f.setAccessible(true);
                return f;
            }).findFirst()
            .orElse(null);

    private final MinaService service;
    private final org.apache.mina.core.session.IoSession session;
    private final Object sessionWriteId;
    private final SocketAddress acceptanceAddress;

    public MinaSession(MinaService service, org.apache.mina.core.session.IoSession session, SocketAddress acceptanceAddress) {
        this.service = service;
        this.session = session;
        this.sessionWriteId = Objects.toString(session);
        this.acceptanceAddress = acceptanceAddress;
    }

    public org.apache.mina.core.session.IoSession getSession() {
        return session;
    }

    public void suspend() {
        session.suspendRead();
        session.suspendWrite();
    }

    @Override
    public Object getAttribute(Object key) {
        return session.getAttribute(key);
    }

    @Override
    public Object setAttribute(Object key, Object value) {
        return session.setAttribute(key, value);
    }

    @Override
    public Object setAttributeIfAbsent(Object key, Object value) {
        return session.setAttributeIfAbsent(key, value);
    }

    @Override
    public Object removeAttribute(Object key) {
        return session.removeAttribute(key);
    }

    @Override
    public SocketAddress getRemoteAddress() {
        return session.getRemoteAddress();
    }

    @Override
    public SocketAddress getLocalAddress() {
        return session.getLocalAddress();
    }

    @Override
    public SocketAddress getAcceptanceAddress() {
        return acceptanceAddress;
    }

    @Override
    public long getId() {
        return session.getId();
    }

    @Override
    protected Closeable getInnerCloseable() {
        return new IoBaseCloseable() {
            @SuppressWarnings("synthetic-access")
            private final DefaultCloseFuture future = new DefaultCloseFuture(MinaSession.this.toString(), futureLock);

            @SuppressWarnings("synthetic-access")
            @Override
            public boolean isClosing() {
                return session.isClosing();
            }

            @SuppressWarnings("synthetic-access")
            @Override
            public boolean isClosed() {
                return !session.isConnected();
            }

            @Override
            public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                future.addListener(listener);
            }

            @Override
            public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
                future.removeListener(listener);
            }

            @SuppressWarnings("synthetic-access")
            @Override
            public org.apache.sshd.common.future.CloseFuture close(boolean immediately) {
                org.apache.mina.core.future.CloseFuture cf = immediately ? session.closeNow() : session.closeOnFlush();
                cf.addListener(f -> future.setValue(Boolean.TRUE));
                return future;
            }
        };
    }

    // NOTE !!! data buffer may NOT be re-used when method returns - at least until IoWriteFuture is signalled
    public IoWriteFuture write(byte[] data) {
        return write(data, 0, NumberUtils.length(data));
    }

    // NOTE !!! data buffer may NOT be re-used when method returns - at least until IoWriteFuture is signalled
    public IoWriteFuture write(byte[] data, int offset, int len) {
        return write(IoBuffer.wrap(data, offset, len));
    }

    @Override // NOTE !!! data buffer may NOT be re-used when method returns - at least until IoWriteFuture is signalled
    public IoWriteFuture writeBuffer(Buffer buffer) {
        return write(MinaSupport.asIoBuffer(buffer));
    }

    // NOTE !!! data buffer may NOT be re-used when method returns - at least until IoWriteFuture is signalled
    public IoWriteFuture write(IoBuffer buffer) {
        Future future = new Future(sessionWriteId, null);
        session.write(buffer)
                .addListener((IoFutureListener<WriteFuture>) cf -> {
                    Throwable t = cf.getException();
                    if (t != null) {
                        future.setException(t);
                    } else {
                        future.setWritten();
                    }
                });
        return future;
    }

    public static class Future extends AbstractIoWriteFuture {
        public Future(Object id, Object lock) {
            super(id, lock);
        }

        public void setWritten() {
            setValue(Boolean.TRUE);
        }

        public void setException(Throwable exception) {
            setValue(Objects.requireNonNull(exception, "No exception specified"));
        }
    }

    @Override
    public IoService getService() {
        return service;
    }

    @Override // see SSHD-902
    public void shutdownOutputStream() throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        if (!(session instanceof NioSession)) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) not a NioSession: {}",
                        session, (session == null) ? null : session.getClass().getSimpleName());
            }
            return;
        }

        if (NIO_SESSION_CHANNEL_FIELD == null) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) missing channel field",
                        session, (session == null) ? null : session.getClass().getSimpleName());
            }
            return;
        }

        Channel channel;
        try {
            channel = (Channel) NIO_SESSION_CHANNEL_FIELD.get(session);
        } catch (Exception t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn("shudownOutputStream({}) failed ({}) to retrieve embedded channel: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            return;
        }

        if (!(channel instanceof SocketChannel)) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) not a SocketChannel: {}",
                        session, (channel == null) ? null : channel.getClass().getSimpleName());
            }
            return;
        }

        Socket socket = ((SocketChannel) channel).socket();
        if (socket.isConnected() && (!socket.isClosed())) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({})", session);
            }
            socket.shutdownOutput();
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[local=" + session.getLocalAddress()
               + ", remote=" + session.getRemoteAddress()
               + "]";
    }
}
