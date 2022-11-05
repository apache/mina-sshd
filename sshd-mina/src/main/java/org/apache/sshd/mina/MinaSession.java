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
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MinaSession extends AbstractInnerCloseable implements IoSession {

    private final MinaService service;
    private final org.apache.mina.core.session.IoSession session;
    private final Object sessionWriteId;
    private final SocketAddress acceptanceAddress;
    private final AtomicBoolean readSuspended = new AtomicBoolean();

    public MinaSession(MinaService service, org.apache.mina.core.session.IoSession session, SocketAddress acceptanceAddress) {
        this.service = service;
        this.session = session;
        this.sessionWriteId = Objects.toString(session);
        this.acceptanceAddress = acceptanceAddress;
    }

    public org.apache.mina.core.session.IoSession getSession() {
        return session;
    }

    @Override
    public void suspendRead() {
        if (!readSuspended.getAndSet(true)) {
            session.suspendRead();
        }
    }

    @Override
    public void resumeRead() {
        if (readSuspended.getAndSet(false)) {
            session.resumeRead();
        }
    }

    /**
     * Intended for tests simulating a sudden connection drop only! Do not call otherwise.
     */
    public void suspend() {
        // Invoked reflectively in org.apache.sshd.client.ClientTest
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
        return new IoSessionCloser(this.toString(), session, futureLock);
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

    @Override // see SSHD-902 and SSHD-1055
    public void shutdownOutputStream() throws IOException {
        // There is no direct way to get the socket to call socket.shutdownOutput(). It would be possible to do so via
        // reflection, but we'd lose any pending writes, and it seems to confuse MINA quite a bit. Instead, schedule the
        // MINA session to be closed once all pending writes have been written.
        session.closeOnFlush();
    }

    private static class IoSessionCloser extends IoBaseCloseable {

        private final DefaultCloseFuture future;

        private final org.apache.mina.core.session.IoSession session;

        IoSessionCloser(String id, org.apache.mina.core.session.IoSession session, Object futureLock) {
            this.session = session;
            future = new DefaultCloseFuture(id, futureLock);
        }

        @Override
        public boolean isClosing() {
            return session.isClosing();
        }

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

        @Override
        public CloseFuture close(boolean immediately) {
            org.apache.mina.core.future.CloseFuture cf = immediately ? session.closeNow() : session.closeOnFlush();
            cf.addListener(f -> future.setValue(Boolean.TRUE));
            return future;
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
