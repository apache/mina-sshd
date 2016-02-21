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

import java.net.SocketAddress;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.IoFuture;
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
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;

/**
 */
public class MinaSession extends AbstractInnerCloseable implements IoSession {

    private final MinaService service;
    private final org.apache.mina.core.session.IoSession session;

    public MinaSession(MinaService service, org.apache.mina.core.session.IoSession session) {
        this.service = service;
        this.session = session;
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
    public SocketAddress getRemoteAddress() {
        return session.getRemoteAddress();
    }

    @Override
    public SocketAddress getLocalAddress() {
        return session.getLocalAddress();
    }

    @Override
    public long getId() {
        return session.getId();
    }

    @Override
    protected Closeable getInnerCloseable() {
        return new IoBaseCloseable() {
            @SuppressWarnings("synthetic-access")
            private final DefaultCloseFuture future = new DefaultCloseFuture(lock);

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
                session.close(false).addListener(new IoFutureListener<IoFuture>() {
                    @Override
                    public void operationComplete(IoFuture f) {
                        future.setValue(Boolean.TRUE);
                    }
                });
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
    public IoWriteFuture write(Buffer buffer) {
        return write(MinaSupport.asIoBuffer(buffer));
    }

    // NOTE !!! data buffer may NOT be re-used when method returns - at least until IoWriteFuture is signalled
    public IoWriteFuture write(IoBuffer buffer) {
        final Future future = new Future(null);
        session.write(buffer).addListener(new IoFutureListener<WriteFuture>() {
            @Override
            public void operationComplete(WriteFuture cf) {
                Throwable t = cf.getException();
                if (t != null) {
                    future.setException(t);
                } else {
                    future.setWritten();
                }
            }
        });
        return future;
    }

    public static class Future extends AbstractIoWriteFuture {
        public Future(Object lock) {
            super(lock);
        }

        public void setWritten() {
            setValue(Boolean.TRUE);
        }

        public void setException(Throwable exception) {
            setValue(ValidateUtils.checkNotNull(exception, "No exception specified"));
        }
    }

    @Override
    public IoService getService() {
        return service;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[local=" + session.getLocalAddress() + ", remote=" + session.getRemoteAddress() + "]";
    }
}
