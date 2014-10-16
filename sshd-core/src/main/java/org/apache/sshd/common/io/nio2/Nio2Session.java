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
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.ClosedChannelException;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.Readable;

/**
 */
public class Nio2Session extends CloseableUtils.AbstractCloseable implements IoSession {

    private static final AtomicLong sessionIdGenerator = new AtomicLong(100);

    private final long id = sessionIdGenerator.incrementAndGet();
    private final Nio2Service service;
    private final IoHandler handler;
    private final AsynchronousSocketChannel socket;
    private final Map<Object, Object> attributes = new HashMap<Object, Object>();
    private final SocketAddress localAddress;
    private final SocketAddress remoteAddress;

    private final Queue<DefaultIoWriteFuture> writes = new LinkedTransferQueue<DefaultIoWriteFuture>();
    private final AtomicReference<DefaultIoWriteFuture> currentWrite = new AtomicReference<DefaultIoWriteFuture>();

    public Nio2Session(Nio2Service service, IoHandler handler, AsynchronousSocketChannel socket) throws IOException {
        this.service = service;
        this.handler = handler;
        this.socket = socket;
        this.localAddress = socket.getLocalAddress();
        this.remoteAddress = socket.getRemoteAddress();
        log.debug("Creating IoSession on {} from {}", localAddress, remoteAddress);
    }

    public long getId() {
        return id;
    }

    public Object getAttribute(Object key) {
        return attributes.get(key);
    }

    public Object setAttribute(Object key, Object value) {
        return attributes.put(key, value);
    }

    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public SocketAddress getLocalAddress() {
        return localAddress;
    }

    public void suspend() {
        try {
            this.socket.shutdownInput();
        } catch (IOException e) {
            // Ignore
        }
        try {
            this.socket.shutdownOutput();
        } catch (IOException e) {
            // Ignore
        }
    }

    public IoWriteFuture write(Buffer buffer) {
        log.debug("Writing {} bytes", buffer.available());
        ByteBuffer buf = ByteBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
        final DefaultIoWriteFuture future = new DefaultIoWriteFuture(null, buf);
        if (isClosing()) {
            Throwable exc = new ClosedChannelException();
            future.setException(exc);
            exceptionCaught(exc);
            return future;
        }
        writes.add(future);
        startWriting();
        return future;
    }

    private void exceptionCaught(Throwable exc) {
        if (!closeFuture.isClosed()) {
            if (isClosing() || !socket.isOpen()) {
                close(true);
            } else {
                try {
                    log.debug("Caught exception, now calling handler");
                    handler.exceptionCaught(this, exc);
                } catch (Throwable t) {
                    log.info("Exception handler threw exception, closing the session", t);
                    close(true);
                }
            }
        }
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        return builder().when(writes).build().close(false);
    }

    @Override
    protected void doCloseImmediately() {
        for (;;) {
            DefaultIoWriteFuture future = writes.poll();
            if (future != null) {
                future.setException(new ClosedChannelException());
            } else {
                break;
            }
        }
        try {
            socket.close();
        } catch (IOException e) {
            log.info("Exception caught while closing socket", e);
        }
        service.sessionClosed(this);
        super.doCloseImmediately();
        try {
            handler.sessionClosed(this);
        } catch (Exception e) {
            // Ignore
            log.debug("Exception caught while calling IoHandler#sessionClosed", e);
        }
    }

    public IoService getService() {
        return service;
    }

    public void startReading() {
        final ByteBuffer buffer = ByteBuffer.allocate(32 * 1024);
        socket.read(buffer, null, new Nio2CompletionHandler<Integer, Object>() {
            protected void onCompleted(Integer result, Object attachment) {
                try {
                    if (result >= 0) {
                        log.debug("Read {} bytes", result);
                        buffer.flip();
                        Readable buf = new Readable() {
                            public int available() {
                                return buffer.remaining();
                            }
                            public void getRawBytes(byte[] data, int offset, int len) {
                                buffer.get(data, offset, len);
                            }
                        };
                        handler.messageReceived(Nio2Session.this, buf);
                        if (!closeFuture.isClosed()) {
                            startReading();
                        } else {
                            log.debug("IoSession has been closed, stop reading");
                        }
                    } else {
                        log.debug("Socket has been disconnected, closing IoSession now");
                        Nio2Session.this.close(true);
                    }
                } catch (Throwable exc) {
                    failed(exc, attachment);
                }
            }
            protected void onFailed(Throwable exc, Object attachment) {
                exceptionCaught(exc);
            }
        });
    }

    private void startWriting() {
        final DefaultIoWriteFuture future = writes.peek();
        if (future != null) {
            if (currentWrite.compareAndSet(null, future)) {
                try {
                    socket.write(future.buffer, null, new Nio2CompletionHandler<Integer, Object>() {
                        protected void onCompleted(Integer result, Object attachment) {
                            if (future.buffer.hasRemaining()) {
                                try {
                                    socket.write(future.buffer, null, this);
                                } catch (Throwable t) {
                                    log.debug("Exception caught while writing", t);
                                    future.setWritten();
                                    finishWrite();
                                }
                            } else {
                                log.debug("Finished writing");
                                future.setWritten();
                                finishWrite();
                            }
                        }
                        protected void onFailed(Throwable exc, Object attachment) {
                            future.setException(exc);
                            exceptionCaught(exc);
                            finishWrite();
                        }
                        private void finishWrite() {
                            writes.remove(future);
                            currentWrite.compareAndSet(future, null);
                            startWriting();
                        }
                    });
                } catch (RuntimeException e) {
                    future.setWritten();
                    throw e;
                }
            }
        }
    }

    static class DefaultIoWriteFuture extends DefaultSshFuture<IoWriteFuture> implements IoWriteFuture {
        private final ByteBuffer buffer;
        DefaultIoWriteFuture(Object lock, ByteBuffer buffer) {
            super(lock);
            this.buffer = buffer;
        }
        public void verify() throws SshException {
            try {
                await();
            }
            catch (InterruptedException e) {
                throw new SshException("Interrupted", e);
            }
            if (!isWritten()) {
                throw new SshException("Write failed", getException());
            }
        }

        public boolean isWritten() {
            return getValue() instanceof Boolean;
        }
        public void setWritten() {
            setValue(Boolean.TRUE);
        }
        public Throwable getException() {
            Object v = getValue();
            return v instanceof Throwable ? (Throwable) v : null;
        }
        public void setException(Throwable exception) {
            if (exception == null) {
                throw new IllegalArgumentException("exception");
            }
            setValue(exception);
        }
    }

    public String toString() {
        return getClass().getSimpleName() + "[local=" + localAddress + ", remote=" + remoteAddress + "]";
    }
}
