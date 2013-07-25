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
import java.nio.channels.CompletionHandler;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoCloseFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.Readable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public class Nio2Session implements IoSession {

    private static final Logger LOGGER = LoggerFactory.getLogger(Nio2Session.class);
    private static final AtomicLong sessionIdGenerator = new AtomicLong(100);

    private final long id = sessionIdGenerator.incrementAndGet();
    private final Nio2Service service;
    private final IoHandler handler;
    private final AsynchronousSocketChannel socket;
    private final Map<Object, Object> attributes = new HashMap<Object, Object>();
    private final SocketAddress localAddress;
    private final SocketAddress remoteAddress;

    private final AtomicBoolean closing = new AtomicBoolean();
    private final IoCloseFuture closeFuture = new DefaultIoCloseFuture(null);
    private final Queue<DefaultIoWriteFuture> writes = new LinkedTransferQueue<DefaultIoWriteFuture>();
    private final AtomicReference<DefaultIoWriteFuture> currentWrite = new AtomicReference<DefaultIoWriteFuture>();

    public Nio2Session(Nio2Service service, IoHandler handler, AsynchronousSocketChannel socket) throws IOException {
        this.service = service;
        this.handler = handler;
        this.socket = socket;
        this.localAddress = socket.getLocalAddress();
        this.remoteAddress = socket.getRemoteAddress();
        LOGGER.debug("Creating Nio2Session on {} from {}", localAddress, remoteAddress);
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
        LOGGER.debug("Writing {} bytes", buffer.available());
        ByteBuffer buf = ByteBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
        final DefaultIoWriteFuture future = new DefaultIoWriteFuture(null, buf);
        if (closing.get()) {
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
        if (!closing.get()) {
            if (!socket.isOpen()) {
                close(true);
            } else {
                try {
                    LOGGER.debug("Caught exception, now calling handler");
                    handler.exceptionCaught(this, exc);
                } catch (Throwable t) {
                    LOGGER.info("Exception handler threw exception, closing the session", t);
                    close(true);
                }
            }
        }
    }

    private void startWriting() {
        final DefaultIoWriteFuture future = writes.peek();
        if (future != null) {
            if (currentWrite.compareAndSet(null, future)) {
                socket.write(future.buffer, null, new CompletionHandler<Integer, Object>() {
                    public void completed(Integer result, Object attachment) {
                        future.setWritten();
                        finishWrite();
                    }
                    public void failed(Throwable exc, Object attachment) {
                        future.setException(exc);
                        exceptionCaught(exc);
                        finishWrite();
                    }
                    private void finishWrite() {
                        synchronized (writes) {
                            writes.remove(future);
                            writes.notifyAll();
                        }
                        currentWrite.compareAndSet(future, null);
                        startWriting();
                    }
                });
            }
        }
    }

    public IoCloseFuture close(boolean immediately) {
        if (closing.compareAndSet(false, true)) {
            LOGGER.debug("Closing Nio2Session");
            if (!immediately) {
                try {
                    boolean logged = false;
                    synchronized (writes) {
                        while (!writes.isEmpty()) {
                            if (!logged) {
                                LOGGER.debug("Waiting for writes to finish");
                                logged = true;
                            }
                            writes.wait();
                        }
                    }
                } catch (InterruptedException e) {
                    // Wait has been interrupted, just close the socket
                }
            }
            for (;;) {
                DefaultIoWriteFuture future = writes.poll();
                if (future != null) {
                    future.setException(new ClosedChannelException());
                } else {
                    break;
                }
            }
            try {
                LOGGER.debug("Closing socket");
                socket.close();
            } catch (IOException e) {
                LOGGER.info("Exception caught while closing session", e);
            }
            service.sessionClosed(this);
            closeFuture.setClosed();
            try {
                handler.sessionClosed(this);
            } catch (Exception e) {
                // Ignore
                LOGGER.debug("Exception caught while calling IoHandler#sessionClosed", e);
            }
        }
        return closeFuture;
    }

    public IoService getService() {
        return service;
    }

    public void startReading() {
        final ByteBuffer buffer = ByteBuffer.allocate(32 * 1024);
        socket.read(buffer, null, new CompletionHandler<Integer, Object>() {
            public void completed(Integer result, Object attachment) {
                try {
                    if (result >= 0) {
                        LOGGER.debug("Read {} bytes", result);
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
                        startReading();
                    } else {
                        LOGGER.debug("Socket has been disconnected, closing IoSession now");
                        Nio2Session.this.close(true);
                    }
                } catch (Throwable exc) {
                    failed(exc, attachment);
                }
            }
            public void failed(Throwable exc, Object attachment) {
                exceptionCaught(exc);
            }
        });
    }

    static class DefaultIoCloseFuture extends DefaultSshFuture<IoCloseFuture> implements IoCloseFuture {
        DefaultIoCloseFuture(Object lock) {
            super(lock);
        }
        public boolean isClosed() {
            return getValue() instanceof Boolean;
        }
        public void setClosed() {
            setValue(Boolean.TRUE);
        }
    }

    static class DefaultIoWriteFuture extends DefaultSshFuture<IoWriteFuture> implements IoWriteFuture {
        private final ByteBuffer buffer;
        DefaultIoWriteFuture(Object lock, ByteBuffer buffer) {
            super(lock);
            this.buffer = buffer;
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
}
