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
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.ClosedChannelException;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 */
public class Nio2Session extends AbstractCloseable implements IoSession {

    public static final int DEFAULT_READBUF_SIZE = 32 * 1024;

    private static final AtomicLong SESSION_ID_GENERATOR = new AtomicLong(100L);

    private final long id = SESSION_ID_GENERATOR.incrementAndGet();
    private final Nio2Service service;
    private final IoHandler ioHandler;
    private final AsynchronousSocketChannel socketChannel;
    private final Map<Object, Object> attributes = new HashMap<Object, Object>();
    private final SocketAddress localAddress;
    private final SocketAddress remoteAddress;
    private final FactoryManager manager;
    private final Queue<Nio2DefaultIoWriteFuture> writes = new LinkedTransferQueue<>();
    private final AtomicReference<Nio2DefaultIoWriteFuture> currentWrite = new AtomicReference<>();

    public Nio2Session(Nio2Service service, FactoryManager manager, IoHandler handler, AsynchronousSocketChannel socket) throws IOException {
        this.service = ValidateUtils.checkNotNull(service, "No service instance");
        this.manager = ValidateUtils.checkNotNull(manager, "No factory manager");
        this.ioHandler = ValidateUtils.checkNotNull(handler, "No IoHandler");
        this.socketChannel = ValidateUtils.checkNotNull(socket, "No socket channel");
        this.localAddress = socket.getLocalAddress();
        this.remoteAddress = socket.getRemoteAddress();
        if (log.isDebugEnabled()) {
            log.debug("Creating IoSession on {} from {}", localAddress, remoteAddress);
        }
    }

    @Override
    public long getId() {
        return id;
    }

    @Override
    public Object getAttribute(Object key) {
        return attributes.get(key);
    }

    @Override
    public Object setAttribute(Object key, Object value) {
        return attributes.put(key, value);
    }

    @Override
    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public SocketAddress getLocalAddress() {
        return localAddress;
    }

    public AsynchronousSocketChannel getSocket() {
        return socketChannel;
    }

    public IoHandler getIoHandler() {
        return ioHandler;
    }

    public void suspend() {
        AsynchronousSocketChannel socket = getSocket();
        try {
            socket.shutdownInput();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("suspend({}) failed {{}) to shutdown input: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }
        }

        try {
            socket.shutdownOutput();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("suspend({}) failed {{}) to shutdown output: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    @Override
    public IoWriteFuture write(Buffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("Writing {} bytes", buffer.available());
        }

        ByteBuffer buf = ByteBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
        final Nio2DefaultIoWriteFuture future = new Nio2DefaultIoWriteFuture(null, buf);
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

    protected void exceptionCaught(Throwable exc) {
        if (!closeFuture.isClosed()) {
            AsynchronousSocketChannel socket = getSocket();
            if (isClosing() || !socket.isOpen()) {
                close(true);
            } else {
                IoHandler handler = getIoHandler();
                try {
                    if (log.isDebugEnabled()) {
                        log.debug("exceptionCaught({}) caught {}[{}] - calling handler",
                                  this, exc.getClass().getSimpleName(), exc.getMessage());
                    }
                    handler.exceptionCaught(this, exc);
                } catch (Throwable e) {
                    Throwable t = GenericUtils.peelException(e);
                    if (log.isDebugEnabled()) {
                        log.debug("exceptionCaught({}) Exception handler threw {}, closing the session: {}",
                                  this, t.getClass().getSimpleName(), t.getMessage());
                    }

                    if (log.isTraceEnabled()) {
                        log.trace("exceptionCaught(" + this + ") exception handler failure details", t);
                    }
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
            Nio2DefaultIoWriteFuture future = writes.poll();
            if (future != null) {
                future.setException(new ClosedChannelException());
            } else {
                break;
            }
        }

        AsynchronousSocketChannel socket = getSocket();
        try {
            socket.close();
        } catch (IOException e) {
            log.info("doCloseImmediately(" + this + ") exception caught while closing socket", e);
        }

        service.sessionClosed(this);
        super.doCloseImmediately();

        IoHandler handler = getIoHandler();
        try {
            handler.sessionClosed(this);
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("doCloseImmediately({}) {} while calling IoHandler#sessionClosed: {}",
                          this, e.getClass().getSimpleName(), e.getMessage());
            }

            if (log.isTraceEnabled()) {
                log.trace("doCloseImmediately(" + this + ") IoHandler#sessionClosed failure details", e);
            }
        }
    }

    @Override   // co-variant return
    public Nio2Service getService() {
        return service;
    }

    public void startReading() {
        startReading(PropertyResolverUtils.getIntProperty(manager, FactoryManager.NIO2_READ_BUFFER_SIZE, DEFAULT_READBUF_SIZE));
    }

    public void startReading(int bufSize) {
        startReading(new byte[bufSize]);
    }

    public void startReading(byte[] buf) {
        startReading(buf, 0, buf.length);
    }

    public void startReading(byte[] buf, int offset, int len) {
        startReading(ByteBuffer.wrap(buf, offset, len));
    }

    public void startReading(final ByteBuffer buffer) {
        doReadCycle(buffer, new Readable() {
            @Override
            public int available() {
                return buffer.remaining();
            }

            @Override
            public void getRawBytes(byte[] data, int offset, int len) {
                buffer.get(data, offset, len);
            }
        });
    }

    protected void doReadCycle(ByteBuffer buffer, Readable bufReader) {
        Nio2CompletionHandler<Integer, Object> completion =
                ValidateUtils.checkNotNull(createReadCycleCompletionHandler(buffer, bufReader), "No completion handler created");
        doReadCycle(buffer, completion);
    }

    protected Nio2CompletionHandler<Integer, Object> createReadCycleCompletionHandler(final ByteBuffer buffer, final Readable bufReader) {
        return new Nio2CompletionHandler<Integer, Object>() {
            @Override
            protected void onCompleted(Integer result, Object attachment) {
                handleReadCycleCompletion(buffer, bufReader, this, result, attachment);
            }

            @Override
            protected void onFailed(Throwable exc, Object attachment) {
                handleReadCycleFailure(buffer, bufReader, exc, attachment);
            }
        };
    }

    protected void handleReadCycleCompletion(
            ByteBuffer buffer, Readable bufReader, Nio2CompletionHandler<Integer, Object> completionHandler, Integer result, Object attachment) {
        try {
            if (result >= 0) {
                if (log.isDebugEnabled()) {
                    log.debug("handleReadCycleCompletion({}) read {} bytes", this, result);
                }
                buffer.flip();

                IoHandler handler = getIoHandler();
                handler.messageReceived(this, bufReader);
                if (!closeFuture.isClosed()) {
                    // re-use reference for next iteration since we finished processing it
                    buffer.clear();
                    doReadCycle(buffer, completionHandler);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("handleReadCycleCompletion({}) IoSession has been closed, stop reading", this);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("handleReadCycleCompletion({}) Socket has been disconnected (result={}), closing IoSession now", this, result);
                }
                close(true);
            }
        } catch (Throwable exc) {
            completionHandler.failed(exc, attachment);
        }
    }

    protected void handleReadCycleFailure(ByteBuffer buffer, Readable bufReader, Throwable exc, Object attachment) {
        exceptionCaught(exc);
    }

    protected void doReadCycle(ByteBuffer buffer, Nio2CompletionHandler<Integer, Object> completion) {
        AsynchronousSocketChannel socket = getSocket();
        socket.read(buffer, null, completion);
    }

    protected void startWriting() {
        Nio2DefaultIoWriteFuture future = writes.peek();
        if (future != null) {
            if (currentWrite.compareAndSet(null, future)) {
                try {
                    AsynchronousSocketChannel socket = getSocket();
                    ByteBuffer buffer = future.getBuffer();
                    Nio2CompletionHandler<Integer, Object> handler =
                            ValidateUtils.checkNotNull(createWriteCycleCompletionHandler(future, socket, buffer),
                                                       "No write cycle completion handler created");
                    doWriteCycle(buffer, handler);
                } catch (Throwable e) {
                    future.setWritten();
                    if (e instanceof RuntimeException) {
                        throw (RuntimeException) e;
                    } else {
                        throw new RuntimeSshException(e);
                    }
                }
            }
        }
    }

    protected void doWriteCycle(ByteBuffer buffer, Nio2CompletionHandler<Integer, Object> completion) {
        AsynchronousSocketChannel socket = getSocket();
        socket.write(buffer, null, completion);
    }

    protected Nio2CompletionHandler<Integer, Object> createWriteCycleCompletionHandler(
            final Nio2DefaultIoWriteFuture future, final AsynchronousSocketChannel socket, final ByteBuffer buffer) {
        final int writeLen = buffer.remaining();
        return new Nio2CompletionHandler<Integer, Object>() {
            @Override
            protected void onCompleted(Integer result, Object attachment) {
                handleCompletedWriteCycle(future, socket, buffer, writeLen, this, result, attachment);
            }

            @Override
            protected void onFailed(Throwable exc, Object attachment) {
                handleWriteCycleFailure(future, socket, buffer, writeLen, exc, attachment);
            }
        };
    }

    protected void handleCompletedWriteCycle(
            Nio2DefaultIoWriteFuture future, AsynchronousSocketChannel socket, ByteBuffer buffer, int writeLen,
            Nio2CompletionHandler<Integer, Object> completionHandler, Integer result, Object attachment) {
        if (buffer.hasRemaining()) {
            try {
                socket.write(buffer, null, completionHandler);
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("handleCompletedWriteCycle(" + this + ") Exception caught while writing " + writeLen + " bytes", t);
                }
                future.setWritten();
                finishWrite(future);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("handleCompletedWriteCycle({}) finished writing len={}", this, writeLen);
            }
            future.setWritten();
            finishWrite(future);
        }
    }

    protected void handleWriteCycleFailure(
            Nio2DefaultIoWriteFuture future, AsynchronousSocketChannel socket,
            ByteBuffer buffer, int writeLen, Throwable exc, Object attachment) {
        if (log.isDebugEnabled()) {
            log.debug("handleWriteCycleFailure({}) failed ({}) to write {} bytes: {}",
                      this, exc.getClass().getSimpleName(), writeLen, exc.getMessage());
        }
        if (log.isTraceEnabled()) {
            log.trace("handleWriteCycleFailure(" + this + ") len=" + writeLen + " failure details", exc);
        }
        future.setException(exc);
        exceptionCaught(exc);
        finishWrite(future);
    }

    protected void finishWrite(Nio2DefaultIoWriteFuture future) {
        writes.remove(future);
        currentWrite.compareAndSet(future, null);
        startWriting();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[local=" + getLocalAddress() + ", remote=" + getRemoteAddress() + "]";
    }
}
