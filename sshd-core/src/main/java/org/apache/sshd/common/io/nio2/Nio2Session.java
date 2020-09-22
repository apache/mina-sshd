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
import java.io.WriteAbortedException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2Session extends AbstractCloseable implements IoSession {

    public static final int DEFAULT_READBUF_SIZE = 32 * 1024;

    private static final AtomicLong SESSION_ID_GENERATOR = new AtomicLong(100L);

    private final long id = SESSION_ID_GENERATOR.incrementAndGet();
    private final Nio2Service service;
    private final IoHandler ioHandler;
    private final AsynchronousSocketChannel socketChannel;
    private final Map<Object, Object> attributes = new HashMap<>();
    private final SocketAddress localAddress;
    private final SocketAddress remoteAddress;
    private final SocketAddress acceptanceAddress;
    private final FactoryManager manager;
    private final Queue<Nio2DefaultIoWriteFuture> writes = new LinkedTransferQueue<>();
    private final AtomicReference<Nio2DefaultIoWriteFuture> currentWrite = new AtomicReference<>();
    private final AtomicLong readCyclesCounter = new AtomicLong();
    private final AtomicLong lastReadCycleStart = new AtomicLong();
    private final AtomicLong writeCyclesCounter = new AtomicLong();
    private final AtomicLong lastWriteCycleStart = new AtomicLong();
    private final Object suspendLock = new Object();
    private volatile boolean suspend;
    private volatile Runnable readRunnable;

    public Nio2Session(
                       Nio2Service service, FactoryManager manager, IoHandler handler, AsynchronousSocketChannel socket,
                       SocketAddress acceptanceAddress)
                                                        throws IOException {
        this.service = Objects.requireNonNull(service, "No service instance");
        this.manager = Objects.requireNonNull(manager, "No factory manager");
        this.ioHandler = Objects.requireNonNull(handler, "No IoHandler");
        this.socketChannel = Objects.requireNonNull(socket, "No socket channel");
        this.localAddress = socket.getLocalAddress();
        this.remoteAddress = socket.getRemoteAddress();
        this.acceptanceAddress = acceptanceAddress;
        if (log.isDebugEnabled()) {
            log.debug("Creating IoSession on {} from {} via {}", localAddress, remoteAddress, acceptanceAddress);
        }
    }

    @Override
    public long getId() {
        return id;
    }

    @Override
    public Object getAttribute(Object key) {
        synchronized (attributes) {
            return attributes.get(key);
        }
    }

    @Override
    public Object setAttribute(Object key, Object value) {
        synchronized (attributes) {
            return attributes.put(key, value);
        }
    }

    @Override
    public Object setAttributeIfAbsent(Object key, Object value) {
        synchronized (attributes) {
            return attributes.putIfAbsent(key, value);
        }
    }

    @Override
    public Object removeAttribute(Object key) {
        synchronized (attributes) {
            return attributes.remove(key);
        }
    }

    @Override
    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public SocketAddress getLocalAddress() {
        return localAddress;
    }

    @Override
    public SocketAddress getAcceptanceAddress() {
        return acceptanceAddress;
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
            debug("suspend({}) failed ({}) to shutdown input: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
        }

        try {
            socket.shutdownOutput();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                debug("suspend({}) failed ({}) to shutdown output: {}",
                        this, e.getClass().getSimpleName(), e.getMessage(), e);
            }
        }
    }

    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("writeBuffer({}) writing {} bytes", this, buffer.available());
        }

        ByteBuffer buf = ByteBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
        Nio2DefaultIoWriteFuture future = new Nio2DefaultIoWriteFuture(getRemoteAddress(), null, buf);
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
        if (closeFuture.isClosed()) {
            return;
        }

        AsynchronousSocketChannel socket = getSocket();
        if (isOpen() && socket.isOpen()) {
            IoHandler handler = getIoHandler();
            try {
                if (log.isDebugEnabled()) {
                    log.debug("exceptionCaught({}) caught {}[{}] - calling handler",
                            this, exc.getClass().getSimpleName(), exc.getMessage());
                }
                handler.exceptionCaught(this, exc);
            } catch (Throwable e) {
                Throwable t = GenericUtils.peelException(e);
                debug("exceptionCaught({}) Exception handler threw {}, closing the session: {}",
                        this, t.getClass().getSimpleName(), t.getMessage(), t);
            }
        }

        close(true);
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        Object closeId = toString();
        return builder()
                .when(closeId, writes)
                .run(closeId, () -> {
                    try {
                        AsynchronousSocketChannel socket = getSocket();
                        socket.shutdownOutput();
                    } catch (IOException e) {
                        info("doCloseGracefully({}) {} while shutting down output: {}",
                                this, e.getClass().getSimpleName(), e.getMessage(), e);
                    }
                }).build()
                .close(false);
    }

    @Override
    protected void doCloseImmediately() {
        boolean debugEnabled = log.isDebugEnabled();
        while (true) {
            // Cancel pending requests informing them of the cancellation
            Nio2DefaultIoWriteFuture future = writes.poll();
            if (future != null) {
                if (future.isWritten()) {
                    if (debugEnabled) {
                        log.debug("doCloseImmediately({}) skip already written future={}", this, future);
                    }
                    continue;
                }

                Throwable error = future.getException();
                if (error == null) {
                    if (debugEnabled) {
                        log.debug("doCloseImmediately({}) signal write abort for future={}", this, future);
                    }
                    future.setException(
                            new WriteAbortedException("Write request aborted due to immediate session close", null));
                }
            } else {
                break;
            }
        }

        AsynchronousSocketChannel socket = getSocket();
        try {
            if (debugEnabled) {
                log.debug("doCloseImmediately({}) closing socket={}", this, socket);
            }

            socket.close();

            if (debugEnabled) {
                log.debug("doCloseImmediately({}) socket={} closed", this, socket);
            }
        } catch (IOException e) {
            debug("doCloseImmediately({}) {} caught while closing socket={}: {}",
                    this, e.getClass().getSimpleName(), socket, e.getMessage(), e);
        }

        service.sessionClosed(this);
        super.doCloseImmediately();

        IoHandler handler = getIoHandler();
        try {
            handler.sessionClosed(this);
        } catch (Throwable e) {
            debug("doCloseImmediately({}) {} while calling IoHandler#sessionClosed: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
        }

        synchronized (attributes) {
            attributes.clear();
        }
    }

    @Override // co-variant return
    public Nio2Service getService() {
        return service;
    }

    @Override
    public void shutdownOutputStream() throws IOException {
        AsynchronousSocketChannel socket = getSocket();
        if (socket.isOpen()) {
            if (log.isDebugEnabled()) {
                log.debug("shudownOutputStream({})", this);
            }
            socket.shutdownOutput();
        }
    }

    public void startReading() {
        startReading(CoreModuleProperties.NIO2_READ_BUFFER_SIZE.getRequired(manager));
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

    public void startReading(ByteBuffer buffer) {
        doReadCycle(buffer, Readable.readable(buffer));
    }

    protected void doReadCycle(ByteBuffer buffer, Readable bufReader) {
        Nio2CompletionHandler<Integer, Object> completion = Objects.requireNonNull(
                createReadCycleCompletionHandler(buffer, bufReader),
                "No completion handler created");
        doReadCycle(buffer, completion);
    }

    protected Nio2CompletionHandler<Integer, Object> createReadCycleCompletionHandler(
            ByteBuffer buffer, Readable bufReader) {
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
            ByteBuffer buffer, Readable bufReader, Nio2CompletionHandler<Integer, Object> completionHandler,
            Integer result, Object attachment) {
        try {
            boolean debugEnabled = log.isDebugEnabled();
            if (result >= 0) {
                if (log.isTraceEnabled()) {
                    log.trace("handleReadCycleCompletion({}) read {} bytes after {} nanos at cycle={}",
                            this, result, System.nanoTime() - lastReadCycleStart.get(), readCyclesCounter);
                }
                buffer.flip();

                IoHandler handler = getIoHandler();
                handler.messageReceived(this, bufReader);
                if (!closeFuture.isClosed()) {
                    // re-use reference for next iteration since we finished processing it
                    buffer.clear();
                    doReadCycle(buffer, completionHandler);
                } else {
                    if (debugEnabled) {
                        log.debug("handleReadCycleCompletion({}) IoSession has been closed, stop reading", this);
                    }
                }
            } else {
                if (debugEnabled) {
                    log.debug("handleReadCycleCompletion({}) Socket has been disconnected (result={}), closing IoSession now",
                            this, result);
                }
                close(true);
            }
        } catch (Throwable exc) {
            completionHandler.failed(exc, attachment);
        }
    }

    protected void handleReadCycleFailure(ByteBuffer buffer, Readable bufReader, Throwable exc, Object attachment) {
        debug("handleReadCycleFailure({}) {} after {} nanos at read cycle={}: {}",
                this, exc.getClass().getSimpleName(), System.nanoTime() - lastReadCycleStart.get(),
                readCyclesCounter, exc.getMessage(), exc);

        exceptionCaught(exc);
    }

    @Override
    public void suspendRead() {
        log.trace("suspendRead({})", this);
        boolean prev = suspend;
        suspend = true;
        if (!prev) {
            log.debug("suspendRead({}) requesting read suspension", this);
        }
    }

    @Override
    public void resumeRead() {
        log.trace("resumeRead({})", this);
        if (suspend) {
            Runnable runnable;
            synchronized (suspendLock) {
                suspend = false;
                runnable = readRunnable;
            }
            if (runnable != null) {
                log.debug("resumeRead({}) resuming read", this);
                runnable.run();
            }
        }
    }

    protected void doReadCycle(ByteBuffer buffer, Nio2CompletionHandler<Integer, Object> completion) {
        if (suspend) {
            log.debug("doReadCycle({}) suspending reading", this);
            synchronized (suspendLock) {
                if (suspend) {
                    readRunnable = () -> doReadCycle(buffer, completion);
                    return;
                }
            }
        }

        AsynchronousSocketChannel socket = getSocket();
        Duration readTimeout = CoreModuleProperties.NIO2_READ_TIMEOUT.getRequired(manager);
        readCyclesCounter.incrementAndGet();
        lastReadCycleStart.set(System.nanoTime());
        socket.read(buffer, readTimeout.toMillis(), TimeUnit.MILLISECONDS, null, completion);
    }

    protected void startWriting() {
        Nio2DefaultIoWriteFuture future = writes.peek();
        if (future == null) {
            return;
        }

        if (!currentWrite.compareAndSet(null, future)) {
            return;
        }

        try {
            AsynchronousSocketChannel socket = getSocket();
            ByteBuffer buffer = future.getBuffer();
            Nio2CompletionHandler<Integer, Object> handler = Objects.requireNonNull(
                    createWriteCycleCompletionHandler(future, socket, buffer),
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

    protected void doWriteCycle(ByteBuffer buffer, Nio2CompletionHandler<Integer, Object> completion) {
        AsynchronousSocketChannel socket = getSocket();
        Duration writeTimeout = CoreModuleProperties.NIO2_MIN_WRITE_TIMEOUT.getRequired(manager);
        writeCyclesCounter.incrementAndGet();
        lastWriteCycleStart.set(System.nanoTime());
        socket.write(buffer, writeTimeout.toMillis(), TimeUnit.MILLISECONDS, null, completion);
    }

    protected Nio2CompletionHandler<Integer, Object> createWriteCycleCompletionHandler(
            Nio2DefaultIoWriteFuture future, AsynchronousSocketChannel socket, ByteBuffer buffer) {
        int writeLen = buffer.remaining();
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
                debug("handleCompletedWriteCycle({}) {} while writing to socket len={}: {}",
                        this, t.getClass().getSimpleName(), writeLen, t.getMessage(), t);
                future.setWritten();
                finishWrite(future);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("handleCompletedWriteCycle({}) finished writing len={} at cycle={} after {} nanos",
                        this, writeLen, writeCyclesCounter, System.nanoTime() - lastWriteCycleStart.get());
            }

            // This should be called before future.setWritten() to avoid WriteAbortedException
            // to be thrown by doCloseImmediately when called in the listener of doCloseGracefully
            writes.remove(future);

            future.setWritten();
            finishWrite(future);
        }
    }

    protected void handleWriteCycleFailure(
            Nio2DefaultIoWriteFuture future, AsynchronousSocketChannel socket,
            ByteBuffer buffer, int writeLen, Throwable exc, Object attachment) {
        if (log.isDebugEnabled()) {
            debug("handleWriteCycleFailure({}) failed ({}) to write {} bytes at write cycle={} afer {} nanos: {}",
                    this, exc.getClass().getSimpleName(), writeLen, writeCyclesCounter,
                    System.nanoTime() - lastWriteCycleStart.get(), exc.getMessage(), exc);
        }

        future.setException(exc);
        exceptionCaught(exc);

        // see SSHD-743
        try {
            finishWrite(future);
        } catch (RuntimeException e) {
            if (log.isTraceEnabled()) {
                log.trace("handleWriteCycleFailure({}) failed ({}) to finish writing: {}",
                        this, e.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    protected void finishWrite(Nio2DefaultIoWriteFuture future) {
        writes.remove(future);
        currentWrite.compareAndSet(future, null);
        startWriting();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[local=" + getLocalAddress()
               + ", remote=" + getRemoteAddress()
               + "]";
    }
}
