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
package org.apache.sshd.agent.unix;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StreamCorruptedException;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerHolder;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * A client for a remote SSH agent
 */
public class AgentClient extends AbstractAgentProxy implements Runnable, FactoryManagerHolder {
    /**
     * Time to wait for new incoming messages before checking if the client is still active
     */
    public static final String MESSAGE_POLL_FREQUENCY = "agent-client-message-poll-time";

    /**
     * Default value for {@value #MESSAGE_POLL_FREQUENCY}
     */
    public static final long DEFAULT_MESSAGE_POLL_FREQUENCY = TimeUnit.MINUTES.toMillis(2L);

    private final String authSocket;
    private final FactoryManager manager;
    private final long pool;
    private final long handle;
    private final Buffer receiveBuffer;
    private final Queue<Buffer> messages;
    private Future<?> pumper;
    private final AtomicBoolean open = new AtomicBoolean(true);

    public AgentClient(FactoryManager manager, String authSocket) throws IOException {
        this(manager, authSocket, null);
    }

    public AgentClient(FactoryManager manager, String authSocket, CloseableExecutorService executor) throws IOException {
        super((executor == null) ? ThreadUtils.newSingleThreadExecutor("AgentClient[" + authSocket + "]") : executor);
        this.manager = Objects.requireNonNull(manager, "No factory manager instance provided");
        this.authSocket = authSocket;

        try {
            AprLibrary aprLibInstance = AprLibrary.getInstance();
            pool = Pool.create(aprLibInstance.getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }
            receiveBuffer = new ByteArrayBuffer();
            messages = new ArrayBlockingQueue<>(10);

            CloseableExecutorService service = getExecutorService();
            pumper = service.submit(this);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    @Override
    public FactoryManager getFactoryManager() {
        return manager;
    }

    public String getAuthSocket() {
        return authSocket;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void run() {
        try {
            byte[] buf = new byte[1024];
            while (isOpen()) {
                int result = Socket.recv(handle, buf, 0, buf.length);
                if (result < Status.APR_SUCCESS) {
                    throwException(result);
                }

                messageReceived(new ByteArrayBuffer(buf, 0, result));
            }
        } catch (Exception e) {
            boolean debugEnabled = log.isDebugEnabled();
            if (isOpen()) {
                log.warn("run({}) {} while still open: {}",
                        this, e.getClass().getSimpleName(), e.getMessage());
                if (debugEnabled) {
                    log.debug("run(" + this + ") open client exception", e);
                }
            } else {
                if (debugEnabled) {
                    log.debug("run(" + this + ") closed client loop exception", e);
                }
            }
        } finally {
            try {
                close();
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("run({}) {} while closing: {}",
                            this, e.getClass().getSimpleName(), e.getMessage());
                }
            }
        }
    }

    protected void messageReceived(Buffer buffer) throws Exception {
        Buffer message = null;
        synchronized (receiveBuffer) {
            receiveBuffer.putBuffer(buffer);
            if (receiveBuffer.available() >= Integer.BYTES) {
                int rpos = receiveBuffer.rpos();
                int len = receiveBuffer.getInt();
                // Protect against malicious or corrupted packets
                if (len < 0) {
                    throw new StreamCorruptedException("Illogical message length: " + len);
                }

                receiveBuffer.rpos(rpos);
                if (receiveBuffer.available() >= (Integer.BYTES + len)) {
                    message = new ByteArrayBuffer(receiveBuffer.getBytes());
                    receiveBuffer.compact();
                }
            }
        }

        if (message != null) {
            synchronized (messages) {
                messages.offer(message);
                messages.notifyAll();
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            Socket.close(handle);
        }

        // make any waiting thread aware of the closure
        synchronized (messages) {
            messages.notifyAll();
        }

        if ((pumper != null) && (!pumper.isDone())) {
            pumper.cancel(true);
        }

        super.close();
    }

    @Override
    protected synchronized Buffer request(Buffer buffer) throws IOException {
        int wpos = buffer.wpos();
        buffer.wpos(0);
        buffer.putInt(wpos - 4);
        buffer.wpos(wpos);
        synchronized (messages) {
            int result = Socket.send(handle, buffer.array(), buffer.rpos(), buffer.available());
            if (result < Status.APR_SUCCESS) {
                throwException(result);
            }

            return waitForMessageBuffer();
        }
    }

    // NOTE: assumes messages lock is obtained prior to calling this method
    protected Buffer waitForMessageBuffer() throws IOException {
        FactoryManager mgr = getFactoryManager();
        long idleTimeout = PropertyResolverUtils.getLongProperty(
                mgr, MESSAGE_POLL_FREQUENCY, DEFAULT_MESSAGE_POLL_FREQUENCY);
        if (idleTimeout <= 0L) {
            idleTimeout = DEFAULT_MESSAGE_POLL_FREQUENCY;
        }

        boolean traceEnabled = log.isTraceEnabled();
        for (int count = 1;; count++) {
            if (!isOpen()) {
                throw new SshException("Client is being closed");
            }

            if (!messages.isEmpty()) {
                return messages.poll();
            }

            if (traceEnabled) {
                log.trace("waitForMessageBuffer({}) wait iteration #{}", this, count);
            }

            try {
                messages.wait(idleTimeout);
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException("Interrupted while waiting for messages at iteration #" + count)
                        .initCause(e);
            }
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param  code                APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    protected void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[socket=" + getAuthSocket() + "]";
    }
}
