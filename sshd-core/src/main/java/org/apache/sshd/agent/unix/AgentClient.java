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
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * A client for a remote SSH agent
 */
public class AgentClient extends AbstractAgentProxy implements Runnable {

    private final String authSocket;
    private final long pool;
    private final long handle;
    private final Buffer receiveBuffer;
    private final Queue<Buffer> messages;
    private Future<?> pumper;
    private final AtomicBoolean open = new AtomicBoolean(true);

    public AgentClient(String authSocket) throws IOException {
        this(authSocket, null, false);
    }

    public AgentClient(String authSocket, ExecutorService executor, boolean shutdownOnExit) throws IOException {
        this.authSocket = authSocket;

        setExecutorService((executor == null) ? ThreadUtils.newSingleThreadExecutor("AgentClient[" + authSocket + "]") : executor);
        setShutdownOnExit((executor == null) ? true : shutdownOnExit);

        try {
            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }
            receiveBuffer = new ByteArrayBuffer();
            messages = new ArrayBlockingQueue<Buffer>(10);

            ExecutorService service = getExecutorService();
            pumper = service.submit(this);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
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
            if (isOpen()) {
                log.warn(e.getClass().getSimpleName() + " while still open: " + e.getMessage());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Closed client loop exception", e);
                }
            }
        } finally {
            try {
                close();
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(e.getClass().getSimpleName() + " while closing: " + e.getMessage());
                }
            }
        }
    }

    protected void messageReceived(Buffer buffer) throws Exception {
        Buffer message = null;
        synchronized (receiveBuffer) {
            receiveBuffer.putBuffer(buffer);
            if (receiveBuffer.available() >= 4) {
                int rpos = receiveBuffer.rpos();
                int len = receiveBuffer.getInt();
                receiveBuffer.rpos(rpos);
                if (receiveBuffer.available() >= 4 + len) {
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

        if ((pumper != null) && isShutdownOnExit() && (!pumper.isDone())) {
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
            try {
                int result = Socket.send(handle, buffer.array(), buffer.rpos(), buffer.available());
                if (result < Status.APR_SUCCESS) {
                    throwException(result);
                }
                if (messages.isEmpty()) {
                    messages.wait();
                }
                return messages.poll();
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException(authSocket + ": Interrupted while polling for messages").initCause(e);
            }
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    private void throwException(int code) throws IOException {
        throw new IOException(
                org.apache.tomcat.jni.Error.strerror(-code)
                        + " (code: " + code + ")");
    }

}
