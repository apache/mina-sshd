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

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.Future;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.common.AbstractAgentClient;
import org.apache.sshd.agent.local.AgentImpl;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * A server for an SSH Agent
 */
public class AgentServer extends AbstractLoggingBean implements Closeable, ExecutorServiceCarrier {
    private final SshAgent agent;
    private final CloseableExecutorService service;
    private Future<?> agentThread;
    private String authSocket;
    private long pool;
    private long handle;

    public AgentServer() {
        this(null);
    }

    public AgentServer(CloseableExecutorService executor) {
        this(new AgentImpl(), executor);
    }

    public AgentServer(SshAgent agent, CloseableExecutorService executor) {
        this.agent = agent;
        this.service = (executor == null)
                ? ThreadUtils.newSingleThreadExecutor("AgentServer[" + agent + "]")
                : executor;
    }

    public SshAgent getAgent() {
        return agent;
    }

    @Override
    public CloseableExecutorService getExecutorService() {
        return service;
    }

    public String start() throws Exception {
        authSocket = AprLibrary.createLocalSocketAddress();
        pool = Pool.create(AprLibrary.getInstance().getRootPool());
        handle = Local.create(authSocket, pool);
        int result = Local.bind(handle, 0);
        if (result != Status.APR_SUCCESS) {
            throwException(result);
        }
        AprLibrary.secureLocalSocket(authSocket, handle);
        result = Local.listen(handle, 0);
        if (result != Status.APR_SUCCESS) {
            throwException(result);
        }

        CloseableExecutorService executor = getExecutorService();
        agentThread = executor.submit(() -> {
            try {
                while (true) {
                    long clientSock = Local.accept(handle);
                    Socket.timeoutSet(clientSock, 10000000L); // TODO make this configurable
                    new SshAgentSession(clientSock, agent).run();
                }
            } catch (Exception e) {
                log.error("Failed to run session", e);
            }
        });
        return authSocket;
    }

    @Override
    public void close() throws IOException {
        IOException err = null;
        try {
            agent.close();
        } catch (IOException e) {
            err = e;
        }

        Socket.close(handle);

        try {
            if ((agentThread != null) && (!agentThread.isDone())) {
                agentThread.cancel(true);
            }
        } finally {
            agentThread = null;
        }

        CloseableExecutorService executor = getExecutorService();
        if ((executor != null) && (!executor.isShutdown())) {
            Collection<?> runners = executor.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("Shut down runners count=" + GenericUtils.size(runners));
            }
        }

        if (err != null) {
            throw err;
        }
    }

    protected static class SshAgentSession extends AbstractAgentClient implements Runnable {
        private final long socket;

        public SshAgentSession(long socket, SshAgent agent) {
            super(agent);
            this.socket = socket;
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public void run() {
            try {
                byte[] buf = new byte[1024];
                while (true) {
                    int result = Socket.recv(socket, buf, 0, buf.length);
                    if (result == -Status.APR_EOF) {
                        break;
                    } else if (result < Status.APR_SUCCESS) {
                        throwException(result);
                    }
                    messageReceived(new ByteArrayBuffer(buf, 0, result));
                }
            } catch (Exception e) {
                log.error("Failed to process", e);
            } finally {
                Socket.close(socket);
            }
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected void reply(Buffer buf) throws IOException {
            int result = Socket.send(socket, buf.array(), buf.rpos(), buf.available());
            if (result < Status.APR_SUCCESS) {
                throwException(result);
            }
        }

    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param  code                APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    private static void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }
}
