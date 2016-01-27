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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentServerProxy extends AbstractLoggingBean implements SshAgentServer, ExecutorServiceCarrier {
    /**
     * Property that can be set on the {@link Session} in order to control
     * the authentication timeout (millis). If not specified then
     * {@link #DEFAULT_AUTH_SOCKET_TIMEOUT} is used
     */
    public static final String AUTH_SOCKET_TIMEOUT = "ssh-agent-server-proxy-auth-socket-timeout";
    public static final int DEFAULT_AUTH_SOCKET_TIMEOUT = 10000000;

    //used to wake the Local.listen() JNI call
    private static final byte[] END_OF_STREAM_MESSAGE = new byte[]{"END_OF_STREAM".getBytes(StandardCharsets.UTF_8)[0]};

    private final ConnectionService service;
    private final String authSocket;
    private final long pool;
    private final long handle;
    private Future<?> piper;
    private final ExecutorService pipeService;
    private final boolean pipeCloseOnExit;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final AtomicBoolean innerFinished = new AtomicBoolean(false);

    public AgentServerProxy(ConnectionService service) throws IOException {
        this(service, null, false);
    }

    public AgentServerProxy(ConnectionService service, ExecutorService executor, boolean shutdownOnExit) throws IOException {
        this.service = service;
        try {
            String authSocket = AprLibrary.createLocalSocketAddress();

            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            this.authSocket = authSocket;

            int result = Local.bind(handle, 0);

            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }
            AprLibrary.secureLocalSocket(authSocket, handle);
            result = Local.listen(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }

            pipeService = (executor == null) ? ThreadUtils.newSingleThreadExecutor("sshd-AgentServerProxy-PIPE-" + authSocket) : executor;
            pipeCloseOnExit = (executor == pipeService) ? shutdownOnExit : true;
            piper = pipeService.submit(new Runnable() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    try {
                        while (isOpen()) {
                            try {
                                long clientSock = Local.accept(handle);
                                if (!isOpen()) {
                                    break;
                                }

                                Session session = AgentServerProxy.this.service.getSession();
                                Socket.timeoutSet(clientSock, PropertyResolverUtils.getIntProperty(session, AUTH_SOCKET_TIMEOUT, DEFAULT_AUTH_SOCKET_TIMEOUT));
                                AgentForwardedChannel channel = new AgentForwardedChannel(clientSock);
                                AgentServerProxy.this.service.registerChannel(channel);
                                channel.open().verify(PropertyResolverUtils.getLongProperty(session, CHANNEL_OPEN_TIMEOUT_PROP, DEFAULT_CHANNEL_OPEN_TIMEOUT));
                            } catch (Exception e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("run(open={}) {} while authentication forwarding: {}",
                                              isOpen(), e.getClass().getSimpleName(), e.getMessage());
                                }
                                if (log.isTraceEnabled()) {
                                    log.trace("run(open=" + isOpen() + ") authentication forwarding failure details", e);
                                }
                            }
                        }
                    } finally {
                        innerFinished.set(true);
                    }
                }
            });
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
    public ExecutorService getExecutorService() {
        return pipeService;
    }

    @Override
    public boolean isShutdownOnExit() {
        return pipeCloseOnExit;
    }

    @Override
    public String getId() {
        return authSocket;
    }

    @Override
    public synchronized void close() throws IOException {
        if (!open.getAndSet(false)) {
            return; // already closed (or closing)
        }

        final boolean isDebug = log.isDebugEnabled();

        if (handle != 0) {
            if (!innerFinished.get()) {
                try {

                    final long tmpPool = Pool.create(AprLibrary.getInstance().getRootPool());
                    final long tmpSocket = Local.create(authSocket, tmpPool);
                    long connectResult = Local.connect(tmpSocket, 0L);

                    if (connectResult != Status.APR_SUCCESS) {
                        if (isDebug) {
                            log.debug("Unable to connect to socket PIPE {}. APR errcode {}", authSocket, Long.valueOf(connectResult));
                        }
                    }

                    //write a single byte -- just wake up the accept()
                    int sendResult = Socket.send(tmpSocket, END_OF_STREAM_MESSAGE, 0, 1);
                    if (sendResult != 1) {
                        if (isDebug) {
                            log.debug("Unable to send signal the EOS for {}. APR retcode {} != 1", authSocket, Integer.valueOf(sendResult));
                        }
                    }
                } catch (Exception e) {
                    //log eventual exceptions in debug mode
                    if (isDebug) {
                        log.debug("Exception connecting to the PIPE socket: " + authSocket, e);
                    }
                }
            }

            final int closeCode = Socket.close(handle);
            if (closeCode != Status.APR_SUCCESS) {
                log.warn("Exceptions closing the PIPE: {}. APR error code: {} ", authSocket, Integer.valueOf(closeCode));
            }
        }

        try {
            if (authSocket != null) {
                final File socketFile = new File(authSocket);
                if (socketFile.exists()) {
                    deleteFile(socketFile, "Deleted PIPE socket {}");

                    if (OsUtils.isUNIX()) {
                        deleteFile(socketFile.getParentFile(), "Deleted parent PIPE socket {}");
                    }
                }
            }
        } catch (Exception e) {
            //log eventual exceptions in debug mode
            if (isDebug) {
                log.debug("Exception deleting the PIPE socket: " + authSocket, e);
            }
        }

        try {
            if ((piper != null) && (!piper.isDone())) {
                piper.cancel(true);
            }
        } finally {
            piper = null;
        }

        ExecutorService executor = getExecutorService();
        if ((executor != null) && isShutdownOnExit() && (!executor.isShutdown())) {
            Collection<?> runners = executor.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("Shut down runners count=" + GenericUtils.size(runners));
            }
        }
    }

    private void deleteFile(File file, String msg) {
        if (file.delete()) {
            if (log.isDebugEnabled()) {
                log.debug(msg, file);
            }
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    static void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }

}
