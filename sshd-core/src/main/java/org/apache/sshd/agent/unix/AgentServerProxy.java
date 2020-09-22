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
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the
 * client side.
 */
public class AgentServerProxy extends AbstractLoggingBean implements SshAgentServer {

    // used to wake the Local.listen() JNI call
    private static final byte[] END_OF_STREAM_MESSAGE = new byte[] { "END_OF_STREAM".getBytes(StandardCharsets.UTF_8)[0] };

    private final ConnectionService service;
    private final String authSocket;
    private final long pool;
    private final long handle;
    private Future<?> piper;
    private final CloseableExecutorService pipeService;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final AtomicBoolean innerFinished = new AtomicBoolean(false);

    public AgentServerProxy(ConnectionService service) throws IOException {
        this(service, null);
    }

    public AgentServerProxy(ConnectionService service, CloseableExecutorService executor) throws IOException {
        this.service = service;
        try {
            String authSocket = AprLibrary.createLocalSocketAddress();

            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            this.authSocket = authSocket;

            int result = Local.bind(handle, 0);

            if (result != Status.APR_SUCCESS) {
                throw toIOException(result);
            }
            AprLibrary.secureLocalSocket(authSocket, handle);
            result = Local.listen(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throw toIOException(result);
            }

            pipeService = (executor == null)
                    ? ThreadUtils.newSingleThreadExecutor("sshd-AgentServerProxy-PIPE-" + authSocket)
                    : ThreadUtils.noClose(executor);
            piper = pipeService.submit(() -> {
                try {
                    while (isOpen()) {
                        try {
                            long clientSock = Local.accept(handle);
                            if (!isOpen()) {
                                break;
                            }

                            Session session = AgentServerProxy.this.service.getSession();
                            Socket.timeoutSet(clientSock,
                                    CoreModuleProperties.AUTH_SOCKET_TIMEOUT.getRequired(session).toMillis() * 1000);
                            String channelType = CoreModuleProperties.PROXY_CHANNEL_TYPE.getRequired(session);
                            AgentForwardedChannel channel = new AgentForwardedChannel(clientSock, channelType);
                            AgentServerProxy.this.service.registerChannel(channel);
                            channel.open().verify(CoreModuleProperties.CHANNEL_OPEN_TIMEOUT.getRequired(session));
                        } catch (Exception e) {
                            debug("run(open={}) {} while authentication forwarding: {}",
                                    isOpen(), e.getClass().getSimpleName(), e.getMessage(), e);
                        }
                    }
                } finally {
                    innerFinished.set(true);
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

    public CloseableExecutorService getExecutorService() {
        return pipeService;
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

        boolean debugEnabled = log.isDebugEnabled();
        if (handle != 0) {
            if (!innerFinished.get()) {
                try {
                    signalEOS(AprLibrary.getInstance(), debugEnabled);
                } catch (Exception e) {
                    // log eventual exceptions in debug mode
                    if (debugEnabled) {
                        log.debug("Exception signalling EOS to the PIPE socket: " + authSocket, e);
                    }
                }
            }

            int closeCode = Socket.close(handle);
            if (closeCode != Status.APR_SUCCESS) {
                log.warn("Exceptions closing the PIPE: {}. APR error code: {} ", authSocket, closeCode);
            }
        }

        try {
            if (authSocket != null) {
                removeSocketFile(authSocket, debugEnabled);
            }
        } catch (Exception e) {
            // log eventual exceptions in debug mode
            if (debugEnabled) {
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

        CloseableExecutorService executor = getExecutorService();
        if ((executor != null) && (!executor.isShutdown())) {
            Collection<?> runners = executor.shutdownNow();
            if (debugEnabled) {
                log.debug("Shut down runners count=" + GenericUtils.size(runners));
            }
        }
    }

    protected File removeSocketFile(String socketPath, boolean debugEnabled) throws Exception {
        File socketFile = new File(socketPath);
        if (socketFile.exists()) {
            deleteFile(socketFile, "Deleted PIPE socket {}", debugEnabled);

            if (OsUtils.isUNIX()) {
                deleteFile(socketFile.getParentFile(), "Deleted parent PIPE socket {}", debugEnabled);
            }
        }

        return socketFile;
    }

    protected void signalEOS(AprLibrary libInstance, boolean debugEnabled) throws Exception {
        long tmpPool = Pool.create(libInstance.getRootPool());
        long tmpSocket = Local.create(authSocket, tmpPool);
        long connectResult = Local.connect(tmpSocket, 0L);

        if (connectResult != Status.APR_SUCCESS) {
            if (debugEnabled) {
                log.debug("Unable to connect to socket PIPE {}. APR errcode {}", authSocket, connectResult);
            }
        }

        // write a single byte -- just wake up the accept()
        int sendResult = Socket.send(tmpSocket, END_OF_STREAM_MESSAGE, 0, 1);
        if (sendResult != 1) {
            if (debugEnabled) {
                log.debug("Unable to send signal the EOS for {}. APR retcode {} != 1", authSocket, sendResult);
            }
        }
    }

    protected boolean deleteFile(File file, String msg, boolean debugEnabled) {
        boolean success = file.delete();
        if (success) {
            if (debugEnabled) {
                log.debug(msg, file);
            }
        }

        return success;
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param  code APR error code
     * @return      {@link IOException} with the exception details for the given APR error number
     */
    public static IOException toIOException(int code) {
        return new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }
}
