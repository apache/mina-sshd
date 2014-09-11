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
package org.apache.sshd.agent.unix;

import java.io.File;
import java.io.IOException;

import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.OsUtils;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentServerProxy implements SshAgentServer {

    private static final Logger LOG = LoggerFactory.getLogger(AgentServerProxy.class);

    private final ConnectionService service;
    private final String authSocket;
    private final long pool;
    private final long handle;
    private final Thread thread;
    private volatile boolean closed;
    private volatile boolean innerFinished;

    //used to wake the Local.listen() JNI call
    private static final byte[] END_OF_STREAM_MESSAGE = new byte[] { "END_OF_STREAM".getBytes()[0] };

    public AgentServerProxy(ConnectionService service) throws IOException {
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
            thread = new Thread("sshd-AgentServerProxy-PIPE-" + authSocket) {
                @Override
                public void run() {
                    try {
                        while (!closed) {
                            try {
                                long clientSock = Local.accept(handle);
                                if (closed) {
                                    break;
                                }
                                Socket.timeoutSet(clientSock, 10000000);
                                AgentForwardedChannel channel = new AgentForwardedChannel(clientSock);
                                AgentServerProxy.this.service.registerChannel(channel);
                                OpenFuture future = channel.open().await();
                                Throwable t = future.getException();
                                if (t instanceof Exception) {
                                    throw (Exception) t;
                                } else if (t != null) {
                                    throw new Exception(t);
                                }
                            } catch (Exception e) {
                                if (!closed) {
                                    LOG.info("Exchange caught in authentication forwarding", e);
                                }
                            }
                        }
                    } finally {
                        innerFinished = true;
                    }
                }
            };
            thread.setDaemon(true);
            thread.start();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    public String getId() {
        return authSocket;
    }

    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        final boolean isDebug = LOG.isDebugEnabled();

        if (handle != 0) {
            if (!innerFinished) {
                try {

                    final long tmpPool = Pool.create(AprLibrary.getInstance().getRootPool());
                    final long tmpSocket = Local.create(authSocket, tmpPool);
                    long connectResult = Local.connect(tmpSocket, 0);

                    if (connectResult != Status.APR_SUCCESS) {
                        if (isDebug) {
                            LOG.debug("Unable to connect to socket PIPE {}. APR errcode {}", authSocket, connectResult);
                        }
                    }

                    //write a single byte -- just wake up the accept()
                    int sendResult = Socket.send(tmpSocket, END_OF_STREAM_MESSAGE, 0, 1);
                    if (sendResult != 1) {
                        if (isDebug) {
                            LOG.debug("Unable to send signal the EOS for {}. APR retcode {} != 1", authSocket,
                                    sendResult);
                        }
                    }
                } catch (Exception e) {
                    //log eventual exceptions in debug mode
                    if (isDebug) {
                        LOG.debug("Exception connecting to the PIPE socket: " + authSocket, e);
                    }
                }
            }

            final int closeCode = Socket.close(handle);
            if (closeCode != Status.APR_SUCCESS) {
                LOG.warn("Exceptions closing the PIPE: {}. APR error code: {} ", authSocket, closeCode);
            }
        }

        try {
            if (authSocket != null) {

                final File socketFile = new File(authSocket);
                if (socketFile.exists()) {
                    if (socketFile.delete()) {
                        if (isDebug) {
                            LOG.debug("Deleted PIPE socket {}", socketFile);
                        }
                    }

                    if (OsUtils.isUNIX()) {
                        final File parentFile = socketFile.getParentFile();
                        if (parentFile.delete()) {
                            if (isDebug) {
                                LOG.debug("Deleted parent PIPE socket {}", parentFile);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            //log eventual exceptions in debug mode
            if (isDebug) {
                LOG.debug("Exception deleting the PIPE socket: " + authSocket, e);
            }
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    static void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }

}
