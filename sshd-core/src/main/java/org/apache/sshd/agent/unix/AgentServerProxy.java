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

import java.io.IOException;

import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshException;
import org.apache.sshd.server.session.ServerSession;
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

    private final ServerSession session;
    private String authSocket;
    private long pool;
    private long handle;
    private Thread thread;
    private boolean closed;

    public AgentServerProxy(ServerSession session) throws IOException {
        this.session = session;
        try {
            String authSocket = AprLibrary.createLocalSocketAddress();
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
            thread = new Thread() {
                public void run() {
                    while (!closed) {
                        try {
                            long clientSock = Local.accept(handle);
                            if (closed) {
                                break;
                            }
                            Socket.timeoutSet(clientSock, 10000000);
                            AgentForwardedChannel channel = new AgentForwardedChannel(clientSock);
                            AgentServerProxy.this.session.registerChannel(channel);
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
                }
            };
            thread.start();
            this.authSocket = authSocket;
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
        closed = true;
        if (handle != 0) {
            Socket.close(handle);
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    static void throwException(int code) throws IOException {
        throw new IOException(
                org.apache.tomcat.jni.Error.strerror(-code) +
                " (code: " + code + ")");
    }

}
