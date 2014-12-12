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
package org.apache.sshd.common.io.mina;

import java.util.HashMap;
import java.util.Map;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.util.CloseableUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public abstract class MinaService extends IoHandlerAdapter implements org.apache.sshd.common.io.IoService, IoHandler, Closeable {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final FactoryManager manager;
    protected final org.apache.sshd.common.io.IoHandler handler;
    protected final IoProcessor<NioSession> ioProcessor;
    protected IoSessionConfig sessionConfig;

    public MinaService(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler, IoProcessor<NioSession> ioProcessor) {
        this.manager = manager;
        this.handler = handler;
        this.ioProcessor = ioProcessor;
    }

    protected abstract IoService getIoService();

    public void dispose() {
        getIoService().dispose();
    }

    public CloseFuture close(boolean immediately) {
        getIoService().dispose();
        return CloseableUtils.closed();
    }

    public boolean isClosed() {
        return getIoService().isDisposed();
    }

    public boolean isClosing() {
        return getIoService().isDisposing();
    }

    public Map<Long, org.apache.sshd.common.io.IoSession> getManagedSessions() {
        Map<Long, IoSession> mina = new HashMap<Long, IoSession>(getIoService().getManagedSessions());
        Map<Long, org.apache.sshd.common.io.IoSession> sessions = new HashMap<Long, org.apache.sshd.common.io.IoSession>();
        for (Long id : mina.keySet()) {
            // Avoid possible NPE if the MinaSession hasn't been created yet
            org.apache.sshd.common.io.IoSession session = getSession(mina.get(id));
            if (session != null) {
                sessions.put(id, session);
            }
        }
        return sessions;
    }

    public void sessionCreated(IoSession session) throws Exception {
        org.apache.sshd.common.io.IoSession ioSession = new MinaSession(this, session);
        session.setAttribute(org.apache.sshd.common.io.IoSession.class, ioSession);
        handler.sessionCreated(ioSession);
    }

    public void sessionClosed(IoSession session) throws Exception {
        handler.sessionClosed(getSession(session));
    }

    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        handler.exceptionCaught(getSession(session), cause);
    }

    public void messageReceived(IoSession session, Object message) throws Exception {
        handler.messageReceived(getSession(session), MinaSupport.asReadable((IoBuffer) message));
    }

    protected org.apache.sshd.common.io.IoSession getSession(IoSession session) {
        return (org.apache.sshd.common.io.IoSession)
                session.getAttribute(org.apache.sshd.common.io.IoSession.class);
    }

    protected void configure(SocketSessionConfig config) {
        Integer intVal;
        Boolean boolVal;
        if ((boolVal = getBoolean(FactoryManager.SOCKET_KEEPALIVE)) != null) {
            config.setKeepAlive(boolVal);
        }
        if ((intVal = getInteger(FactoryManager.SOCKET_SNDBUF)) != null) {
            config.setSendBufferSize(intVal);
        }
        if ((intVal = getInteger(FactoryManager.SOCKET_RCVBUF)) != null) {
            config.setReceiveBufferSize(intVal);
        }
        if ((intVal = getInteger(FactoryManager.SOCKET_LINGER)) != null) {
            config.setSoLinger(intVal);
        }
        if ((boolVal = getBoolean(FactoryManager.SOCKET_LINGER)) != null) {
            config.setTcpNoDelay(boolVal);
        }
        if (sessionConfig != null) {
            config.setAll(sessionConfig);
        }
    }

    protected Integer getInteger(String property) {
        String strVal = manager.getProperties().get(property);
        return (strVal != null) ? Integer.parseInt(strVal) : null;
    }

    protected Boolean getBoolean(String property) {
        String strVal = manager.getProperties().get(property);
        return (strVal != null) ? Boolean.parseBoolean(strVal) : null;
    }

}
