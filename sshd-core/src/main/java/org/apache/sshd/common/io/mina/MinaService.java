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
package org.apache.sshd.common.io.mina;

import java.util.HashMap;
import java.util.Map;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 */
public abstract class MinaService extends AbstractCloseable implements org.apache.sshd.common.io.IoService, IoHandler, Closeable {
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

    @Override
    protected void doCloseImmediately() {
        getIoService().dispose();
        super.doCloseImmediately();
    }

    @Override
    public Map<Long, org.apache.sshd.common.io.IoSession> getManagedSessions() {
        Map<Long, IoSession> mina = new HashMap<>(getIoService().getManagedSessions());
        Map<Long, org.apache.sshd.common.io.IoSession> sessions = new HashMap<>();
        for (Long id : mina.keySet()) {
            // Avoid possible NPE if the MinaSession hasn't been created yet
            org.apache.sshd.common.io.IoSession session = getSession(mina.get(id));
            if (session != null) {
                sessions.put(id, session);
            }
        }
        return sessions;
    }

    @Override
    public void sessionOpened(IoSession session) throws Exception {
        // Empty handler
    }

    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        // Empty handler
    }

    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        // Empty handler
    }

    @Override
    public void inputClosed(IoSession session) throws Exception {
        session.close(true);
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        org.apache.sshd.common.io.IoSession ioSession = new MinaSession(this, session);
        session.setAttribute(org.apache.sshd.common.io.IoSession.class, ioSession);
        handler.sessionCreated(ioSession);
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        handler.sessionClosed(getSession(session));
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        handler.exceptionCaught(getSession(session), cause);
    }

    @Override
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
        boolVal = getBoolean(FactoryManager.SOCKET_KEEPALIVE);
        if (boolVal != null) {
            config.setKeepAlive(boolVal);
        }
        intVal = getInteger(FactoryManager.SOCKET_SNDBUF);
        if (intVal != null) {
            config.setSendBufferSize(intVal);
        }
        intVal = getInteger(FactoryManager.SOCKET_RCVBUF);
        if (intVal != null) {
            config.setReceiveBufferSize(intVal);
        }
        intVal = getInteger(FactoryManager.SOCKET_LINGER);
        if (intVal != null) {
            config.setSoLinger(intVal);
        }
        boolVal = getBoolean(FactoryManager.TCP_NODELAY);
        if (boolVal != null) {
            config.setTcpNoDelay(boolVal);
        }
        if (sessionConfig != null) {
            config.setAll(sessionConfig);
        }
    }

    protected Integer getInteger(String property) {
        return PropertyResolverUtils.getInteger(manager, property);
    }

    protected Boolean getBoolean(String property) {
        return PropertyResolverUtils.getBoolean(manager, property);
    }

}
