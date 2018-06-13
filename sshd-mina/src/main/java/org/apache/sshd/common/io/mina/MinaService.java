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

import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.mina.core.RuntimeIoException;
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
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class MinaService extends AbstractCloseable implements org.apache.sshd.common.io.IoService, IoHandler, Closeable {
    protected final FactoryManager manager;
    protected final org.apache.sshd.common.io.IoHandler handler;
    protected final IoProcessor<NioSession> ioProcessor;
    protected IoSessionConfig sessionConfig;

    public MinaService(FactoryManager manager, org.apache.sshd.common.io.IoHandler handler, IoProcessor<NioSession> ioProcessor) {
        this.manager = Objects.requireNonNull(manager, "No factory manager provided");
        this.handler = Objects.requireNonNull(handler, "No IoHandler provided");
        this.ioProcessor = Objects.requireNonNull(ioProcessor, "No IoProcessor provided");
    }

    protected abstract IoService getIoService();

    public void dispose() {
        IoService ioService = getIoService();
        ioService.dispose();
    }

    @Override
    protected void doCloseImmediately() {
        try {
            dispose();
        } finally {
            super.doCloseImmediately();
        }
    }

    @Override
    public Map<Long, org.apache.sshd.common.io.IoSession> getManagedSessions() {
        IoService ioService = getIoService();
        Map<Long, IoSession> managedMap = ioService.getManagedSessions();
        Map<Long, IoSession> mina = new TreeMap<>(managedMap);
        Map<Long, org.apache.sshd.common.io.IoSession> sessions = new TreeMap<>(Comparator.naturalOrder());
        for (Long id : mina.keySet()) {
            // Avoid possible NPE if the MinaSession hasn't been created yet
            IoSession minaSession = mina.get(id);
            org.apache.sshd.common.io.IoSession session = getSession(minaSession);
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
        session.closeNow();
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        org.apache.sshd.common.io.IoSession ioSession = new MinaSession(this, session);
        try {
            session.setAttribute(org.apache.sshd.common.io.IoSession.class, ioSession);
            handler.sessionCreated(ioSession);
        } catch (Exception e) {
            log.warn("sessionCreated({}) failed {} to handle creation event: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            ioSession.close(true);
            throw e;
        }
    }

    @Override
    public void sessionClosed(IoSession ioSession) throws Exception {
        org.apache.sshd.common.io.IoSession session = getSession(ioSession);
        handler.sessionClosed(session);
    }

    @Override
    public void exceptionCaught(IoSession ioSession, Throwable cause) throws Exception {
        org.apache.sshd.common.io.IoSession session = getSession(ioSession);
        handler.exceptionCaught(session, cause);
    }

    @Override
    public void messageReceived(IoSession ioSession, Object message) throws Exception {
        org.apache.sshd.common.io.IoSession session = getSession(ioSession);
        Readable ioBuffer = MinaSupport.asReadable((IoBuffer) message);
        handler.messageReceived(session, ioBuffer);
    }

    protected org.apache.sshd.common.io.IoSession getSession(IoSession session) {
        return (org.apache.sshd.common.io.IoSession)
            session.getAttribute(org.apache.sshd.common.io.IoSession.class);
    }

    protected void configure(SocketSessionConfig config) {
        Boolean boolVal = getBoolean(FactoryManager.SOCKET_KEEPALIVE);
        if (boolVal != null) {
            try {
                config.setKeepAlive(boolVal);
            } catch (RuntimeIoException t) {
                handleConfigurationError(config, FactoryManager.SOCKET_KEEPALIVE, boolVal, t);
            }
        }

        Integer intVal = getInteger(FactoryManager.SOCKET_SNDBUF);
        if (intVal != null) {
            try {
                config.setSendBufferSize(intVal);
            } catch (RuntimeIoException t) {
                handleConfigurationError(config, FactoryManager.SOCKET_SNDBUF, intVal, t);
            }
        }

        intVal = getInteger(FactoryManager.SOCKET_RCVBUF);
        if (intVal != null) {
            try {
                config.setReceiveBufferSize(intVal);
            } catch (RuntimeIoException t) {
                handleConfigurationError(config, FactoryManager.SOCKET_RCVBUF, intVal, t);
            }
        }

        intVal = getInteger(FactoryManager.SOCKET_LINGER);
        if (intVal != null) {
            try {
                config.setSoLinger(intVal);
            } catch (RuntimeIoException t) {
                handleConfigurationError(config, FactoryManager.SOCKET_LINGER, intVal, t);
            }
        }

        boolVal = getBoolean(FactoryManager.TCP_NODELAY);
        if (boolVal != null) {
            try {
                config.setTcpNoDelay(boolVal);
            } catch (RuntimeIoException t) {
                handleConfigurationError(config, FactoryManager.TCP_NODELAY, boolVal, t);
            }
        }

        if (sessionConfig != null) {
            config.setAll(sessionConfig);
        }
    }

    protected void handleConfigurationError(SocketSessionConfig config, String propName, Object propValue, RuntimeIoException t) {
        Throwable e = GenericUtils.resolveExceptionCause(t);
        log.warn("handleConfigurationError({}={}) failed ({}) to configure: {}",
                 propName, propValue, e.getClass().getSimpleName(), e.getMessage());
    }

    protected Integer getInteger(String property) {
        return manager.getInteger(property);
    }

    protected Boolean getBoolean(String property) {
        return manager.getBoolean(property);
    }
}
