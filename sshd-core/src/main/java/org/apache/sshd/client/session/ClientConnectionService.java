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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.helpers.AbstractConnectionService;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Client side <code>ssh-connection</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientConnectionService
        extends AbstractConnectionService
        implements ClientSessionHolder {

    private ScheduledFuture<?> heartBeat;

    public ClientConnectionService(AbstractClientSession s) throws SshException {
        super(s);
    }

    @Override
    public final ClientSession getClientSession() {
        return getSession();
    }

    @Override
    public AbstractClientSession getSession() {
        return (AbstractClientSession) super.getSession();
    }

    @Override
    public void start() {
        ClientSession session = getClientSession();
        if (!session.isAuthenticated()) {
            throw new IllegalStateException("Session is not authenticated");
        }
        startHeartBeat();
    }

    @Override
    protected void preClose() {
        stopHeartBeat();
        super.preClose();
    }

    protected synchronized void startHeartBeat() {
        stopHeartBeat();
        ClientSession session = getClientSession();
        long interval = session.getLongProperty(ClientFactoryManager.HEARTBEAT_INTERVAL, ClientFactoryManager.DEFAULT_HEARTBEAT_INTERVAL);
        if (interval > 0L) {
            FactoryManager manager = session.getFactoryManager();
            ScheduledExecutorService service = manager.getScheduledExecutorService();
            heartBeat = service.scheduleAtFixedRate(this::sendHeartBeat, interval, interval, TimeUnit.MILLISECONDS);
            if (log.isDebugEnabled()) {
                log.debug("startHeartbeat - started at interval={}", interval);
            }
        }
    }

    protected synchronized void stopHeartBeat() {
        if (heartBeat != null) {
            heartBeat.cancel(true);
            heartBeat = null;
        }
    }

    /**
     * Sends a heartbeat message
     * @return The {@link IoWriteFuture} that can be used to wait for the
     * message write completion
     */
    protected IoWriteFuture sendHeartBeat() {
        ClientSession session = getClientSession();
        String request = session.getStringProperty(ClientFactoryManager.HEARTBEAT_REQUEST, ClientFactoryManager.DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING);
        try {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, request.length() + Byte.SIZE);
            buf.putString(request);
            buf.putBoolean(false);
            IoWriteFuture future = session.writePacket(buf);
            future.addListener(this::futureDone);
            return future;
        } catch (IOException e) {
            getSession().exceptionCaught(e);
            if (log.isDebugEnabled()) {
                log.debug("Error (" + e.getClass().getSimpleName() + ") sending keepalive message=" + request + ": " + e.getMessage());
            }
            Throwable t = e;
            return new AbstractIoWriteFuture(request, null) {
                {
                    setValue(t);
                }
            };
        }
    }

    protected void futureDone(IoWriteFuture future) {
        Throwable t = future.getException();
        if (t != null) {
            getSession().exceptionCaught(t);
        }
    }

    @Override
    public AgentForwardSupport getAgentForwardSupport() {
        throw new IllegalStateException("Server side operation");
    }

    @Override
    public X11ForwardSupport getX11ForwardSupport() {
        throw new IllegalStateException("Server side operation");
    }
}
