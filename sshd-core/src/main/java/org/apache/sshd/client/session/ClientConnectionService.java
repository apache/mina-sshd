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
import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractConnectionService;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Client side <code>ssh-connection</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientConnectionService
        extends AbstractConnectionService
        implements ClientSessionHolder {
    protected final String heartbeatRequest;
    protected final Duration heartbeatInterval;
    protected final Duration heartbeatReplyMaxWait;
    /** Non-null only if using the &quot;keep-alive&quot; request mechanism */
    protected ScheduledFuture<?> clientHeartbeat;

    public ClientConnectionService(AbstractClientSession s) throws SshException {
        super(s);

        heartbeatRequest = CoreModuleProperties.HEARTBEAT_REQUEST.getRequired(this);
        heartbeatInterval = CoreModuleProperties.HEARTBEAT_INTERVAL.getRequired(this);
        heartbeatReplyMaxWait = CoreModuleProperties.HEARTBEAT_REPLY_WAIT.getRequired(this);
    }

    @Override
    public final ClientSession getClientSession() {
        return getSession();
    }

    @Override // co-variant return
    public AbstractClientSession getSession() {
        return (AbstractClientSession) super.getSession();
    }

    @Override
    public void start() {
        ClientSession session = getClientSession();
        if (!session.isAuthenticated()) {
            throw new IllegalStateException("Session is not authenticated");
        }
        super.start();
    }

    @Override
    protected synchronized ScheduledFuture<?> startHeartBeat() {
        if (!GenericUtils.isNegativeOrNull(heartbeatInterval) && GenericUtils.isNotEmpty(heartbeatRequest)) {
            stopHeartBeat();

            ClientSession session = getClientSession();
            FactoryManager manager = session.getFactoryManager();
            ScheduledExecutorService service = manager.getScheduledExecutorService();
            clientHeartbeat = service.scheduleAtFixedRate(
                    this::sendHeartBeat, heartbeatInterval.toMillis(), heartbeatInterval.toMillis(), TimeUnit.MILLISECONDS);
            if (log.isDebugEnabled()) {
                log.debug("startHeartbeat({}) - started at interval={} with request={}",
                        session, heartbeatInterval, heartbeatRequest);
            }

            return clientHeartbeat;
        } else {
            return super.startHeartBeat();
        }
    }

    @Override
    protected synchronized void stopHeartBeat() {
        try {
            super.stopHeartBeat();
        } finally {
            // No need to cancel since this is the same reference as the superclass heartbeat future
            if (clientHeartbeat != null) {
                clientHeartbeat = null;
            }
        }
    }

    @Override
    protected boolean sendHeartBeat() {
        if (clientHeartbeat == null) {
            return super.sendHeartBeat();
        }

        Session session = getSession();
        try {
            boolean withReply = !GenericUtils.isNegativeOrNull(heartbeatReplyMaxWait);
            Buffer buf = session.createBuffer(
                    SshConstants.SSH_MSG_GLOBAL_REQUEST, heartbeatRequest.length() + Byte.SIZE);
            buf.putString(heartbeatRequest);
            buf.putBoolean(withReply);

            if (withReply) {
                Buffer reply = session.request(heartbeatRequest, buf, heartbeatReplyMaxWait);
                if (reply != null) {
                    if (log.isTraceEnabled()) {
                        log.trace("sendHeartBeat({}) received reply size={} for request={}",
                                session, reply.available(), heartbeatRequest);
                    }
                }
            } else {
                IoWriteFuture future = session.writePacket(buf);
                future.addListener(this::futureDone);
            }
            heartbeatCount.incrementAndGet();
            return true;
        } catch (IOException | RuntimeException | Error e) {
            session.exceptionCaught(e);
            warn("sendHeartBeat({}) failed ({}) to send heartbeat #{} request={}: {}",
                    session, e.getClass().getSimpleName(), heartbeatCount, heartbeatRequest, e.getMessage(), e);
            return false;
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
