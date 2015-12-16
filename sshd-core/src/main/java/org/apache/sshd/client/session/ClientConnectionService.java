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
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Client side <code>ssh-connection</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientConnectionService extends AbstractConnectionService<AbstractClientSession> implements ClientSessionHolder {
    public ClientConnectionService(AbstractClientSession s) throws SshException {
        super(s);
    }

    @Override
    public final ClientSession getClientSession() {
        return getSession();
    }

    @Override
    public void start() {
        ClientSession session = getClientSession();
        if (!session.isAuthenticated()) {
            throw new IllegalStateException("Session is not authenticated");
        }
        startHeartBeat();
    }

    protected void startHeartBeat() {
        ClientSession session = getClientSession();
        long interval = PropertyResolverUtils.getLongProperty(session, ClientFactoryManager.HEARTBEAT_INTERVAL, ClientFactoryManager.DEFAULT_HEARTBEAT_INTERVAL);
        if (interval > 0L) {
            FactoryManager manager = session.getFactoryManager();
            ScheduledExecutorService service = manager.getScheduledExecutorService();
            service.scheduleAtFixedRate(new Runnable() {
                @Override
                public void run() {
                    sendHeartBeat();
                }
            }, interval, interval, TimeUnit.MILLISECONDS);
            if (log.isDebugEnabled()) {
                log.debug("startHeartbeat - started at interval={}", Long.valueOf(interval));
            }
        }
    }

    protected void sendHeartBeat() {
        ClientSession session = getClientSession();
        String request = PropertyResolverUtils.getStringProperty(session, ClientFactoryManager.HEARTBEAT_REQUEST, ClientFactoryManager.DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING);
        try {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, request.length() + Byte.SIZE);
            buf.putString(request);
            buf.putBoolean(false);
            session.writePacket(buf);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error (" + e.getClass().getSimpleName() + ") sending keepalive message=" + request + ": " + e.getMessage());
            }
        }
    }

    // TODO: remove from interface
    @Override
    public String initAgentForward() throws IOException {
        throw new IllegalStateException("Server side operation");
    }

    // TODO: remove from interface
    @Override
    public String createX11Display(boolean singleConnection, String authenticationProtocol, String authenticationCookie, int screen) throws IOException {
        throw new IllegalStateException("Server side operation");
    }
}
