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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Client side <code>ssh-connection</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientConnectionService extends AbstractConnectionService {

    public static final String DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING = "keepalive@sshd.apache.org";
    public static final long DEFAULT_HEARTBEAT_INTERVAL = 0L;

    public static class Factory implements ServiceFactory {

        public String getName() {
            return "ssh-connection";
        }

        public Service create(Session session) throws IOException {
            return new ClientConnectionService(session);
        }
    }

    public ClientConnectionService(Session s) throws SshException {
        super(s);
        if (!(s instanceof ClientSessionImpl)) {
            throw new IllegalStateException("Client side service used on server side");
        }
    }

    @Override
    public void start() {
        if (!((ClientSessionImpl) session).isAuthenticated()) {
            throw new IllegalStateException("Session is not authenticated");
        }
        startHeartBeat();
    }

    protected void startHeartBeat() {
        long interval = FactoryManagerUtils.getLongProperty(session, ClientFactoryManager.HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_INTERVAL);
        if (interval > 0L) {
            FactoryManager manager = session.getFactoryManager();
            ScheduledExecutorService service = manager.getScheduledExecutorService();
            service.scheduleAtFixedRate(new Runnable() {
                public void run() {
                    sendHeartBeat();
                }
            }, interval, interval, TimeUnit.MILLISECONDS);
            log.debug("startHeartbeat - started at interval={}", interval);
        }
    }

    protected void sendHeartBeat() {
        String request = FactoryManagerUtils.getStringProperty(session, ClientFactoryManager.HEARTBEAT_REQUEST, DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING);
        try {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buf.putString(request);
            buf.putBoolean(false);
            session.writePacket(buf);
        } catch (IOException e) {
            log.info("Error sending keepalive message=" + request, e);
        }
    }

    // TODO: remove from interface
    public String initAgentForward() throws IOException {
        throw new IllegalStateException("Server side operation");
    }

    // TODO: remove from interface
    public String createX11Display(boolean singleConnection, String authenticationProtocol, String authenticationCookie, int screen) throws IOException {
        throw new IllegalStateException("Server side operation");
    }
}
