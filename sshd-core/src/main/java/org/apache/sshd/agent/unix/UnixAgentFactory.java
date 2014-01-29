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

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.server.session.ServerSession;

public class UnixAgentFactory implements SshAgentFactory {

    public NamedFactory<Channel> getChannelForwardingFactory() {
        return new ChannelAgentForwarding.Factory();
    }

    public SshAgent createClient(FactoryManager manager) throws IOException {
        String authSocket = manager.getProperties().get(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
        SshAgent agent = new AgentClient(authSocket);
        return agent;
    }

    public SshAgentServer createServer(ConnectionService service) throws IOException {
        Session session = service.getSession();
        if (!(session instanceof ServerSession)) {
            throw new IllegalStateException("The session used to create an agent server proxy must be a server session");
        }
        return new AgentServerProxy(service);
    }
}
