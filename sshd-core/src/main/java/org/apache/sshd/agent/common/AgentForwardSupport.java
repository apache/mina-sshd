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
package org.apache.sshd.agent.common;

import java.io.IOException;

import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.SshException;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentForwardSupport {

    private static final Logger log = LoggerFactory.getLogger(AgentForwardSupport.class);

    private final ServerSession session;
    private String agentId;
    private SshAgentServer agentServer;

    public AgentForwardSupport(ServerSession session) {
        this.session = session;
    }

    public String initialize() throws IOException {
        try {
            if (agentId == null) {
                agentServer = session.getFactoryManager().getAgentFactory().createServer(session);
                agentId = agentServer.getId();
            }
            return agentId;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    public synchronized void close() {
        if (agentId != null) {
            agentId = null;
            agentServer.close();
            agentServer = null;
        }
    }

}
