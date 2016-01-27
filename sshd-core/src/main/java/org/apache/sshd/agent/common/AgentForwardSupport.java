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
package org.apache.sshd.agent.common;

import java.io.IOException;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentForwardSupport extends AbstractCloseable {

    private final ConnectionService service;
    private String agentId;
    private SshAgentServer agentServer;

    public AgentForwardSupport(ConnectionService service) {
        this.service = service;
    }

    public String initialize() throws IOException {
        try {
            if (agentId == null) {
                Session session = ValidateUtils.checkNotNull(service.getSession(), "No session");
                FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No session factory manager");
                SshAgentFactory factory = ValidateUtils.checkNotNull(manager.getAgentFactory(), "No agent factory");
                agentServer = ValidateUtils.checkNotNull(factory.createServer(service), "No agent server created");
                agentId = agentServer.getId();
            }
            return agentId;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (agentId != null) {
            agentId = null;
            agentServer.close();
            agentServer = null;
        }
    }

    @Override
    protected void doCloseImmediately() {
        try {
            close();
        } catch (IOException e) {
            throw new RuntimeException("Failed (" + e.getClass().getSimpleName() + ") to close agent: " + e.getMessage(), e);
        }
        super.doCloseImmediately();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + service.getSession() + "]";
    }

}
