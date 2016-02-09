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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultAgentForwardSupport extends AbstractCloseable implements AgentForwardSupport {

    private final ConnectionService serviceInstance;
    private final AtomicReference<SshAgentServer> agentServerHolder = new AtomicReference<>();

    public DefaultAgentForwardSupport(ConnectionService service) {
        serviceInstance = ValidateUtils.checkNotNull(service, "No connection service");
    }

    @Override
    public String initialize() throws IOException {
        Session session = serviceInstance.getSession();
        try {
            SshAgentServer agentServer;
            synchronized (agentServerHolder) {
                agentServer = agentServerHolder.get();
                if (agentServer != null) {
                    return agentServer.getId();
                }

                agentServer = ValidateUtils.checkNotNull(createSshAgentServer(serviceInstance, session), "No agent server created");
                agentServerHolder.set(agentServer);
            }

            String agentId = agentServer.getId();
            if (log.isDebugEnabled()) {
                log.debug("initialize({}) id={}, server={}", session, agentId, agentServer);
            }

            return agentId;
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("initialize({}) failed ({}) to create server: {}",
                          session, t.getClass().getSimpleName(), t.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("initialize(" + session + ") server creation failure details", t);
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new SshException(t);
            }
        }
    }

    protected SshAgentServer createSshAgentServer(ConnectionService service, Session session) throws Throwable {
        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No session factory manager");
        SshAgentFactory factory = ValidateUtils.checkNotNull(manager.getAgentFactory(), "No agent factory");
        return factory.createServer(service);
    }

    @Override
    public void close() throws IOException {
        SshAgentServer agentServer = agentServerHolder.getAndSet(null);
        if (agentServer != null) {
            if (log.isDebugEnabled()) {
                log.debug("close({}) closing server={}", serviceInstance.getSession(), agentServer);
            }
            agentServer.close();
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
        return getClass().getSimpleName() + "[" + serviceInstance.getSession() + "]";
    }
}
