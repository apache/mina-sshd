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
package org.apache.sshd.agent.unix;

import java.io.IOException;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UnixAgentFactory implements SshAgentFactory, ExecutorServiceConfigurer {
    private ExecutorService executor;
    private boolean shutdownExecutor;
    private final NamedFactory<Channel> factory = new ChannelAgentForwardingFactory() {
        @Override
        public ExecutorService getExecutorService() {
            return UnixAgentFactory.this.getExecutorService();
        }

        @Override
        public boolean isShutdownOnExit() {
            return UnixAgentFactory.this.isShutdownOnExit();
        }

    };

    public UnixAgentFactory() {
        super();
    }

    public UnixAgentFactory(ExecutorService service, boolean shutdown) {
        executor = service;
        shutdownExecutor = shutdown;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public void setExecutorService(ExecutorService service) {
        executor = service;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    @Override
    public void setShutdownOnExit(boolean shutdown) {
        shutdownExecutor = shutdown;
    }

    @Override
    public NamedFactory<Channel> getChannelForwardingFactory() {
        return factory;
    }

    @Override
    public SshAgent createClient(FactoryManager manager) throws IOException {
        String authSocket = PropertyResolverUtils.getString(manager, SshAgent.SSH_AUTHSOCKET_ENV_NAME);
        if (GenericUtils.isEmpty(authSocket)) {
            throw new SshException("No " + SshAgent.SSH_AUTHSOCKET_ENV_NAME + " value");
        }

        return new AgentClient(authSocket, getExecutorService(), isShutdownOnExit());
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) throws IOException {
        Session session = ValidateUtils.checkNotNull(service.getSession(), "No session");
        ValidateUtils.checkTrue(session instanceof ServerSession,
                "The session used to create an agent server proxy must be a server session");
        return new AgentServerProxy(service, getExecutorService(), isShutdownOnExit());
    }
}
