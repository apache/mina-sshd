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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UnixAgentFactory implements SshAgentFactory {
    public static final List<ChannelFactory> DEFAULT_FORWARDING_CHANNELS = Collections.unmodifiableList(
            Arrays.asList(
                    ChannelAgentForwardingFactory.OPENSSH,
                    ChannelAgentForwardingFactory.IETF));

    private Factory<CloseableExecutorService> executorServiceFactory;

    public UnixAgentFactory() {
        super();
    }

    public UnixAgentFactory(Factory<CloseableExecutorService> factory) {
        executorServiceFactory = factory;
    }

    protected CloseableExecutorService newExecutor() {
        return executorServiceFactory != null ? executorServiceFactory.create() : null;
    }

    @Override
    public List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager) {
        if (executorServiceFactory != null) {
            return DEFAULT_FORWARDING_CHANNELS.stream()
                    .map(cf -> new ChannelAgentForwardingFactory(cf.getName(), executorServiceFactory))
                    .collect(Collectors.toList());
        } else {
            return DEFAULT_FORWARDING_CHANNELS;
        }
    }

    @Override
    public SshAgent createClient(FactoryManager manager) throws IOException {
        String authSocket = manager.getString(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
        if (GenericUtils.isEmpty(authSocket)) {
            throw new SshException("No " + SshAgent.SSH_AUTHSOCKET_ENV_NAME + " value");
        }

        return new AgentClient(manager, authSocket, newExecutor());
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) throws IOException {
        Session session = Objects.requireNonNull(service.getSession(), "No session");
        ValidateUtils.checkInstanceOf(session, ServerSession.class,
                "The session used to create an agent server proxy must be a server session: %s", session);
        return new AgentServerProxy(service, newExecutor());
    }
}
