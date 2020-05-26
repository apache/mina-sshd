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
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.agent.common.AgentDelegate;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;

public class LocalAgentFactory implements SshAgentFactory {
    public static final List<ChannelFactory> DEFAULT_FORWARDING_CHANNELS = Collections.unmodifiableList(
            Arrays.asList(
                    ChannelAgentForwardingFactory.OPENSSH,
                    ChannelAgentForwardingFactory.IETF));

    private final SshAgent agent;

    public LocalAgentFactory() {
        this.agent = new AgentImpl();
    }

    public LocalAgentFactory(SshAgent agent) {
        this.agent = agent;
    }

    public SshAgent getAgent() {
        return agent;
    }

    @Override
    public List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager) {
        return DEFAULT_FORWARDING_CHANNELS;
    }

    @Override
    public SshAgent createClient(FactoryManager manager) throws IOException {
        return new AgentDelegate(agent);
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) throws IOException {
        return null;
    }
}
