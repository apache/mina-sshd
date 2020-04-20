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

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelAgentForwardingFactory implements ChannelFactory {

    public static final ChannelAgentForwardingFactory OPENSSH = new ChannelAgentForwardingFactory("auth-agent@openssh.com");
    // see https://tools.ietf.org/html/draft-ietf-secsh-agent-02
    public static final ChannelAgentForwardingFactory IETF = new ChannelAgentForwardingFactory("auth-agent");

    private final String name;
    private final Factory<CloseableExecutorService> executorServiceFactory;

    public ChannelAgentForwardingFactory(String name) {
        this(name, null);
    }

    public ChannelAgentForwardingFactory(String name, Factory<CloseableExecutorService> executorServiceFactory) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No channel factory name specified");
        this.executorServiceFactory = executorServiceFactory;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Channel createChannel(Session session) throws IOException {
        CloseableExecutorService executorService = executorServiceFactory != null ? executorServiceFactory.create() : null;
        ChannelAgentForwarding channel = new ChannelAgentForwarding(executorService);
        return channel;
    }
}
