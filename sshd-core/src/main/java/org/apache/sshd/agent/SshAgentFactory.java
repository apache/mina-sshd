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
package org.apache.sshd.agent;

import java.io.IOException;
import java.util.List;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;

/**
 * The <code>SshAgentFactory</code> is used to communicate with an SshAgent.
 */
public interface SshAgentFactory {

    /**
     * The channels are requested by the ssh server when forwarding a client request. The channel will receive agent
     * requests and need to forward them to the agent, either local or through another proxy.
     *
     * @param  manager The {@link FactoryManager} through which the request is made
     * @return         The {@link ChannelFactory}-ies used to create channels on the client side
     */
    List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager);

    /**
     * Create an SshAgent that can be used on the client side by the authentication process to send possible keys.
     *
     * @param  manager     The {@link FactoryManager} instance
     * @return             The {@link SshAgent} instance
     * @throws IOException If failed to create the client
     */
    SshAgent createClient(FactoryManager manager) throws IOException;

    /**
     * Create the server side that will be used by other SSH clients. It will usually create a channel that will forward
     * the requests to the original client.
     *
     * @param  service     The {@link ConnectionService} to use
     * @return             The {@link SshAgentServer} instance
     * @throws IOException If failed to create the server
     */
    SshAgentServer createServer(ConnectionService service) throws IOException;
}
