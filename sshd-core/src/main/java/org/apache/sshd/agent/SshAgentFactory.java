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
package org.apache.sshd.agent;

import java.io.IOException;

import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;

/**
 * The <code>SshAgentFactory</code> is used to communicate with an SshAgent.
 */
public interface SshAgentFactory {

    /**
     * Retrieve the channel factory used to create channels on the client side.
     * The channels are requested by the ssh server when forwarding a client request.
     * The channel will receive agent requests and need to forward them to the agent,
     * either local or through another proxy.
     * @return
     */
    NamedFactory<Channel> getChannelForwardingFactory();

    /**
     * Create an SshAgent that can be used on the client side by the authentication
     * process to send possible keys.
     * @param session
     * @return
     */
    SshAgent createClient(Session session) throws IOException;

    /**
     * Create the server side that will be used by other SSH clients.
     * It will usually create a channel that will forward the requests
     * to the original client.
     *
     * @param session
     * @return
     */
    SshAgentServer createServer(Session session) throws IOException;

}
