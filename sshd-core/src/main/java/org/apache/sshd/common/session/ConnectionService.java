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
package org.apache.sshd.common.session;

import java.io.IOException;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.forward.PortForwardingEventListenerManager;
import org.apache.sshd.common.forward.PortForwardingEventListenerManagerHolder;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Interface implementing ssh-connection service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ConnectionService
        extends Service,
        SessionHeartbeatController,
        UnknownChannelReferenceHandlerManager,
        PortForwardingEventListenerManager,
        PortForwardingEventListenerManagerHolder {

    /**
     * Register a newly created channel with a new unique identifier
     *
     * @param  channel     The {@link Channel} to register
     * @return             The assigned id of this channel
     * @throws IOException If failed to initialize and register the channel
     */
    int registerChannel(Channel channel) throws IOException;

    /**
     * Remove this channel from the list of managed channels
     *
     * @param channel The {@link Channel} instance
     */
    void unregisterChannel(Channel channel);

    /**
     * Retrieve the forwarder instance
     *
     * @return The {@link Forwarder}
     */
    Forwarder getForwarder();

    // TODO: remove from interface, it's server side only
    AgentForwardSupport getAgentForwardSupport();

    // TODO: remove from interface, it's server side only
    X11ForwardSupport getX11ForwardSupport();

    boolean isAllowMoreSessions();

    void setAllowMoreSessions(boolean allow);
}
