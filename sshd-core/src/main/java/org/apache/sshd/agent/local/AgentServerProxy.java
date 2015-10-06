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
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentServerProxy extends AbstractLoggingBean implements SshAgentServer {
    private final ConnectionService service;
    private final String id;
    private final AtomicBoolean open = new AtomicBoolean(true);

    public AgentServerProxy(ConnectionService service) throws IOException {
        this.service = ValidateUtils.checkNotNull(service, "No connection service provided");
        this.id = UUID.randomUUID().toString();
    }

    public SshAgent createClient() throws IOException {
        try {
            AgentForwardedChannel channel = new AgentForwardedChannel();
            this.service.registerChannel(channel);
            channel.open().verify(PropertyResolverUtils.getLongProperty(channel, CHANNEL_OPEN_TIMEOUT_PROP, DEFAULT_CHANNEL_OPEN_TIMEOUT));
            return channel.getAgent();
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("createClient(" + service.getSession() + ")[" + getId() + ")"
                        + " failed (" + t.getClass().getSimpleName() + ")"
                        + " to create client: " + t.getMessage());
            }

            if (t instanceof IOException) {
                throw (IOException) t;
            }

            throw (IOException) new IOException("Failed (" + t.getClass().getSimpleName() + ") to create client: " + t.getMessage()).initCause(t);
        }
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            if (log.isDebugEnabled()) {
                log.debug("closed(" + service.getSession() + ")[" + getId() + "]");
            }
        }
    }
}
