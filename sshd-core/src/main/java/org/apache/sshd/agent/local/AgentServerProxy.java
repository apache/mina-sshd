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
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.util.UUID;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentServerProxy implements SshAgentServer {

    private static final Logger LOG = LoggerFactory.getLogger(AgentServerProxy.class);

    private final ServerSession session;
    private String id;

    public AgentServerProxy(ServerSession session) throws IOException {
        this.session = session;
        this.id = UUID.randomUUID().toString();
    }

    public SshAgent createClient() throws IOException {
        try {
            AgentForwardedChannel channel = new AgentForwardedChannel();
            this.session.registerChannel(channel);
            OpenFuture future = channel.open().await();
            Throwable t = future.getException();
            if (t instanceof Exception) {
                throw (Exception) t;
            } else if (t != null) {
                throw new Exception(t);
            }
            return channel.getAgent();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw (IOException) new IOException().initCause(e);
        }
    }

    public String getId() {
        return id;
    }

    public void close() {
    }

}
