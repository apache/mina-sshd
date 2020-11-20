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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.session.SessionContext;

public class AgentDelegate implements SshAgent {

    private final SshAgent agent;

    public AgentDelegate(SshAgent agent) {
        this.agent = agent;
    }

    @Override
    public boolean isOpen() {
        return agent.isOpen();
    }

    @Override
    public void close() throws IOException {
        // ignored
    }

    @Override
    public Iterable<? extends Map.Entry<PublicKey, String>> getIdentities() throws IOException {
        return agent.getIdentities();
    }

    @Override
    public Map.Entry<String, byte[]> sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException {
        return agent.sign(session, key, algo, data);
    }

    @Override
    public void addIdentity(KeyPair key, String comment) throws IOException {
        agent.addIdentity(key, comment);
    }

    @Override
    public void removeIdentity(PublicKey key) throws IOException {
        agent.removeIdentity(key);
    }

    @Override
    public void removeAllIdentities() throws IOException {
        agent.removeAllIdentities();
    }
}
