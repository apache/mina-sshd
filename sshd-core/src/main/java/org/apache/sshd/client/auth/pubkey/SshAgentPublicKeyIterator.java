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

package org.apache.sshd.client.auth.pubkey;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshAgentPublicKeyIterator extends AbstractKeyPairIterator<KeyAgentIdentity> {
    private final SshAgent agent;
    private final Iterator<? extends Map.Entry<PublicKey, String>> keys;

    public SshAgentPublicKeyIterator(ClientSession session, SshAgent agent) throws IOException {
        super(session);
        this.agent = Objects.requireNonNull(agent, "No agent");
        keys = GenericUtils.iteratorOf(agent.getIdentities());
    }

    @Override
    public boolean hasNext() {
        return (keys != null) && keys.hasNext();
    }

    @Override
    public KeyAgentIdentity next() {
        Map.Entry<PublicKey, String> kp = keys.next();
        return new KeyAgentIdentity(agent, kp.getKey(), kp.getValue());
    }
}
