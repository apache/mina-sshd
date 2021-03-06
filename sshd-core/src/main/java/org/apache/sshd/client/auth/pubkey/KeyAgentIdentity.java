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

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;

/**
 * Uses an {@link SshAgent} to generate the identity signature
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyAgentIdentity implements PublicKeyIdentity {
    private final SshAgent agent;
    private final KeyPair keyPair;
    private KeyPair resolvedPair;
    private final String comment;

    public KeyAgentIdentity(SshAgent agent, PublicKey key, String comment) {
        this.agent = Objects.requireNonNull(agent, "No signing agent");
        this.keyPair = new KeyPair(Objects.requireNonNull(key, "No public key"), null);
        this.comment = comment;
    }

    @Override
    public KeyPair getKeyIdentity() {
        if (resolvedPair == null) {
            resolvedPair = agent.resolveLocalIdentity(keyPair.getPublic());
        }

        return (resolvedPair == null) ? keyPair : resolvedPair;
    }

    public String getComment() {
        return comment;
    }

    @Override
    public Map.Entry<String, byte[]> sign(SessionContext session, String algo, byte[] data) throws Exception {
        KeyPair kp = getKeyIdentity();
        return agent.sign(session, kp.getPublic(), algo, data);
    }

    @Override
    public String toString() {
        KeyPair kp = getKeyIdentity();
        PublicKey pubKey = kp.getPublic();
        return getClass().getSimpleName() + "[" + KeyUtils.getKeyType(pubKey) + "]"
               + " fingerprint=" + KeyUtils.getFingerPrint(pubKey)
               + ", comment=" + getComment();
    }
}
