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

import java.security.PublicKey;
import java.util.Objects;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.config.keys.KeyUtils;

/**
 * Uses an {@link SshAgent} to generate the identity signature
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyAgentIdentity implements PublicKeyIdentity {
    private final SshAgent agent;
    private final PublicKey key;
    private final String comment;

    public KeyAgentIdentity(SshAgent agent, PublicKey key, String comment) {
        this.agent = Objects.requireNonNull(agent, "No signing agent");
        this.key = Objects.requireNonNull(key, "No public key");
        this.comment = comment;
    }

    @Override
    public PublicKey getPublicKey() {
        return key;
    }

    public String getComment() {
        return comment;
    }

    @Override
    public byte[] sign(byte[] data) throws Exception {
        return agent.sign(getPublicKey(), data);
    }

    @Override
    public String toString() {
        PublicKey pubKey = getPublicKey();
        return getClass().getSimpleName() + "[" + KeyUtils.getKeyType(pubKey) + "]"
             + " fingerprint=" + KeyUtils.getFingerPrint(pubKey)
             + ", comment=" + getComment();
    }
}