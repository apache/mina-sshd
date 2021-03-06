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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;

import org.apache.sshd.common.session.SessionContext;

/**
 * SSH key agent server
 */
public interface SshAgent extends java.nio.channels.Channel {

    String SSH_AUTHSOCKET_ENV_NAME = "SSH_AUTH_SOCK";

    Iterable<? extends Map.Entry<PublicKey, String>> getIdentities() throws IOException;

    /**
     *
     * @param  session     The current {@link SessionContext}
     * @param  key         The {@link PublicKey} to use for signing
     * @param  algo        Recommended signature algorithm - if {@code null}/empty then one will be selected based on
     *                     the key type and/or signature factories. <B>Note:</B> even if specific algorithm specified,
     *                     the implementation may disregard and choose another
     * @param  data        Data to sign
     * @return             used algorithm + signed data - using the identity
     * @throws IOException If failed to sign
     */
    Map.Entry<String, byte[]> sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException;

    /**
     * Used for reporting client-side public key authentication via agent
     *
     * @param  key The {@link PublicKey} that is going to be used
     * @return     The {@link KeyPair} identity for it - if available - {@code null} otherwise
     */
    default KeyPair resolveLocalIdentity(PublicKey key) {
        return null;
    }

    void addIdentity(KeyPair key, String comment) throws IOException;

    void removeIdentity(PublicKey key) throws IOException;

    void removeAllIdentities() throws IOException;
}
