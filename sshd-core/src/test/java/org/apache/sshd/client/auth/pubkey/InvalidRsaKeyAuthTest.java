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
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.hostbased.RejectAllHostBasedAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class InvalidRsaKeyAuthTest extends BaseTestSupport {

    private SshServer sshd;
    private SshClient client;
    private int port;

    private KeyPair ecKeyUser;

    public InvalidRsaKeyAuthTest() {
        super();
    }

    @BeforeEach
    void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(InvalidRsaKeyAuthTest.class);
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setHostBasedAuthenticator(RejectAllHostBasedAuthenticator.INSTANCE);
        // Generate an EC key to be used as real user key. Just any non-RSA key will do.
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyUtils.EC_ALGORITHM);
        generator.initialize(256);
        ecKeyUser = generator.generateKeyPair();
        sshd.setPublickeyAuthenticator((username, key, session) -> KeyUtils.compareKeys(key, ecKeyUser.getPublic()));
        sshd.start();
        port = sshd.getPort();
        client = CoreTestSupportUtils.setupTestClient(InvalidRsaKeyAuthTest.class);
        client.setUserAuthFactoriesNames(UserAuthMethodFactory.PUBLIC_KEY);
        client.start();
    }

    @AfterEach
    void teardownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    // SSHD-1231
    @Test
    void connectWithWrongRsaKeyFirst() throws Exception {
        // Generate an RSA key the client will try first, and which the server will reject.
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyUtils.RSA_ALGORITHM);
        generator.initialize(2048);
        KeyPair rsaKey = generator.generateKeyPair();

        try (ClientSession session = createClientSession(client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKey);
                result.add(ecKeyUser);
                return result;
            });
            session.auth().verify(AUTH_TIMEOUT);
        }
        // Fails with an exception in SSHD-1231; if fixed authentication succeeds.
    }
}
