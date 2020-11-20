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
import java.security.KeyPair;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.hostbased.RejectAllHostBasedAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class RSAVariantsAuthPublicKeyTest extends BaseTestSupport {
    private static final List<NamedFactory<Signature>> RSA_FACTORIES = Collections.unmodifiableList(
            BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE.stream()
                    .filter(f -> f.getName().contains("rsa"))
                    .filter(f -> !f.getName().contains("cert"))
                    .collect(Collectors.toList()));
    private static final AbstractGeneratorHostKeyProvider KEYS_PROVIDER = new SimpleGeneratorHostKeyProvider() {
        {
            setAlgorithm(KeyUtils.RSA_ALGORITHM);
            setKeySize(2048);
        }
    };

    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    private final SignatureFactory factory;

    public RSAVariantsAuthPublicKeyTest(SignatureFactory factory) {
        Assume.assumeTrue("Skip unsupported factory", factory.isSupported());
        this.factory = factory;
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(RSAVariantsAuthPublicKeyTest.class);
        sshd.setSignatureFactories(RSA_FACTORIES);
        sshd.setKeyPairProvider(KEYS_PROVIDER);
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setHostBasedAuthenticator(RejectAllHostBasedAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            String keyType = KeyUtils.getKeyType(key);
            outputDebugMessage("authenticate(%s) keyType=%s session=%s", username, keyType, session);
            return KeyPairProvider.SSH_RSA.equals(keyType);
        });

        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(RSAVariantsAuthPublicKeyTest.class);
        client.setServerKeyVerifier((session, peerAddress, key) -> {
            String keyType = KeyUtils.getKeyType(key);
            outputDebugMessage("verifyServerKey - keyType=%s session=%s", keyType, session);
            return KeyPairProvider.SSH_RSA.equals(keyType);
        });
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
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

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(RSA_FACTORIES);
    }

    @Test
    public void testRSAVariantAuth() throws IOException {
        client.setSignatureFactories(Collections.singletonList(factory));
        try (ClientSession session = createClientSession(client, port)) {
            List<KeyPair> keys = KEYS_PROVIDER.loadKeys(session);
            KeyPair kp = keys.get(0);
            assertEquals("Mismatched key type", KeyPairProvider.SSH_RSA, KeyUtils.getKeyType(kp));
            session.addPublicKeyIdentity(kp);
            session.auth().verify(AUTH_TIMEOUT);

            String serverKeyType = session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
            assertEquals("Mismatched host key used", factory.getName(), serverKeyType);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + factory + "]";
    }
}
