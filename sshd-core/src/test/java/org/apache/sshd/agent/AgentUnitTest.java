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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.sshd.agent.common.AbstractAgentClient;
import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.agent.local.AgentImpl;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simple short-circuited test for {@link AbstractAgentClient} and {@link AbstractAgentProxy}.
 */
@Tag("NoIoTestCase")
public class AgentUnitTest extends BaseTestSupport {

    private String algorithm;

    private BuiltinSignatures factory;

    public void initAgentUnitTest(String algorithm, BuiltinSignatures factory) {
        this.algorithm = algorithm;
        this.factory = factory;
    }

    public static List<Object[]> getParameters() {
        return Arrays.asList(new Object[] { KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS, BuiltinSignatures.rsaSHA512 },
                new Object[] { KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS, BuiltinSignatures.rsaSHA256 },
                new Object[] { KeyPairProvider.SSH_RSA, BuiltinSignatures.rsa });
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "{0}")
    public void rsaSignature(String algorithm, BuiltinSignatures factory) throws Exception {
        initAgentUnitTest(algorithm, factory);
        SshAgent agent = new AgentImpl();
        KeyPair pair = SecurityUtils.getKeyPairGenerator(KeyUtils.RSA_ALGORITHM).generateKeyPair();
        agent.addIdentity(pair, "test key");
        Server server = new Server(agent);
        Client client = new Client(server);
        server.setClient(client);
        byte[] data = { 'd', 'a', 't', 'a' };
        Map.Entry<String, byte[]> result = client.sign(null, pair.getPublic(), algorithm, data);
        assertEquals(algorithm, result.getKey(), "Unexpected signature algorithm");
        byte[] signature = result.getValue();
        Signature verifier = factory.get();
        verifier.initVerifier(null, pair.getPublic());
        verifier.update(null, data);
        assertTrue(verifier.verify(null, signature), "Signature should validate");
    }

    private static class Server extends AbstractAgentClient {

        private Client client;

        protected Server(SshAgent agent) {
            super(agent);
        }

        @Override
        protected void reply(Buffer buf) throws IOException {
            client.setResult(buf.getCompactData());
        }

        void setClient(Client client) {
            this.client = client;
        }

        void request(byte[] data) throws IOException {
            messageReceived(ByteArrayBuffer.getCompactClone(data));
        }
    }

    private static class Client extends AbstractAgentProxy {

        private final Server server;

        private byte[] result;

        protected Client(Server server) {
            super(null);
            this.server = server;
        }

        @Override
        protected Buffer request(Buffer buffer) throws IOException {
            server.request(buffer.getCompactData());
            Buffer received = ByteArrayBuffer.getCompactClone(result);
            return new ByteArrayBuffer(received.getBytes());
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        void setResult(byte[] data) {
            result = data;
        }
    }
}
