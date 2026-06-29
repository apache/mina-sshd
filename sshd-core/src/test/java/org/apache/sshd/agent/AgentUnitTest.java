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
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.agent.common.AbstractAgentClient;
import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.agent.local.AgentImpl;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Simple short-circuited test for {@link AbstractAgentClient} and {@link AbstractAgentProxy}.
 */
@Tag("NoIoTestCase")
class AgentUnitTest extends BaseTestSupport {

    static List<Object[]> getParameters() {
        return Arrays.asList(new Object[] { KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS, BuiltinSignatures.rsaSHA512 },
                new Object[] { KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS, BuiltinSignatures.rsaSHA256 },
                new Object[] { KeyPairProvider.SSH_RSA, BuiltinSignatures.rsa });
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "{0}")
    void rsaSignature(String algorithm, BuiltinSignatures factory) throws Exception {
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

    @Test
    void securityKeySignatureBlob() throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        ECPublicKey ecPublicKey = ValidateUtils.checkInstanceOf(
                pair.getPublic(), ECPublicKey.class, "Expected an ECPublicKey");
        SkEcdsaPublicKey key = new SkEcdsaPublicKey("ssh", false, false, ecPublicKey);

        byte[] rawSignature = { 1, 2, 3, 4, 5 };
        byte flags = 1;
        long counter = 42;
        byte[] signature = createSkSignature(rawSignature, flags, counter);

        SshAgent agent = new StaticSignatureAgent(key, signature);
        Server server = new Server(agent);
        Client client = new Client(server);
        server.setClient(client);

        Map.Entry<String, byte[]> result = client.sign(null, key, key.getKeyType(), new byte[] { 'd', 'a', 't', 'a' });
        assertEquals(key.getKeyType(), result.getKey(), "Unexpected signature algorithm");
        assertSkSignature(rawSignature, flags, counter, result.getValue());
    }

    private static byte[] createSkSignature(byte[] rawSignature, byte flags, long counter) {
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putBytes(rawSignature);
        buffer.putByte(flags);
        buffer.putUInt(counter);
        return buffer.getCompactData();
    }

    private static void assertSkSignature(byte[] rawSignature, byte flags, long counter, byte[] signature) {
        ByteArrayBuffer buffer = new ByteArrayBuffer(signature);
        assertArrayEquals(rawSignature, buffer.getBytes());
        assertEquals(flags, buffer.getByte());
        assertEquals(counter, buffer.getUInt());
        assertEquals(0, buffer.available());
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

    private static class StaticSignatureAgent implements SshAgent {
        private final PublicKey key;
        private final byte[] signature;

        StaticSignatureAgent(PublicKey key, byte[] signature) {
            this.key = key;
            this.signature = signature.clone();
        }

        @Override
        public Iterable<? extends Map.Entry<PublicKey, String>> getIdentities() {
            return Collections.singletonList(new SimpleImmutableEntry<>(key, "security key"));
        }

        @Override
        public Map.Entry<String, byte[]> sign(SessionContext session, PublicKey key, String algo, byte[] data) {
            return new SimpleImmutableEntry<>(KeyUtils.getKeyType(key), signature.clone());
        }

        @Override
        public void addIdentity(KeyPair key, String comment, SshAgentKeyConstraint... constraints) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeIdentity(PublicKey key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeAllIdentities() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
            // Nothing to close.
        }
    }
}
