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
import java.security.interfaces.ECPublicKey;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.auth.AbstractUserAuthServiceFactory;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for client-side sk-* authentication packet encoding.
 */
@Tag("NoIoTestCase")
public class UserAuthPublicKeySkTest extends BaseTestSupport {

    @Test
    public void securityKeySignatureBlobIsNotWrapped() throws Exception {
        byte[] rawSignature = { 1, 2, 3, 4, 5 };
        byte flags = 1;
        long counter = 42;

        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        ECPublicKey ecPublicKey = ValidateUtils.checkInstanceOf(
                pair.getPublic(), ECPublicKey.class, "Expected an ECPublicKey");
        SkEcdsaPublicKey sk = new SkEcdsaPublicKey("ssh", false, false, ecPublicKey);
        byte[] skSignature = createSkSignature(rawSignature, flags, counter);

        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getSessionId()).thenReturn(new byte[] { 9, 8, 7, 6 });

        ExposedUserAuthPublicKey auth = new ExposedUserAuthPublicKey(new StaticSignatureIdentity(sk, skSignature));
        byte[] actual = auth.appendSignature(
                session, AbstractUserAuthServiceFactory.DEFAULT_NAME, UserAuthPublicKey.NAME, "testuser", sk.getKeyType(), sk);

        assertSkSignature(sk, rawSignature, flags, counter, actual);
    }

    private static byte[] createSkSignature(byte[] rawSignature, byte flags, long counter) {
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putBytes(rawSignature);
        buffer.putByte(flags);
        buffer.putUInt(counter);
        return buffer.getCompactData();
    }

    private static void assertSkSignature(
            SkEcdsaPublicKey key, byte[] rawSignature, byte flags, long counter, byte[] signature) {
        ByteArrayBuffer buffer = new ByteArrayBuffer(signature);
        assertEquals(key.getKeyType(), buffer.getString());
        assertArrayEquals(rawSignature, buffer.getBytes());
        assertEquals(flags, buffer.getByte());
        assertEquals(counter, buffer.getUInt());
        assertEquals(0, buffer.available());
    }

    private static class ExposedUserAuthPublicKey extends UserAuthPublicKey {
        ExposedUserAuthPublicKey(PublicKeyIdentity identity) {
            super(Collections.emptyList());
            current = identity;
        }

        byte[] appendSignature(
                ClientSession session, String service, String name, String username, String algo, SkEcdsaPublicKey key)
                throws Exception {
            ByteArrayBuffer buffer = new ByteArrayBuffer();
            super.appendSignature(session, service, name, username, algo, key, null, buffer);
            return buffer.getBytes();
        }
    }

    private static class StaticSignatureIdentity implements PublicKeyIdentity {
        private final SkEcdsaPublicKey key;
        private final byte[] signature;

        StaticSignatureIdentity(SkEcdsaPublicKey key, byte[] signature) {
            this.key = key;
            this.signature = signature.clone();
        }

        @Override
        public KeyPair getKeyIdentity() {
            return new KeyPair(key, null);
        }

        @Override
        public Map.Entry<String, byte[]> sign(SessionContext session, String algo, byte[] data) {
            return new SimpleImmutableEntry<>(key.getKeyType(), signature.clone());
        }
    }
}
