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
package org.apache.sshd.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.AbstractUserAuthServiceFactory;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

/**
 * Unit test for {@link UserAuthPublickey} handling sk-* authentication on the server-side.
 */
@Tag("NoIoTestCase")
class UserAuthPublicKeySkTest extends BaseTestSupport {

    @ParameterizedTest(name = "auth {0} sig {1}")
    @CsvSource({ //
            "0,0", "0,1", "0,4", "0,5", //
            "1,0", "1,1", "1,4", "1,5", //
            "4,0", "4,1", "4,4", "4,5", //
            "5,0", "5,1", "5,4", "5,5" //
    })
    void testSk(int authFlags, int flagsOnSig) throws Exception {
        // Determine expected outcome
        boolean expectSuccess = true;
        if ((flagsOnSig & 1) == 0 && (authFlags & 1) == 0) {
            // Incoming key/signature doesn't have "user presence" flag but auth requires is (no-touch-required not set)
            expectSuccess = false;
        }
        if ((authFlags & 4) != 0 && (flagsOnSig & 4) == 0) {
            // auth has verify-required but incoming key/signature doesn't.
            expectSuccess = false;
        }

        // Generate a "fake" SK EC key. "Fake" because we actually use a normal EC key as basis, so that we have the
        // private key
        // and can generate a signature.
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        ECPublicKey ecPubKey = ValidateUtils.checkInstanceOf(pair.getPublic(), ECPublicKey.class, "Expected an ECPublicKey");
        SkEcdsaPublicKey sk = new SkEcdsaPublicKey("ssh", false, false, ecPubKey);

        MockSession session = createSession();
        // Give it a session ID since it is part of the signed data.
        byte[] id = new byte[32];
        ThreadLocalRandom.current().nextBytes(id);
        session.setSessionId(id);

        // Generate an AuthorizedKeyEntry, and set an authenticator on the mock session.
        String entryLine = "";
        switch (authFlags & 5) {
            case 0:
                break;
            case 1:
                entryLine = "no-touch-required ";
                break;
            case 4:
                entryLine = "verify-required ";
                break;
            case 5:
                entryLine = "no-touch-required,verify-required ";
                break;
            default:
                fail("Invalid authFlags " + authFlags);
                break;
        }
        entryLine += PublicKeyEntry.toString(sk);
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(entryLine);
        AuthorizedKeyEntriesPublickeyAuthenticator authenticator = new AuthorizedKeyEntriesPublickeyAuthenticator("test",
                session, Collections.singleton(entry), PublicKeyEntryResolver.FAILING);
        session.setPublickeyAuthenticator(authenticator);

        // Create the UserAuthPublickey object under test; give it the signature factory we need.
        UserAuthPublicKey pubkeyAuth = new UserAuthPublicKey(
                Collections.singletonList(BuiltinSignatures.sk_ecdsa_sha2_nistp256));

        // Create a buffer with a full properly signed authentication request.
        ByteArrayBuffer buffer = createRequest(id, (byte) flagsOnSig, sk, pair.getPrivate());

        String userName = buffer.getString();
        String serviceName = buffer.getString();
        buffer.getString(); // Skip method name

        // Finally try to authenticate and check the result.
        try {
            Boolean result = pubkeyAuth.auth(session, userName, serviceName, buffer);
            assertEquals(expectSuccess, result.booleanValue());
        } catch (SignatureException e) {
            if (!"Key verification failed".equals(e.getMessage())) {
                throw e;
            }
            assertFalse(expectSuccess);
        }
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private MockSession createSession() throws Exception {
        // Create a mock ServerSession. We can't simple mock the server session since the authenticator might want to
        // set an attribute on it.
        ServerFactoryManager manager = Mockito.mock(ServerFactoryManager.class);
        Factory<? extends Random> randomFactory = new SingletonRandomFactory(JceRandomFactory.INSTANCE);
        Mockito.when(manager.getRandomFactory()).thenReturn((Factory) randomFactory);
        return new MockSession(manager, Mockito.mock(IoSession.class));
    }

    private ByteArrayBuffer createRequest(byte[] sessionId, byte flagsOnSig, SkEcdsaPublicKey sk, PrivateKey priv)
            throws Exception {
        ByteArrayBuffer payload = new ByteArrayBuffer();
        payload.putString("testuser");
        payload.putString(AbstractUserAuthServiceFactory.DEFAULT_NAME);
        payload.putString(UserAuthPublicKey.NAME);
        payload.putBoolean(true); // With signature
        payload.putString(sk.getKeyType()); // Algorithm
        payload.putPublicKey(sk);

        MessageDigest md = SecurityUtils.getMessageDigest("SHA-256");
        byte[] uint = new byte[4];
        BufferUtils.putUInt(sessionId.length, uint);
        md.update(uint);
        md.update(sessionId);
        md.update(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        byte[] sigBlobHash = md.digest(payload.getCompactData());

        byte[] appHash = md.digest(sk.getAppName().getBytes(StandardCharsets.UTF_8));

        Signature signer = BuiltinSignatures.nistp256.create();
        signer.initSigner(null, priv);
        signer.update(null, appHash);
        uint[0] = flagsOnSig;
        signer.update(null, uint, 0, 1);
        BufferUtils.putUInt(42, uint); // Counter
        signer.update(null, uint);
        // Extensions only for webauthn, in which case they would also be in the skSignature below.
        signer.update(null, sigBlobHash);
        byte[] rawSignature = signer.sign(null);

        ByteArrayBuffer skSignature = new ByteArrayBuffer();
        skSignature.putString(sk.getKeyType());
        skSignature.putBytes(rawSignature);
        skSignature.putByte(flagsOnSig);
        skSignature.putUInt(42); // Counter
        // Webauthn stuff would follow.

        payload.putBytes(skSignature.getCompactData());
        return payload;
    }

    private static class MockSession extends ServerSessionImpl {

        private byte[] sessionId;

        MockSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
            super(server, ioSession);
        }

        void setSessionId(byte[] id) {
            sessionId = id.clone();
        }

        @Override
        public byte[] getSessionId() {
            return sessionId;
        }
    }
}
