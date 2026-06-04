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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.AbstractUserAuthServiceFactory;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

/**
 * Unit test for {@link UserAuthPublickey} handling certificates on the server-side.
 */
@Tag("NoIoTestCase")
class UserAuthPublicKeyCertificateTest extends BaseTestSupport {

    @ParameterizedTest(name = "auth {0} {1}")
    @CsvSource({ //
            ",,true", //
            "source-address,10.1.2.3/32,true", //
            "source-address,10.1/16,true", //
            "source-address,'10.2/16,10.1/16', true", //
            "source-address,10.2/16,false", //
            "source-address,10.1.2.1/32,false", //
            "source-address,172.1/16,false", //
            "verify-required,,false", //
            "verify-required,bogus,false", //
            "force-command,,false", //
            "force-command,exit,false", //
            "unknown-option,,false", //
            "unknown-option,unknown,false" //
    })
    void testCertOptions(String criticalOption, String optionValue, boolean expectSuccess) throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();

        // Create a CA key
        KeyPair caKeypair = generator.generateKeyPair();
        // Create a certificate for the above key
        OpenSshCertificateBuilder builder = OpenSshCertificateBuilder.userCertificate() //
                .serial(0L) //
                .publicKey(pair.getPublic()) //
                .id("testuser") //
                .principals(Collections.singletonList("testuser"));
        if (criticalOption != null && !criticalOption.isEmpty()) {
            builder = builder.criticalOption(criticalOption, optionValue);
        }
        OpenSshCertificate cert = builder.sign(caKeypair);

        MockSession session = createSession();
        // Give it a session ID since it is part of the signed data.
        byte[] id = new byte[32];
        ThreadLocalRandom.current().nextBytes(id);
        session.setSessionId(id);
        // We don't care about the authenticator in this test.
        session.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        // Create the UserAuthPublickey object under test; give it the signature factories we need.
        UserAuthPublicKey pubkeyAuth = new UserAuthPublicKey(
                Arrays.asList(BuiltinSignatures.nistp256_cert, BuiltinSignatures.nistp256));

        // Create a buffer with a full properly signed authentication request.
        ByteArrayBuffer buffer = createRequest(id, cert, pair.getPrivate());

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

    @ParameterizedTest(name = "auth {0} {1}")
    @CsvSource({ //
            ",,true", //
            "verify-required,,false", //
            "verify-required,bogus,false", //
            "force-command,,false", //
            "force-command,exit,false", //
            "unknown-option,,false", //
            "unknown-option,unknown,false" //
    })
    void testMultipleCertOptions(String criticalOption, String optionValue, boolean expectSuccess) throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();

        // Create a CA key
        KeyPair caKeypair = generator.generateKeyPair();
        // Create a certificate for the above key
        OpenSshCertificateBuilder builder = OpenSshCertificateBuilder.userCertificate() //
                .serial(0L) //
                .publicKey(pair.getPublic()) //
                .id("testuser") //
                .principals(Collections.singletonList("testuser"));
        builder.criticalOption(OpenSshCertificate.SOURCE_ADDRESS, "10.1.2.3/24");
        if (criticalOption != null && !criticalOption.isEmpty()) {
            builder = builder.criticalOption(criticalOption, optionValue);
        }
        OpenSshCertificate cert = builder.sign(caKeypair);

        MockSession session = createSession();
        // Give it a session ID since it is part of the signed data.
        byte[] id = new byte[32];
        ThreadLocalRandom.current().nextBytes(id);
        session.setSessionId(id);
        // We don't care about the authenticator in this test.
        session.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        // Create the UserAuthPublickey object under test; give it the signature factories we need.
        UserAuthPublicKey pubkeyAuth = new UserAuthPublicKey(
                Arrays.asList(BuiltinSignatures.nistp256_cert, BuiltinSignatures.nistp256));

        // Create a buffer with a full properly signed authentication request.
        ByteArrayBuffer buffer = createRequest(id, cert, pair.getPrivate());

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
        // Create a mock ServerSession. We can't simply mock the server session since the authenticator might want to
        // set an attribute on it.
        ServerFactoryManager manager = Mockito.mock(ServerFactoryManager.class);
        Factory<? extends Random> randomFactory = new SingletonRandomFactory(JceRandomFactory.INSTANCE);
        Mockito.when(manager.getRandomFactory()).thenReturn((Factory) randomFactory);
        IoSession ioSession = Mockito.mock(IoSession.class);
        InetSocketAddress fakeClientAddress = new InetSocketAddress(InetAddress.getByAddress(new byte[] { 10, 1, 2, 3 }), 1234);
        Mockito.when(ioSession.getRemoteAddress()).thenReturn(fakeClientAddress);
        return new MockSession(manager, ioSession);
    }

    private ByteArrayBuffer createRequest(byte[] sessionId, OpenSshCertificate cert, PrivateKey priv)
            throws Exception {
        ByteArrayBuffer payload = new ByteArrayBuffer();
        payload.putString("testuser");
        payload.putString(AbstractUserAuthServiceFactory.DEFAULT_NAME);
        payload.putString(UserAuthPublicKey.NAME);
        payload.putBoolean(true); // With signature
        payload.putString(cert.getKeyType()); // Algorithm
        payload.putPublicKey(cert);

        Signature signer = BuiltinSignatures.nistp256_cert.create();
        signer.initSigner(null, priv);
        byte[] uint = new byte[4];
        BufferUtils.putUInt(sessionId.length, uint);
        signer.update(null, uint);
        signer.update(null, sessionId);
        signer.update(null, new byte[] { SshConstants.SSH_MSG_USERAUTH_REQUEST });
        signer.update(null, payload.getCompactData());
        byte[] rawSignature = signer.sign(null);

        ByteArrayBuffer sig = new ByteArrayBuffer();
        sig.putString(cert.getRawKeyType());
        sig.putBytes(rawSignature);
        payload.putBytes(sig.getCompactData());
        return payload;
    }

    private static class MockSession extends ServerSessionImpl {

        MockSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
            super(server, ioSession);
        }

        void setSessionId(byte[] id) {
            sessionId = id.clone();
        }
    }
}
