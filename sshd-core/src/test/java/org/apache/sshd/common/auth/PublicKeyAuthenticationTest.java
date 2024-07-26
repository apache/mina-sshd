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

package org.apache.sshd.common.auth;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.resource.URLResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class PublicKeyAuthenticationTest extends AuthenticationTestSupport {
    public PublicKeyAuthenticationTest() {
        super();
    }

    // see SSHD-618
    @Test
    void publicKeyAuthDifferentThanKex() throws Exception {
        KeyPairProvider serverKeys = KeyPairProvider.wrap(
                CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024),
                CommonTestSupportUtils.generateKeyPair(KeyUtils.DSS_ALGORITHM, 512),
                CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256));
        sshd.setKeyPairProvider(serverKeys);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

        KeyPair clientIdentity = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            String keyType = KeyUtils.getKeyType(key);
            String expType = KeyUtils.getKeyType(clientIdentity);
            assertEquals(expType, keyType, "Mismatched client key types");
            assertKeyEquals("Mismatched authentication public keys", clientIdentity.getPublic(), key);
            return true;
        });

        // since we need to use RSA
        CoreTestSupportUtils.setupFullSignaturesSupport(sshd);
        try (SshClient client = setupTestClient()) {
            // force server to use only RSA
            NamedFactory<Signature> kexSignature = BuiltinSignatures.rsa;
            client.setSignatureFactories(Collections.singletonList(kexSignature));
            client.setServerKeyVerifier((sshClientSession, remoteAddress, serverKey) -> {
                String keyType = KeyUtils.getKeyType(serverKey);
                String expType = kexSignature.getName();
                assertEquals(expType, keyType, "Mismatched server key type");

                KeyPair kp;
                try {
                    kp = ValidateUtils.checkNotNull(serverKeys.loadKey(null, keyType), "No server key for type=%s", keyType);
                } catch (IOException | GeneralSecurityException e) {
                    throw new RuntimeException("Unexpected " + e.getClass().getSimpleName() + ")"
                                               + " keys loading exception: " + e.getMessage(),
                            e);
                }
                assertKeyEquals("Mismatched server public keys", kp.getPublic(), serverKey);
                return true;
            });

            // allow only EC keys for public key authentication
            org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory factory
                    = new org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory();
            factory.setSignatureFactories(
                    Arrays.asList(
                            BuiltinSignatures.nistp256, BuiltinSignatures.nistp384, BuiltinSignatures.nistp521));
            client.setUserAuthFactories(Collections.singletonList(factory));

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPublicKeyIdentity(clientIdentity);
                s.auth().verify(AUTH_TIMEOUT);
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-624
    @Test
    void userAuthPkOkWrongKey() throws Exception {
        sshd.setUserAuthFactories(Collections.singletonList(
                new org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory() {
                    @Override
                    public org.apache.sshd.server.auth.pubkey.UserAuthPublicKey createUserAuth(ServerSession session)
                            throws IOException {
                        return new org.apache.sshd.server.auth.pubkey.UserAuthPublicKey() {
                            @Override
                            protected void sendPublicKeyResponse(
                                    ServerSession session, String username, String alg, PublicKey key,
                                    byte[] keyBlob, int offset, int blobLen, Buffer buffer)
                                    throws Exception {
                                // send another key
                                KeyPair otherPair = org.apache.sshd.util.test.CommonTestSupportUtils
                                        .generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
                                PublicKey otherKey = otherPair.getPublic();
                                Buffer buf = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK,
                                        blobLen + alg.length() + Long.SIZE);
                                buf.putString(alg);
                                buf.putPublicKey(otherKey);
                                session.writePacket(buf);
                            }
                        };
                    }

                }));

        try (SshClient client = setupTestClient()) {
            KeyPair clientIdentity = CommonTestSupportUtils.generateKeyPair(
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM,
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_SIZE);
            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPublicKeyIdentity(clientIdentity);
                SshException e = assertThrows(SshException.class, () -> s.auth().verify(AUTH_TIMEOUT));
                Throwable t = e.getCause();
                assertObjectInstanceOf("Unexpected failure cause", InvalidKeySpecException.class, t);
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-1141
    @Test
    void userAuthPkOkWrongAlgorithm() throws Exception {
        sshd.setUserAuthFactories(Collections.singletonList(
                new org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory() {
                    @Override
                    public org.apache.sshd.server.auth.pubkey.UserAuthPublicKey createUserAuth(ServerSession session)
                            throws IOException {
                        return new org.apache.sshd.server.auth.pubkey.UserAuthPublicKey() {
                            @Override
                            protected void sendPublicKeyResponse(
                                    ServerSession session, String username, String alg, PublicKey key,
                                    byte[] keyBlob, int offset, int blobLen, Buffer buffer)
                                    throws Exception {
                                super.sendPublicKeyResponse(session, username, KeyPairProvider.SSH_DSS, key, keyBlob, offset,
                                        blobLen, buffer);
                            }
                        };
                    }

                }));

        try (SshClient client = setupTestClient()) {
            KeyPair clientIdentity = CommonTestSupportUtils.generateKeyPair(
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM,
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_SIZE);
            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                s.addPublicKeyIdentity(clientIdentity);
                assertTrue(s.auth().verify(AUTH_TIMEOUT).isSuccess(), "Successful authentication expected");
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-862
    @Test
    void sessionContextPropagatedToKeyFilePasswordProvider() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                String keyLocation = "super-secret-passphrase-ec256-key";
                FilePasswordProvider passwordProvider = new FilePasswordProvider() {
                    @Override
                    public String getPassword(
                            SessionContext session, NamedResource resourceKey, int retryIndex)
                            throws IOException {
                        assertSame(s, session, "Mismatched session context");
                        assertEquals(0, retryIndex, "Mismatched retry index");

                        String name = resourceKey.getName();
                        int pos = name.lastIndexOf('/');
                        if (pos >= 0) {
                            name = name.substring(pos + 1);
                        }
                        assertEquals(keyLocation, name, "Mismatched location");

                        Boolean passwordRequested = session.getAttribute(PASSWORD_ATTR);
                        assertNull(passwordRequested, "Password already requested");
                        session.setAttribute(PASSWORD_ATTR, Boolean.TRUE);
                        return "super secret passphrase";
                    }
                };
                s.setKeyIdentityProvider(new KeyIdentityProvider() {
                    @Override
                    public Iterable<KeyPair> loadKeys(SessionContext session) throws IOException, GeneralSecurityException {
                        assertSame(s, session, "Mismatched session context");
                        URL location = getClass().getResource(keyLocation);
                        assertNotNull(location, "Missing key file " + keyLocation);

                        URLResource resourceKey = new URLResource(location);
                        Iterable<KeyPair> ids;
                        try (InputStream keyData = resourceKey.openInputStream()) {
                            ids = SecurityUtils.loadKeyPairIdentities(session, resourceKey, keyData, passwordProvider);
                        }
                        KeyPair kp = GenericUtils.head(ids);
                        assertNotNull(kp, "No identity loaded from " + resourceKey);
                        return Collections.singletonList(kp);
                    }
                });
                s.auth().verify(AUTH_TIMEOUT);

                Boolean passwordRequested = s.getAttribute(PASSWORD_ATTR);
                assertNotNull(passwordRequested, "Password provider not invoked");
                assertTrue(passwordRequested.booleanValue(), "Password not requested");
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-1114
    @Test
    void publicKeyAuthenticationReporter() throws Exception {
        KeyPair goodIdentity = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        KeyPair badIdentity = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        List<PublicKey> attempted = new ArrayList<>();
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            attempted.add(key);
            return KeyUtils.compareKeys(goodIdentity.getPublic(), key);
        });
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

        List<PublicKey> reported = new ArrayList<>();
        List<PublicKey> signed = new ArrayList<>();
        PublicKeyAuthenticationReporter reporter = new PublicKeyAuthenticationReporter() {
            @Override
            public void signalAuthenticationAttempt(
                    ClientSession session, String service, KeyPair identity, String signature)
                    throws Exception {
                reported.add(identity.getPublic());
            }

            @Override
            public void signalSignatureAttempt(
                    ClientSession session, String service, KeyPair identity, String signature, byte[] sigData)
                    throws Exception {
                signed.add(identity.getPublic());
            }

            @Override
            public void signalAuthenticationSuccess(ClientSession session, String service, KeyPair identity)
                    throws Exception {
                assertTrue(KeyUtils.compareKeys(goodIdentity.getPublic(), identity.getPublic()), "Mismatched success identity");
            }

            @Override
            public void signalAuthenticationFailure(
                    ClientSession session, String service, KeyPair identity, boolean partial, List<String> serverMethods)
                    throws Exception {
                assertTrue(KeyUtils.compareKeys(badIdentity.getPublic(), identity.getPublic()), "Mismatched failed identity");
            }
        };

        try (SshClient client = setupTestClient()) {
            client.setUserAuthFactories(
                    Collections.singletonList(new org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory()));
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPublicKeyIdentity(badIdentity);
                session.addPublicKeyIdentity(goodIdentity);
                session.setPublicKeyAuthenticationReporter(reporter);
                session.auth().verify(AUTH_TIMEOUT);
            } finally {
                client.stop();
            }
        }

        List<PublicKey> expected = Arrays.asList(badIdentity.getPublic(), goodIdentity.getPublic());
        // The server public key authenticator is called twice with the good identity
        int numAttempted = attempted.size();
        assertKeyListEquals("Attempted", expected, (numAttempted > 0) ? attempted.subList(0, numAttempted - 1) : attempted);
        assertKeyListEquals("Reported", expected, reported);
        // The signing is attempted only if the initial public key is accepted
        assertKeyListEquals("Signed", Collections.singletonList(goodIdentity.getPublic()), signed);
    }

    // see SSHD-1114
    @Test
    void authenticationAttemptsExhausted() throws Exception {
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

        AtomicInteger exhaustedCount = new AtomicInteger();
        PublicKeyAuthenticationReporter reporter = new PublicKeyAuthenticationReporter() {
            @Override
            public void signalAuthenticationExhausted(ClientSession session, String service) throws Exception {
                exhaustedCount.incrementAndGet();
            }
        };

        KeyPair kp = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        AtomicInteger attemptsCount = new AtomicInteger();
        UserInteraction ui = new UserInteraction() {
            @Override
            public String[] interactive(
                    ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                throw new UnsupportedOperationException("Unexpected interactive invocation");
            }

            @Override
            public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                throw new UnsupportedOperationException("Unexpected updated password request");
            }

            @Override
            public KeyPair resolveAuthPublicKeyIdentityAttempt(ClientSession session) throws Exception {
                int count = attemptsCount.incrementAndGet();
                if (count <= 3) {
                    return kp;
                } else {
                    return UserInteraction.super.resolveAuthPublicKeyIdentityAttempt(session);
                }
            }
        };

        try (SshClient client = setupTestClient()) {
            client.setUserAuthFactories(
                    Collections.singletonList(new org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory()));
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.setPublicKeyAuthenticationReporter(reporter);
                session.setUserInteraction(ui);
                for (int index = 1; index <= 5; index++) {
                    session.addPublicKeyIdentity(kp);
                }
                AuthFuture auth = session.auth();
                assertAuthenticationResult("Authenticating", auth, false);
            } finally {
                client.stop();
            }
        }

        assertEquals(1, exhaustedCount.getAndSet(0), "Mismatched invocation count");
        assertEquals(4 /* 3 attempts + null */, attemptsCount.getAndSet(0), "Mismatched retries count");
    }

    @Test
    void rsaAuthenticationOldServer() throws Exception {
        KeyPair userkey = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 2048);
        List<String> factoryNames = sshd.getSignatureFactoriesNames();
        // Remove anything that has "rsa" in the name, except "ssh-rsa". Make sure "ssh-rsa" is there.
        // We need to keep the others; the test server uses an EC host key, and sshd uses the same
        // factory list for host key algorithms and public key signature algorithms. So we can't just
        // set the list to only "ssh-rsa".
        boolean sshRsaFound = false;
        for (Iterator<String> i = factoryNames.iterator(); i.hasNext();) {
            String name = i.next();
            if (name.equalsIgnoreCase("ssh-rsa")) {
                sshRsaFound = true;
            } else if (name.toLowerCase(Locale.ROOT).contains("rsa")) {
                i.remove();
            }
        }
        if (!sshRsaFound) {
            factoryNames.add("ssh-rsa");
        }
        sshd.setSignatureFactoriesNames(factoryNames);
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            return KeyUtils.compareKeys(userkey.getPublic(), key);
        });
        try (SshClient client = setupTestClient()) {
            client.setUserAuthFactories(
                    Collections.singletonList(new org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory()));
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPublicKeyIdentity(userkey);
                assertTrue(session.auth().verify(AUTH_TIMEOUT).isSuccess(), "Successful authentication expected");
            } finally {
                client.stop();
            }
        }
    }
}
