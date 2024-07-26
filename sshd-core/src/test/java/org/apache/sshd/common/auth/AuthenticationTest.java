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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodName.class)
public class AuthenticationTest extends AuthenticationTestSupport {
    public AuthenticationTest() {
        super();
    }

    // see SSHD-600
    @Test
    void authExceptionPropagation() throws Exception {
        try (SshClient client = setupTestClient()) {
            RuntimeException expected = new RuntimeException("Synthetic exception");
            AtomicInteger invocations = new AtomicInteger(0);
            AtomicReference<Throwable> caughtException = new AtomicReference<>();
            client.addSessionListener(new SessionListener() {
                @Override
                public void sessionEvent(Session session, Event event) {
                    assertEquals(1, invocations.incrementAndGet(), "Mismatched invocations count");
                    throw expected;
                }

                @Override
                public void sessionException(Session session, Throwable t) {
                    if (t == expected) {
                        caughtException.set(t);
                    }
                }
            });

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPasswordIdentity(getCurrentTestName());

                AuthFuture future = s.auth();
                assertTrue(future.await(DEFAULT_TIMEOUT), "Failed to complete auth in allocated time");
                assertFalse(future.isSuccess(), "Unexpected authentication success");

                Throwable signalled = future.getException();
                Throwable actual = signalled;
                if (actual instanceof IOException) {
                    actual = actual.getCause();
                }

                if (expected != actual) {
                    // Possible race condition between session close and session exception signalled
                    Throwable caught = caughtException.get();
                    if (caught == null) {
                        fail("Mismatched authentication failure reason: signalled=" + signalled + ", actual=" + actual);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-625
    @Test
    void runtimeErrorsInAuthenticators() throws Exception {
        Error thrown = new OutOfMemoryError(getCurrentTestName());
        PasswordAuthenticator authPassword = sshd.getPasswordAuthenticator();
        AtomicInteger passCounter = new AtomicInteger(0);
        sshd.setPasswordAuthenticator((username, password, session) -> {
            int count = passCounter.incrementAndGet();
            if (count == 1) {
                throw thrown;
            }
            return authPassword.authenticate(username, password, session);
        });

        PublickeyAuthenticator authPubkey = sshd.getPublickeyAuthenticator();
        AtomicInteger pubkeyCounter = new AtomicInteger(0);
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            int count = pubkeyCounter.incrementAndGet();
            if (count == 1) {
                throw thrown;
            }
            return authPubkey.authenticate(username, key, session);
        });
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

        try (SshClient client = setupTestClient()) {
            KeyPair kp = CommonTestSupportUtils.generateKeyPair(
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_PROVIDER_ALGORITHM,
                    CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_SIZE);
            client.start();

            try {
                for (int index = 1; index < 3; index++) {
                    try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                            .verify(CONNECT_TIMEOUT)
                            .getSession()) {
                        s.addPasswordIdentity(getCurrentTestName());
                        s.addPublicKeyIdentity(kp);

                        AuthFuture auth = s.auth();
                        assertTrue(auth.await(AUTH_TIMEOUT), "Failed to complete authentication on time");
                        if (auth.isSuccess()) {
                            assertTrue(index > 1, "Premature authentication success");
                            break;
                        }

                        assertEquals(1, passCounter.get(), "Password authenticator not consulted");
                        assertEquals(1, pubkeyCounter.get(), "Pubkey authenticator not consulted");
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    // see SSHD-1040
    @Test
    void serverKeyAvailableAfterAuth() throws Exception {
        KeyPairProvider keyPairProvider = sshd.getKeyPairProvider();
        Iterable<KeyPair> availableKeys = keyPairProvider.loadKeys(null);
        PublicKey actualKey = null;

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                KeyExchange kex = session.getKex();
                assertNull(kex, "KEX not nullified after completion");

                actualKey = session.getServerKey();
            } finally {
                client.stop();
            }
        }

        assertNotNull(actualKey, "No server key extracted");

        for (KeyPair kp : availableKeys) {
            PublicKey expectedKey = kp.getPublic();
            if (KeyUtils.compareKeys(expectedKey, actualKey)) {
                return;
            }
        }

        fail("No matching server key found for " + actualKey);
    }
}
