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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PasswordAuthenticationTest extends AuthenticationTestSupport {
    public PasswordAuthenticationTest() {
        super();
    }

    @Test
    public void testWrongPassword() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();
            try (ClientSession s = client.connect("user", TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPasswordIdentity("bad password");
                assertAuthenticationResult(getCurrentTestName(), s.auth(), false);
            }
        }
    }

    @Test
    public void testChangeUser() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                Collection<ClientSession.ClientSessionEvent> mask
                        = EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH);
                Collection<ClientSession.ClientSessionEvent> result = s.waitFor(mask, DEFAULT_TIMEOUT);
                assertFalse("Timeout while waiting on session events",
                        result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                String password = "the-password";
                for (String username : new String[] { "user1", "user2" }) {
                    try {
                        assertAuthenticationResult(username, authPassword(s, username, password), false);
                    } finally {
                        s.removePasswordIdentity(password);
                    }
                }

                // Note that WAIT_AUTH flag should be false, but since the internal
                // authentication future is not updated, it's still returned
                result = s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), DEFAULT_TIMEOUT);
                assertTrue("Mismatched client session close mask: " + result, result.containsAll(mask));
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-196
    public void testChangePassword() throws Exception {
        PasswordAuthenticator delegate = sshd.getPasswordAuthenticator();
        AtomicInteger attemptsCount = new AtomicInteger(0);
        AtomicInteger changesCount = new AtomicInteger(0);
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                if (attemptsCount.incrementAndGet() == 1) {
                    throw new PasswordChangeRequiredException(
                            attemptsCount.toString(),
                            getCurrentTestName(), CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequiredDefault());
                }

                return delegate.authenticate(username, password, session);
            }

            @Override
            public boolean handleClientPasswordChangeRequest(
                    ServerSession session, String username, String oldPassword, String newPassword) {
                if (changesCount.incrementAndGet() == 1) {
                    assertNotEquals("Non-different passwords", oldPassword, newPassword);
                    return authenticate(username, newPassword, session);
                } else {
                    return PasswordAuthenticator.super.handleClientPasswordChangeRequest(
                            session, username, oldPassword, newPassword);
                }
            }
        });
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public String[] interactive(
                        ClientSession session, String name, String instruction,
                        String lang, String[] prompt, boolean[] echo) {
                    throw new UnsupportedOperationException("Unexpected call");
                }

                @Override
                public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                    assertEquals("Mismatched prompt", getCurrentTestName(), prompt);
                    assertEquals("Mismatched language",
                            CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequiredDefault(), lang);
                    assertEquals("Unexpected repeated call", 1, updatesCount.incrementAndGet());
                    return getCurrentTestName();
                }
            });

            AtomicInteger sentCount = new AtomicInteger(0);
            client.setUserAuthFactories(Collections.singletonList(
                    new org.apache.sshd.client.auth.password.UserAuthPasswordFactory() {
                        @Override
                        public org.apache.sshd.client.auth.password.UserAuthPassword createUserAuth(ClientSession session)
                                throws IOException {
                            return new org.apache.sshd.client.auth.password.UserAuthPassword() {
                                @Override
                                protected IoWriteFuture sendPassword(
                                        Buffer buffer, ClientSession session, String oldPassword, String newPassword)
                                        throws Exception {
                                    int count = sentCount.incrementAndGet();
                                    // 1st one is the original one (which is denied by the server)
                                    // 2nd one is the updated one retrieved from the user interaction
                                    if (count == 2) {
                                        return super.sendPassword(buffer, session, getClass().getName(), newPassword);
                                    } else {
                                        return super.sendPassword(buffer, session, oldPassword, newPassword);
                                    }
                                }
                            };
                        }
                    }));
            CoreModuleProperties.AUTH_METHODS.set(client, UserAuthPasswordFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPasswordIdentity(getCurrentTestName());
                s.auth().verify(AUTH_TIMEOUT);
                assertEquals("No password change request generated", 2, attemptsCount.get());
                assertEquals("No password change handled", 1, changesCount.get());
                assertEquals("No user interaction invoked", 1, updatesCount.get());
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthPasswordOnly() throws Exception {
        try (SshClient client = setupTestClient()) {
            sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

            client.start();
            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                Collection<ClientSession.ClientSessionEvent> result = s.waitFor(
                        EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH),
                        DEFAULT_TIMEOUT);
                assertFalse("Timeout while waiting for session", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                String password = getCurrentTestName();
                try {
                    assertAuthenticationResult(getCurrentTestName(),
                            authPassword(s, getCurrentTestName(), password), false);
                } finally {
                    s.removePasswordIdentity(password);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthKeyPassword() throws Exception {
        try (SshClient client = setupTestClient()) {
            sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
            sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                Collection<ClientSession.ClientSessionEvent> result = s.waitFor(
                        EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH),
                        DEFAULT_TIMEOUT);
                assertFalse("Timeout while waiting for session", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                KeyPairProvider provider = createTestHostKeyProvider();
                KeyPair pair = provider.loadKey(s, CommonTestSupportUtils.DEFAULT_TEST_HOST_KEY_TYPE);
                try {
                    assertAuthenticationResult(UserAuthMethodFactory.PUBLIC_KEY,
                            authPublicKey(s, getCurrentTestName(), pair), false);
                } finally {
                    s.removePublicKeyIdentity(pair);
                }

                String password = getCurrentTestName();
                try {
                    assertAuthenticationResult(UserAuthMethodFactory.PASSWORD,
                            authPassword(s, getCurrentTestName(), password), true);
                } finally {
                    s.removePasswordIdentity(password);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-196
    public void testAuthPasswordChangeRequest() throws Exception {
        PasswordAuthenticator delegate = Objects.requireNonNull(sshd.getPasswordAuthenticator(), "No password authenticator");
        AtomicInteger attemptsCount = new AtomicInteger(0);
        sshd.setPasswordAuthenticator((username, password, session) -> {
            if (attemptsCount.incrementAndGet() == 1) {
                throw new PasswordChangeRequiredException(
                        attemptsCount.toString(),
                        getCurrentTestName(), CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequiredDefault());
            }

            return delegate.authenticate(username, password, session);
        });
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public String[] interactive(
                        ClientSession session, String name, String instruction,
                        String lang, String[] prompt, boolean[] echo) {
                    throw new UnsupportedOperationException("Unexpected call");
                }

                @Override
                public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                    assertEquals("Mismatched prompt", getCurrentTestName(), prompt);
                    assertEquals("Mismatched language",
                            CoreModuleProperties.WELCOME_BANNER_LANGUAGE.getRequiredDefault(), lang);
                    assertEquals("Unexpected repeated call", 1, updatesCount.incrementAndGet());
                    return getCurrentTestName();
                }
            });
            CoreModuleProperties.AUTH_METHODS.set(client, UserAuthPasswordFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPasswordIdentity(getCurrentTestName());
                s.auth().verify(AUTH_TIMEOUT);
                assertEquals("No password change request generated", 2, attemptsCount.get());
                assertEquals("No user interaction invoked", 1, updatesCount.get());
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testPasswordIdentityProviderPropagation() throws Exception {
        try (SshClient client = setupTestClient()) {
            List<String> passwords = Collections.singletonList(getCurrentTestName());
            AtomicInteger loadCount = new AtomicInteger(0);
            PasswordIdentityProvider provider = () -> {
                loadCount.incrementAndGet();
                outputDebugMessage("loadPasswords - count=%s", loadCount);
                return passwords;
            };
            client.setPasswordIdentityProvider(provider);

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.auth().verify(AUTH_TIMEOUT);
                assertEquals("Mismatched load passwords count", 1, loadCount.get());
                assertSame("Mismatched passwords identity provider", provider, s.getPasswordIdentityProvider());
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-714
    public void testPasswordIdentityWithSpacesPrefixOrSuffix() throws Exception {
        sshd.setPasswordAuthenticator((username, password, session) -> {
            return (username != null) && (!username.trim().isEmpty())
                    && (password != null) && (!password.isEmpty())
                    && ((password.charAt(0) == ' ') || (password.charAt(password.length() - 1) == ' '));
        });

        try (SshClient client = setupTestClient()) {
            client.start();

            try {
                for (String password : new String[] {
                        " ", "    ", "  " + getCurrentTestName(), getCurrentTestName() + "    "
                }) {
                    try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                            .verify(CONNECT_TIMEOUT)
                            .getSession()) {
                        s.addPasswordIdentity(password);

                        AuthFuture auth = s.auth();
                        assertTrue("No authentication result in time for password='" + password + "'",
                                auth.await(AUTH_TIMEOUT));
                        assertTrue("Failed to authenticate with password='" + password + "'", auth.isSuccess());
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-1114
    public void testPasswordAuthenticationReporter() throws Exception {
        String goodPassword = getCurrentTestName();
        String badPassword = getClass().getSimpleName();
        List<String> attempted = new ArrayList<>();
        sshd.setPasswordAuthenticator((user, password, session) -> {
            attempted.add(password);
            return goodPassword.equals(password);
        });
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);

        List<String> reported = new ArrayList<>();
        PasswordAuthenticationReporter reporter = new PasswordAuthenticationReporter() {
            @Override
            public void signalAuthenticationAttempt(
                    ClientSession session, String service, String oldPassword, boolean modified, String newPassword)
                    throws Exception {
                reported.add(oldPassword);
            }

            @Override
            public void signalAuthenticationSuccess(ClientSession session, String service, String password)
                    throws Exception {
                assertEquals("Mismatched succesful password", goodPassword, password);
            }

            @Override
            public void signalAuthenticationFailure(
                    ClientSession session, String service, String password, boolean partial, List<String> serverMethods)
                    throws Exception {
                assertEquals("Mismatched failed password", badPassword, password);
            }
        };

        try (SshClient client = setupTestClient()) {
            client.setUserAuthFactories(
                    Collections.singletonList(new org.apache.sshd.client.auth.password.UserAuthPasswordFactory()));
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(badPassword);
                session.addPasswordIdentity(goodPassword);
                session.setPasswordAuthenticationReporter(reporter);
                session.auth().verify(AUTH_TIMEOUT);
            } finally {
                client.stop();
            }
        }

        List<String> expected = Arrays.asList(badPassword, goodPassword);
        assertListEquals("Attempted passwords", expected, attempted);
        assertListEquals("Reported passwords", expected, reported);
    }

    @Test   // see SSHD-1114
    public void testAuthenticationAttemptsExhausted() throws Exception {
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

        AtomicInteger exhaustedCount = new AtomicInteger();
        PasswordAuthenticationReporter reporter = new PasswordAuthenticationReporter() {
            @Override
            public void signalAuthenticationExhausted(ClientSession session, String service) throws Exception {
                exhaustedCount.incrementAndGet();
            }
        };

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
            public String resolveAuthPasswordAttempt(ClientSession session) throws Exception {
                int count = attemptsCount.incrementAndGet();
                if (count <= 3) {
                    return "attempt#" + count;
                } else {
                    return UserInteraction.super.resolveAuthPasswordAttempt(session);
                }
            }
        };

        try (SshClient client = setupTestClient()) {
            client.setUserAuthFactories(
                    Collections.singletonList(new org.apache.sshd.client.auth.password.UserAuthPasswordFactory()));
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.setPasswordAuthenticationReporter(reporter);
                session.setUserInteraction(ui);
                for (int index = 1; index <= 5; index++) {
                    session.addPasswordIdentity("password#" + index);
                }

                AuthFuture auth = session.auth();
                assertAuthenticationResult("Authenticating", auth, false);
            } finally {
                client.stop();
            }
        }

        assertEquals("Mismatched invocation count", 1, exhaustedCount.getAndSet(0));
        assertEquals("Mismatched retries count", 4 /* 3 attempts + null */, attemptsCount.getAndSet(0));
    }
}
