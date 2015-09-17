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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.deprecated.ClientUserAuthServiceOld;
import org.apache.sshd.deprecated.UserAuthKeyboardInteractive;
import org.apache.sshd.deprecated.UserAuthPassword;
import org.apache.sshd.deprecated.UserAuthPublicKey;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.auth.UserAuthPasswordFactory;
import org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.PromptEntry;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthenticationTest extends BaseTestSupport {

    private static final String WELCOME = "Welcome to SSHD";

    private SshServer sshd;
    private int port;

    public AuthenticationTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.WELCOME_BANNER, WELCOME);
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, "publickey,password publickey,keyboard-interactive");
        sshd.setSessionFactory(new SessionFactory(sshd) {
            @Override
            protected ServerSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                return new TestSession(getServer(), ioSession);
            }
        });
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testWrongPassword() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();
            try (ClientSession s = client.connect("user", TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPasswordIdentity("bad password");
                assertAuthenticationResult(getCurrentTestName(), s.auth(), false);
            }
        }
    }

    @Test
    public void testChangeUser() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));

            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                for (String username : new String[]{"user1", "user2"}) {
                    assertAuthenticationResult(username, authPassword(s, username, "the-password"), false);
                }

                // Note that WAIT_AUTH flag should be false, but since the internal
                // authentication future is not updated, it's still returned
                assertEquals("Mismatched client session close mask", ClientSession.CLOSED | ClientSession.WAIT_AUTH, s.waitFor(ClientSession.CLOSED, 1000));
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-196
    public void testChangePassword() throws Exception {
        final PasswordAuthenticator delegate = sshd.getPasswordAuthenticator();
        final AtomicInteger attemptsCount = new AtomicInteger(0);
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session)
                    throws PasswordChangeRequiredException {
                if (attemptsCount.incrementAndGet() == 1) {
                    throw new PasswordChangeRequiredException(attemptsCount.toString(), getCurrentTestName(), ServerFactoryManager.DEFAULT_WELCOME_BANNER_LANGUAGE);
                }

                return delegate.authenticate(username, password, session);
            }
        });

        final AtomicInteger changesCount = new AtomicInteger(0);
        sshd.setUserAuthFactories(Collections.<NamedFactory<org.apache.sshd.server.auth.UserAuth>>singletonList(
            new org.apache.sshd.server.auth.UserAuthPasswordFactory() {
                @Override
                public org.apache.sshd.server.auth.UserAuth create() {
                    return new org.apache.sshd.server.auth.UserAuthPassword() {
                        @Override
                        protected Boolean handleClientPasswordChangeRequest(
                                Buffer buffer, ServerSession session, String username, String oldPassword, String newPassword)
                                        throws Exception {
                            if (changesCount.incrementAndGet() == 1) {
                                assertNotEquals("Non-different passwords", oldPassword, newPassword);
                                return checkPassword(buffer, session, username, newPassword);
                            } else {
                                return super.handleClientPasswordChangeRequest(buffer, session, username, oldPassword, newPassword);
                            }
                        }
                    };
                }
            }
        ));
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(ClientSession session, String banner, String lang) {
                    // ignored
                }

                @Override
                public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                    throw new UnsupportedOperationException("Unexpected call");
                }

                @Override
                public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                    assertEquals("Mismatched prompt", getCurrentTestName(), prompt);
                    assertEquals("Mismatched language", ServerFactoryManager.DEFAULT_WELCOME_BANNER_LANGUAGE, lang);
                    assertEquals("Unexpected repeated call", 1, updatesCount.incrementAndGet());
                    return getCurrentTestName();
                }
            });

            final AtomicInteger sentCount = new AtomicInteger(0);
            client.setUserAuthFactories(Collections.<NamedFactory<org.apache.sshd.client.auth.UserAuth>>singletonList(
                new org.apache.sshd.client.auth.UserAuthPasswordFactory() {
                    @Override
                    public org.apache.sshd.client.auth.UserAuth create() {
                        return new org.apache.sshd.client.auth.UserAuthPassword() {
                            @Override
                            protected void sendPassword(Buffer buffer, ClientSession session, String oldPassword, String newPassword) throws IOException {
                                int count = sentCount.incrementAndGet();
                                // 1st one is the original one (which is denied by the server)
                                // 2nd one is the updated one retrieved from the user interaction
                                if (count == 2) {
                                    super.sendPassword(buffer, session, getClass().getName(), newPassword);
                                } else {
                                    super.sendPassword(buffer, session, oldPassword, newPassword);
                                }
                            }
                        };
                    }
            }));
            FactoryManagerUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPasswordIdentity(getCurrentTestName());
                s.auth().verify(11L, TimeUnit.SECONDS);
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
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));
            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);
                assertAuthenticationResult(getCurrentTestName(), authPassword(s, getCurrentTestName(), getCurrentTestName()), false);
                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthKeyPassword() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));
            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                assertAuthenticationResult(UserAuthMethodFactory.PUBLIC_KEY, authPublicKey(s, getCurrentTestName(), pair), false);
                assertAuthenticationResult(UserAuthMethodFactory.PASSWORD, authPassword(s, getCurrentTestName(), getCurrentTestName()), true);
                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthDefaultKeyInteractive() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));

            sshd.setKeyboardInteractiveAuthenticator(new DefaultKeyboardInteractiveAuthenticator() {
                @Override
                public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods) {
                    assertEquals("Mismatched user language",
                            FactoryManagerUtils.getStringProperty(
                                    client,
                                    org.apache.sshd.client.auth.UserAuthKeyboardInteractive.INTERACTIVE_LANGUAGE_TAG,
                                    org.apache.sshd.client.auth.UserAuthKeyboardInteractive.DEFAULT_INTERACTIVE_LANGUAGE_TAG),
                            lang);
                    assertEquals("Mismatched client sub-methods",
                            FactoryManagerUtils.getStringProperty(
                                    client,
                                    org.apache.sshd.client.auth.UserAuthKeyboardInteractive.INTERACTIVE_SUBMETHODS,
                                    org.apache.sshd.client.auth.UserAuthKeyboardInteractive.DEFAULT_INTERACTIVE_SUBMETHODS),
                            subMethods);

                    InteractiveChallenge challenge = super.generateChallenge(session, username, lang, subMethods);
                    assertEquals("Mismatched interaction name", getInteractionName(session), challenge.getInteractionName());
                    assertEquals("Mismatched interaction instruction", getInteractionInstruction(session), challenge.getInteractionInstruction());
                    assertEquals("Mismatched language tag", getInteractionLanguage(session), challenge.getLanguageTag());

                    List<PromptEntry> entries = challenge.getPrompts();
                    assertEquals("Mismatched prompts count", 1, GenericUtils.size(entries));

                    PromptEntry entry = entries.get(0);
                    assertEquals("Mismatched prompt", getInteractionPrompt(session), entry.getPrompt());
                    assertEquals("Mismatched echo", isInteractionPromptEchoEnabled(session), entry.isEcho());

                    return challenge;
                }

                @Override
                public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
                    return super.authenticate(session, username, responses);
                }

            });
            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                assertAuthenticationResult(UserAuthMethodFactory.PUBLIC_KEY, authPublicKey(s, getCurrentTestName(), pair), false);
                assertAuthenticationResult(UserAuthMethodFactory.KB_INTERACTIVE, authInteractive(s, getCurrentTestName(), getCurrentTestName()), true);

                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-563
    public void testAuthMultiChallengeKeyInteractive() throws Exception {
        final Class<?> anchor = getClass();
        final InteractiveChallenge challenge = new InteractiveChallenge();
        challenge.setInteractionName(getCurrentTestName());
        challenge.setInteractionInstruction(anchor.getPackage().getName());
        challenge.setLanguageTag(Locale.getDefault().getLanguage());

        final Map<String,String> rspMap = new TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                put("class", anchor.getSimpleName());
                put("package", anchor.getPackage().getName());
                put("test", getCurrentTestName());
            }
        };
        for (String prompt : rspMap.keySet()) {
            challenge.addPrompt(prompt, (GenericUtils.size(challenge.getPrompts()) & 0x1) != 0);
        }

        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);
        final AtomicInteger genCount = new AtomicInteger(0);
        final AtomicInteger authCount = new AtomicInteger(0);
        sshd.setKeyboardInteractiveAuthenticator(new KeyboardInteractiveAuthenticator() {
            @Override
            public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods) {
                assertEquals("Unexpected challenge call", 1, genCount.incrementAndGet());
                return challenge;
            }

            @Override
            public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
                assertEquals("Unexpected authenticate call", 1, authCount.incrementAndGet());
                assertEquals("Mismatched number of responses", GenericUtils.size(rspMap), GenericUtils.size(responses));

                int index = 0;
                for (Map.Entry<String,String> re : rspMap.entrySet()) {
                    String prompt = re.getKey();
                    String expected = re.getValue();
                    String actual = responses.get(index);
                    assertEquals("Mismatched response for prompt=" + prompt, expected, actual);
                    index++;
                }
                return true;
            }
        });
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger interactiveCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(ClientSession session, String banner, String lang) {
                    // ignored
                }

                @Override
                public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                    assertEquals("Unexpected multiple calls", 1, interactiveCount.incrementAndGet());
                    assertEquals("Mismatched name", challenge.getInteractionName(), name);
                    assertEquals("Mismatched instruction", challenge.getInteractionInstruction(), instruction);
                    assertEquals("Mismatched language", challenge.getLanguageTag(), lang);

                    List<PromptEntry> entries = challenge.getPrompts();
                    assertEquals("Mismatched prompts count", GenericUtils.size(entries), GenericUtils.length(prompt));

                    String[] responses = new String[prompt.length];
                    for (int index = 0; index < prompt.length; index++) {
                        PromptEntry e = entries.get(index);
                        String key = e.getPrompt();
                        assertEquals("Mismatched prompt at index=" + index, key, prompt[index]);
                        assertEquals("Mismatched echo at index=" + index, e.isEcho(), echo[index]);
                        responses[index] = ValidateUtils.checkNotNull(rspMap.get(key), "No value for prompt=%s", key);
                    }

                    return responses;
                }

                @Override
                public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                    throw new UnsupportedOperationException("Unexpected call");
                }
            });
            FactoryManagerUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.auth().verify(11L, TimeUnit.SECONDS);
                assertEquals("Bad generated challenge count", 1, genCount.get());
                assertEquals("Bad authentication count", 1, authCount.get());
                assertEquals("Bad interactive count", 1, interactiveCount.get());
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-196
    public void testAuthPasswordChangeRequest() throws Exception {
        final PasswordAuthenticator delegate = ValidateUtils.checkNotNull(sshd.getPasswordAuthenticator(), "No password authenticator");
        final AtomicInteger attemptsCount = new AtomicInteger(0);
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session)
                    throws PasswordChangeRequiredException {
                if (attemptsCount.incrementAndGet() == 1) {
                    throw new PasswordChangeRequiredException(attemptsCount.toString(), getCurrentTestName(), ServerFactoryManager.DEFAULT_WELCOME_BANNER_LANGUAGE);
                }

                return delegate.authenticate(username, password, session);
            }
        });
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(ClientSession session, String banner, String lang) {
                    // ignored
                }

                @Override
                public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                    throw new UnsupportedOperationException("Unexpected call");
                }

                @Override
                public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                    assertEquals("Mismatched prompt", getCurrentTestName(), prompt);
                    assertEquals("Mismatched language", ServerFactoryManager.DEFAULT_WELCOME_BANNER_LANGUAGE, lang);
                    assertEquals("Unexpected repeated call", 1, updatesCount.incrementAndGet());
                    return getCurrentTestName();
                }
            });
            FactoryManagerUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPasswordIdentity(getCurrentTestName());
                s.auth().verify(11L, TimeUnit.SECONDS);
                assertEquals("No password change request generated", 2, attemptsCount.get());
                assertEquals("No user interaction invoked", 1, updatesCount.get());
            } finally {
                client.stop();
            }
        }
    }

    private static void assertAuthenticationResult(String message, AuthFuture future, boolean expected) throws IOException {
        assertTrue(message + ": failed to get result on time", future.await(5L, TimeUnit.SECONDS));
        assertEquals(message + ": mismatched authentication result", expected, future.isSuccess());
    }

    private AuthFuture authPassword(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthPassword(s, "ssh-connection", pswd));
    }

    private AuthFuture authInteractive(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthKeyboardInteractive(s, "ssh-connection", pswd));
    }

    private AuthFuture authPublicKey(ClientSession s, String user, KeyPair pair) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthPublicKey(s, "ssh-connection", pair));
    }

    public static class TestSession extends ServerSessionImpl {
        public TestSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
            super(server, ioSession);
        }

        @Override
        public void handleMessage(Buffer buffer) throws Exception {
            super.handleMessage(buffer);    // debug breakpoint
        }
    }
}
