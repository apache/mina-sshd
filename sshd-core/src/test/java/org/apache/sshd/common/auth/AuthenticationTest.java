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
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.hostbased.HostKeyIdentityProvider;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.PromptEntry;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthenticationTest extends BaseTestSupport {
    private SshServer sshd;
    private int port;

    public AuthenticationTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
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
            client.start();

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                Collection<ClientSession.ClientSessionEvent> mask =
                        EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH);
                Collection<ClientSession.ClientSessionEvent> result = s.waitFor(mask, TimeUnit.SECONDS.toMillis(11L));
                assertFalse("Timeout while waiting on session events", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                String password = "the-password";
                for (String username : new String[]{"user1", "user2"}) {
                    try {
                        assertAuthenticationResult(username, authPassword(s, username, password), false);
                    } finally {
                        s.removePasswordIdentity(password);
                    }
                }

                // Note that WAIT_AUTH flag should be false, but since the internal
                // authentication future is not updated, it's still returned
                result = s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), TimeUnit.SECONDS.toMillis(3L));
                assertTrue("Mismatched client session close mask: " + result, result.containsAll(mask));
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
            new org.apache.sshd.server.auth.password.UserAuthPasswordFactory() {
                @Override
                public org.apache.sshd.server.auth.password.UserAuthPassword create() {
                    return new org.apache.sshd.server.auth.password.UserAuthPassword() {
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
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public void serverVersionInfo(ClientSession session, List<String> lines) {
                    // ignored
                }

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
                new org.apache.sshd.client.auth.password.UserAuthPasswordFactory() {
                    @Override
                    public org.apache.sshd.client.auth.password.UserAuthPassword create() {
                        return new org.apache.sshd.client.auth.password.UserAuthPassword() {
                            @Override
                            protected IoWriteFuture sendPassword(Buffer buffer, ClientSession session, String oldPassword, String newPassword) throws IOException {
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
            PropertyResolverUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

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
            sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

            client.start();
            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                Collection<ClientSession.ClientSessionEvent> result =
                        s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH),
                        TimeUnit.SECONDS.toMillis(11L));
                assertFalse("Timeout while waiting for session", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                String password = getCurrentTestName();
                try {
                    assertAuthenticationResult(getCurrentTestName(), authPassword(s, getCurrentTestName(), password), false);
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

            try (ClientSession s = client.connect(null, TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                Collection<ClientSession.ClientSessionEvent> result =
                        s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH),
                        TimeUnit.SECONDS.toMillis(11L));
                assertFalse("Timeout while waiting for session", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                try {
                    assertAuthenticationResult(UserAuthMethodFactory.PUBLIC_KEY, authPublicKey(s, getCurrentTestName(), pair), false);
                } finally {
                    s.removePublicKeyIdentity(pair);
                }

                String password = getCurrentTestName();
                try {
                    assertAuthenticationResult(UserAuthMethodFactory.PASSWORD, authPassword(s, getCurrentTestName(), password), true);
                } finally {
                    s.removePasswordIdentity(password);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-612
    public void testAuthDefaultKeyInteractive() throws Exception {
        try (SshClient client = setupTestClient()) {
            sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
            sshd.setKeyboardInteractiveAuthenticator(new DefaultKeyboardInteractiveAuthenticator() {
                @Override
                public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods) {
                    assertEquals("Mismatched user language",
                            PropertyResolverUtils.getStringProperty(
                                    client,
                                    org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractive.INTERACTIVE_LANGUAGE_TAG,
                                    org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractive.DEFAULT_INTERACTIVE_LANGUAGE_TAG),
                            lang);
                    assertEquals("Mismatched client sub-methods",
                            PropertyResolverUtils.getStringProperty(
                                    client,
                                    org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractive.INTERACTIVE_SUBMETHODS,
                                    org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractive.DEFAULT_INTERACTIVE_SUBMETHODS),
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
                Collection<ClientSession.ClientSessionEvent> result =
                        s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH),
                        TimeUnit.SECONDS.toMillis(11L));
                assertFalse("Timeout while waiting for session", result.contains(ClientSession.ClientSessionEvent.TIMEOUT));

                KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                try {
                    assertAuthenticationResult(UserAuthMethodFactory.PUBLIC_KEY, authPublicKey(s, getCurrentTestName(), pair), false);
                } finally {
                    s.removePublicKeyIdentity(pair);
                }

                try {
                    assertAuthenticationResult(UserAuthMethodFactory.KB_INTERACTIVE, authInteractive(s, getCurrentTestName(), getCurrentTestName()), true);
                } finally {
                    s.setUserInteraction(null);
                }
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

        final Map<String, String> rspMap = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER) {
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

        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);
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
                for (Map.Entry<String, String> re : rspMap.entrySet()) {
                    String prompt = re.getKey();
                    String expected = re.getValue();
                    String actual = responses.get(index);
                    assertEquals("Mismatched response for prompt=" + prompt, expected, actual);
                    index++;
                }
                return true;
            }
        });
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger interactiveCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public void serverVersionInfo(ClientSession session, List<String> lines) {
                    // ignored
                }

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
            PropertyResolverUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthKeyboardInteractiveFactory.NAME);

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
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

        try (SshClient client = setupTestClient()) {
            final AtomicInteger updatesCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public void serverVersionInfo(ClientSession session, List<String> lines) {
                    // ignored
                }

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
            PropertyResolverUtils.updateProperty(client, ServerFactoryManager.AUTH_METHODS, UserAuthPasswordFactory.NAME);

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

    @Test   // see SSHD-600
    public void testAuthExceptionPropagation() throws Exception {
        try (SshClient client = setupTestClient()) {
            final RuntimeException expected = new RuntimeException("Synthetic exception");
            final AtomicInteger invocations = new AtomicInteger(0);
            client.addSessionListener(new SessionListener() {
                @Override
                public void sessionCreated(Session session) {
                    // ignored
                }

                @Override
                public void sessionEvent(Session session, Event event) {
                    assertEquals("Mismatched invocations count", 1, invocations.incrementAndGet());
                    throw expected;
                }

                @Override
                public void sessionException(Session session, Throwable t) {
                    // ignored
                }

                @Override
                public void sessionClosed(Session session) {
                    // ignored
                }
            });

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPasswordIdentity(getCurrentTestName());

                AuthFuture future = s.auth();
                assertTrue("Failed to complete auth in allocated time", future.await(11L, TimeUnit.SECONDS));
                assertFalse("Unexpected authentication success", future.isSuccess());

                Throwable actual = future.getException();
                if (actual instanceof IOException) {
                    actual = actual.getCause();
                }
                assertSame("Mismatched authentication failure reason", expected, actual);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testPasswordIdentityProviderPropagation() throws Exception {
        try (SshClient client = setupTestClient()) {
            final List<String> passwords = Collections.singletonList(getCurrentTestName());
            final AtomicInteger loadCount = new AtomicInteger(0);
            PasswordIdentityProvider provider = new PasswordIdentityProvider() {
                @Override
                public Iterable<String> loadPasswords() {
                    loadCount.incrementAndGet();
                    outputDebugMessage("loadPasswords - count=%s", loadCount);
                    return passwords;
                }
            };
            client.setPasswordIdentityProvider(provider);

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.auth().verify(11L, TimeUnit.SECONDS);
                assertEquals("Mismatched load passwords count", 1, loadCount.get());
                assertSame("Mismatched passwords identity provider", provider, s.getPasswordIdentityProvider());
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-618
    public void testPublicKeyAuthDifferentThanKex() throws Exception {
        final KeyPairProvider serverKeys = KeyPairProvider.Utils.wrap(
                    Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024),
                    Utils.generateKeyPair(KeyUtils.DSS_ALGORITHM, 512),
                    Utils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256));
        sshd.setKeyPairProvider(serverKeys);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);

        final KeyPair clientIdentity = Utils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                String keyType = KeyUtils.getKeyType(key);
                String expType = KeyUtils.getKeyType(clientIdentity);
                assertEquals("Mismatched client key types", expType, keyType);
                assertKeyEquals("Mismatched authentication public keys", clientIdentity.getPublic(), key);
                return true;
            }
        });

        try (SshClient client = setupTestClient()) {
            // force server to use only the RSA key
            final NamedFactory<Signature> kexSignature = BuiltinSignatures.rsa;
            client.setSignatureFactories(Collections.<NamedFactory<Signature>>singletonList(kexSignature));
            client.setServerKeyVerifier(new ServerKeyVerifier() {
                @Override
                public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                    String keyType = KeyUtils.getKeyType(serverKey);
                    String expType = kexSignature.getName();
                    assertEquals("Mismatched server key type", expType, keyType);

                    KeyPair kp = ValidateUtils.checkNotNull(serverKeys.loadKey(keyType), "No server key for type=%s", keyType);
                    assertKeyEquals("Mismatched server public keys", kp.getPublic(), serverKey);
                    return true;
                }
            });

            // allow only EC keys for public key authentication
            org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory factory = new org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory();
            factory.setSignatureFactories(Arrays.<NamedFactory<Signature>>asList(BuiltinSignatures.nistp256, BuiltinSignatures.nistp384, BuiltinSignatures.nistp521));
            client.setUserAuthFactories(Collections.<NamedFactory<UserAuth>>singletonList(factory));

            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPublicKeyIdentity(clientIdentity);
                s.auth().verify(11L, TimeUnit.SECONDS);
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-624
    public void testMismatchedUserAuthPkOkData() throws Exception {
        final AtomicInteger challengeCounter = new AtomicInteger(0);
        sshd.setUserAuthFactories(Collections.<NamedFactory<org.apache.sshd.server.auth.UserAuth>>singletonList(
                new org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory() {
                    @Override
                    public org.apache.sshd.server.auth.pubkey.UserAuthPublicKey create() {
                        return new org.apache.sshd.server.auth.pubkey.UserAuthPublicKey() {
                            @Override
                            protected void sendPublicKeyResponse(ServerSession session, String username, String alg, PublicKey key,
                                    byte[] keyBlob, int offset, int blobLen, Buffer buffer) throws Exception {
                                int count = challengeCounter.incrementAndGet();
                                outputDebugMessage("sendPublicKeyChallenge(%s)[%s]: count=%d", session, alg, count);
                                if (count == 1) {
                                    // send wrong key type
                                    super.sendPublicKeyResponse(session, username, KeyPairProvider.SSH_DSS, key, keyBlob, offset, blobLen, buffer);
                                } else if (count == 2) {
                                    // send another key
                                    KeyPair otherPair = org.apache.sshd.util.test.Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
                                    PublicKey otherKey = otherPair.getPublic();
                                    Buffer buf = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_PK_OK, blobLen + alg.length() + Long.SIZE);
                                    buf.putString(alg);
                                    buf.putPublicKey(otherKey);
                                    session.writePacket(buf);
                                } else {
                                    super.sendPublicKeyResponse(session, username, alg, key, keyBlob, offset, blobLen, buffer);
                                }
                            }
                        };
                    }

        }));

        try (SshClient client = setupTestClient()) {
            KeyPair clientIdentity = Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
            client.start();

            try {
                for (int index = 1; index <= 4; index++) {
                    try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                        s.addPublicKeyIdentity(clientIdentity);
                        s.auth().verify(17L, TimeUnit.SECONDS);
                        assertEquals("Mismatched number of challenges", 3, challengeCounter.get());
                        break;
                    } catch (SshException e) {   // expected
                        outputDebugMessage("%s on retry #%d: %s", e.getClass().getSimpleName(), index, e.getMessage());

                        Throwable t = e.getCause();
                        assertObjectInstanceOf("Unexpected failure cause at retry #" + index, InvalidKeySpecException.class, t);
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-620
    public void testHostBasedAuthentication() throws Exception {
        final String hostClienUser = getClass().getSimpleName();
        final String hostClientName = SshdSocketAddress.toAddressString(SshdSocketAddress.getFirstExternalNetwork4Address());
        final KeyPair hostClientKey = Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        final AtomicInteger invocationCount = new AtomicInteger(0);
        sshd.setHostBasedAuthenticator(new HostBasedAuthenticator() {
            @Override
            public boolean authenticate(ServerSession session, String username,
                    PublicKey clientHostKey, String clientHostName, String clientUsername, List<X509Certificate> certificates) {
                invocationCount.incrementAndGet();
                return hostClienUser.equals(clientUsername)
                    && hostClientName.equals(clientHostName)
                    && KeyUtils.compareKeys(hostClientKey.getPublic(), clientHostKey);
            }
        });
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        sshd.setUserAuthFactories(
                Collections.<NamedFactory<org.apache.sshd.server.auth.UserAuth>>singletonList(
                        org.apache.sshd.server.auth.hostbased.UserAuthHostBasedFactory.INSTANCE));

        try (SshClient client = setupTestClient()) {
            org.apache.sshd.client.auth.hostbased.UserAuthHostBasedFactory factory =
                    new org.apache.sshd.client.auth.hostbased.UserAuthHostBasedFactory();
            // TODO factory.setClientHostname(CLIENT_HOSTNAME);
            factory.setClientUsername(hostClienUser);
            factory.setClientHostKeys(HostKeyIdentityProvider.Utils.wrap(hostClientKey));

            client.setUserAuthFactories(Collections.<NamedFactory<org.apache.sshd.client.auth.UserAuth>>singletonList(factory));
            client.start();
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.auth().verify(11L, TimeUnit.SECONDS);
                assertEquals("Mismatched authenticator invocation count", 1, invocationCount.get());
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-625
    public void testRuntimeErrorsInAuthenticators() throws Exception {
        final Error thrown = new OutOfMemoryError(getCurrentTestName());
        final PasswordAuthenticator authPassword = sshd.getPasswordAuthenticator();
        final AtomicInteger passCounter = new AtomicInteger(0);
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session)
                    throws PasswordChangeRequiredException {
                int count = passCounter.incrementAndGet();
                if (count == 1) {
                    throw thrown;
                }
                return authPassword.authenticate(username, password, session);
            }
        });

        final PublickeyAuthenticator authPubkey = sshd.getPublickeyAuthenticator();
        final AtomicInteger pubkeyCounter = new AtomicInteger(0);
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                int count = pubkeyCounter.incrementAndGet();
                if (count == 1) {
                    throw thrown;
                }
                return authPubkey.authenticate(username, key, session);
            }
        });
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);

        try (SshClient client = setupTestClient()) {
            KeyPair kp = Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
            client.start();
            try {
                for (int index = 1; index < 3; index++) {
                    try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                        s.addPasswordIdentity(getCurrentTestName());
                        s.addPublicKeyIdentity(kp);

                        AuthFuture auth = s.auth();
                        assertTrue("Failed to complete authentication on time", auth.await(11L, TimeUnit.SECONDS));
                        if (auth.isSuccess()) {
                            assertTrue("Premature authentication success", index > 1);
                            break;
                        }

                        assertEquals("Password authenticator not consulted", 1, passCounter.get());
                        assertEquals("Pubkey authenticator not consulted", 1, pubkeyCounter.get());
                    }
                }
            } finally {
                client.stop();
            }
        }
    }

    private static void assertAuthenticationResult(String message, AuthFuture future, boolean expected) throws IOException {
        assertTrue(message + ": failed to get result on time", future.await(5L, TimeUnit.SECONDS));
        assertEquals(message + ": mismatched authentication result", expected, future.isSuccess());
    }

    private static AuthFuture authPassword(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        s.addPasswordIdentity(pswd);
        return s.auth();
    }

    private static AuthFuture authInteractive(final ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        final String[] response = {pswd};
        s.setUserInteraction(new UserInteraction() {
            @Override
            public void welcome(ClientSession session, String banner, String lang) {
                // ignored
            }

            @Override
            public void serverVersionInfo(ClientSession session, List<String> lines) {
                // ignored
            }

            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                assertSame("Mismatched session instance", s, session);
                assertEquals("Mismatched prompt size", 1, GenericUtils.length(prompt));
                assertTrue("Mismatched prompt: " + prompt[0], prompt[0].toLowerCase().contains("password"));
                return response;
            }

            @Override
            public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                throw new UnsupportedOperationException("Unexpected password update request");
            }
        });
        return s.auth();
    }

    private static AuthFuture authPublicKey(ClientSession s, String user, KeyPair pair) throws IOException {
        s.setUsername(user);
        s.addPublicKeyIdentity(pair);
        return s.auth();
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
