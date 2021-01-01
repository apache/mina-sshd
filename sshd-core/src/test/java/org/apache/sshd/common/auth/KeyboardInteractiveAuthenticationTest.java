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

import java.security.KeyPair;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.auth.keyboard.DefaultKeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.PromptEntry;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
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
public class KeyboardInteractiveAuthenticationTest extends AuthenticationTestSupport {
    public KeyboardInteractiveAuthenticationTest() {
        super();
    }

    @Test // see SSHD-612
    public void testAuthDefaultKeyInteractive() throws Exception {
        try (SshClient client = setupTestClient()) {
            sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
            sshd.setKeyboardInteractiveAuthenticator(new DefaultKeyboardInteractiveAuthenticator() {
                @Override
                public InteractiveChallenge generateChallenge(
                        ServerSession session, String username, String lang, String subMethods)
                        throws Exception {
                    assertEquals("Mismatched user language",
                            CoreModuleProperties.INTERACTIVE_LANGUAGE_TAG.getRequired(client),
                            lang);
                    assertEquals("Mismatched client sub-methods",
                            CoreModuleProperties.INTERACTIVE_SUBMETHODS.getRequired(client),
                            subMethods);

                    InteractiveChallenge challenge = super.generateChallenge(session, username, lang, subMethods);
                    assertEquals("Mismatched interaction name", getInteractionName(session), challenge.getInteractionName());
                    assertEquals("Mismatched interaction instruction", getInteractionInstruction(session),
                            challenge.getInteractionInstruction());
                    assertEquals("Mismatched language tag", getInteractionLanguage(session), challenge.getLanguageTag());

                    List<PromptEntry> entries = challenge.getPrompts();
                    assertEquals("Mismatched prompts count", 1, GenericUtils.size(entries));

                    PromptEntry entry = entries.get(0);
                    assertEquals("Mismatched prompt", getInteractionPrompt(session), entry.getPrompt());
                    assertEquals("Mismatched echo", isInteractionPromptEchoEnabled(session), entry.isEcho());

                    return challenge;
                }

                @Override
                public boolean authenticate(
                        ServerSession session, String username, List<String> responses)
                        throws Exception {
                    return super.authenticate(session, username, responses);
                }

            });
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

                try {
                    assertAuthenticationResult(UserAuthMethodFactory.KB_INTERACTIVE,
                            authInteractive(s, getCurrentTestName(), getCurrentTestName()), true);
                } finally {
                    s.setUserInteraction(null);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-563
    public void testAuthMultiChallengeKeyInteractive() throws Exception {
        Class<?> anchor = getClass();
        InteractiveChallenge challenge = new InteractiveChallenge();
        challenge.setInteractionName(getCurrentTestName());
        challenge.setInteractionInstruction(anchor.getPackage().getName());
        challenge.setLanguageTag(Locale.getDefault().getLanguage());

        Map<String, String> rspMap = NavigableMapBuilder.<String, String> builder(String.CASE_INSENSITIVE_ORDER)
                .put("class", anchor.getSimpleName())
                .put("package", anchor.getPackage().getName())
                .put("test", getCurrentTestName())
                .build();
        for (String prompt : rspMap.keySet()) {
            challenge.addPrompt(prompt, (GenericUtils.size(challenge.getPrompts()) & 0x1) != 0);
        }

        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthKeyboardInteractiveFactory.NAME);
        AtomicInteger genCount = new AtomicInteger(0);
        AtomicInteger authCount = new AtomicInteger(0);
        sshd.setKeyboardInteractiveAuthenticator(new KeyboardInteractiveAuthenticator() {
            @Override
            public InteractiveChallenge generateChallenge(
                    ServerSession session, String username, String lang, String subMethods)
                    throws Exception {
                assertEquals("Unexpected challenge call", 1, genCount.incrementAndGet());
                return challenge;
            }

            @Override
            public boolean authenticate(
                    ServerSession session, String username, List<String> responses)
                    throws Exception {
                assertEquals("Unexpected authenticate call", 1, authCount.incrementAndGet());
                assertEquals("Mismatched number of responses", GenericUtils.size(rspMap), GenericUtils.size(responses));

                int index = 0;
                // Cannot use forEach because the index is not effectively final
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
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthKeyboardInteractiveFactory.NAME);

        try (SshClient client = setupTestClient()) {
            AtomicInteger interactiveCount = new AtomicInteger(0);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public String[] interactive(
                        ClientSession session, String name, String instruction,
                        String lang, String[] prompt, boolean[] echo) {
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
            CoreModuleProperties.AUTH_METHODS.set(client, UserAuthKeyboardInteractiveFactory.NAME);

            client.start();

            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.auth().verify(AUTH_TIMEOUT);
                assertEquals("Bad generated challenge count", 1, genCount.get());
                assertEquals("Bad authentication count", 1, authCount.get());
                assertEquals("Bad interactive count", 1, interactiveCount.get());
            } finally {
                client.stop();
            }
        }
    }
}
