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
package org.apache.sshd.contrib.client.auth.password;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class InteractivePasswordIdentityProviderTest extends BaseTestSupport {
    public InteractivePasswordIdentityProviderTest() {
        super();
    }

    @Test
    void passwordEnumerations() throws IOException, GeneralSecurityException {
        List<String> expected
                = Arrays.asList(getClass().getSimpleName(), getClass().getPackage().getName(), getCurrentTestName());
        ClientSession session = Mockito.mock(ClientSession.class);
        AtomicInteger passwordIndex = new AtomicInteger(0);
        String prompt = getCurrentTestName();
        UserInteraction userInteraction = Mockito.mock(UserInteraction.class);
        Mockito.when(userInteraction.isInteractionAllowed(ArgumentMatchers.any(ClientSession.class))).thenReturn(Boolean.TRUE);
        Mockito.when(userInteraction.getUpdatedPassword(ArgumentMatchers.any(ClientSession.class), ArgumentMatchers.anyString(),
                ArgumentMatchers.anyString()))
                .thenAnswer(new Answer<String>() {
                    @Override
                    public String answer(InvocationOnMock invocation) throws Throwable {
                        Object[] args = invocation.getArguments();
                        assertSame(session, args[0], "Mismatched session instance at index=" + passwordIndex);
                        assertSame(prompt, args[1], "Mismatched prompt instance at index=" + passwordIndex);

                        int index = passwordIndex.getAndIncrement();
                        if (index < expected.size()) {
                            return expected.get(index);
                        }
                        assertEquals(expected.size(), index, "Mismatched last call index");
                        return null;
                    }
                });
        Mockito.when(session.getUserInteraction()).thenReturn(userInteraction);

        PasswordIdentityProvider provider = InteractivePasswordIdentityProvider.providerOf(session, prompt);
        Iterable<String> passwords = provider.loadPasswords(session);
        int expIndex = 0;
        for (String actValue : passwords) {
            String expValue = expected.get(expIndex);
            assertSame(expValue, actValue, "Mismatched password provided at index=" + expIndex);
            expIndex++;
        }

        assertEquals(expected.size() + 1, passwordIndex.get(), "Not all passwords exhausted");
        assertEquals(expIndex, expected.size(), "Mismatched retrieved passwords count");
    }

    @Test
    void interactionAllowedConsultation() throws IOException, GeneralSecurityException {
        ClientSession session = Mockito.mock(ClientSession.class);
        UserInteraction userInteraction = Mockito.mock(UserInteraction.class);
        Mockito.when(userInteraction.isInteractionAllowed(ArgumentMatchers.any(ClientSession.class))).thenReturn(Boolean.FALSE);
        Mockito.when(userInteraction.getUpdatedPassword(ArgumentMatchers.any(ClientSession.class), ArgumentMatchers.anyString(),
                ArgumentMatchers.anyString()))
                .thenThrow(new UnsupportedOperationException("Unexpected call"));
        PasswordIdentityProvider provider
                = InteractivePasswordIdentityProvider.providerOf(session, userInteraction, getCurrentTestName());
        Iterable<String> passwords = provider.loadPasswords(session);
        for (String p : passwords) {
            fail("Unexpected password: " + p);
        }
    }
}
