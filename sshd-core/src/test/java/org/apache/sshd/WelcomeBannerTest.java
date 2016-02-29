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
package org.apache.sshd;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WelcomeBannerTest extends BaseTestSupport {

    private static final String WELCOME = "Welcome to SSHD WelcomeBannerTest";

    private SshServer sshd;
    private int port;

    public WelcomeBannerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.WELCOME_BANNER, WELCOME);
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
    public void testBanner() throws Exception {
        try (SshClient client = setupTestClient()) {
            final AtomicReference<String> welcomeHolder = new AtomicReference<>(null);
            final AtomicReference<ClientSession> sessionHolder = new AtomicReference<>(null);
            client.setUserInteraction(new UserInteraction() {
                @Override
                public boolean isInteractionAllowed(ClientSession session) {
                    return true;
                }

                @Override
                public void serverVersionInfo(ClientSession session, List<String> lines) {
                    validateSession("serverVersionInfo", session);
                }

                @Override
                public void welcome(ClientSession session, String banner, String lang) {
                    validateSession("welcome", session);
                    assertNull("Multiple banner invocations", welcomeHolder.getAndSet(banner));
                }

                @Override
                public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                    validateSession("interactive", session);
                    return null;
                }

                @Override
                public String getUpdatedPassword(ClientSession clientSession, String prompt, String lang) {
                    throw new UnsupportedOperationException("Unexpected call");
                }

                private void validateSession(String phase, ClientSession session) {
                    ClientSession prev = sessionHolder.getAndSet(session);
                    if (prev != null) {
                        assertSame("Mismatched " + phase + " client session", prev, session);
                    }
                }
            });
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);
                assertSame("Mismatched sessions", session, sessionHolder.get());
                assertEquals("Mismatched banner", WELCOME, welcomeHolder.get());
            } finally {
                client.stop();
            }
        }
    }
}
