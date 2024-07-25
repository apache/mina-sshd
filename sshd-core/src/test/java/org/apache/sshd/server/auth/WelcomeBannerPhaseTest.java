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

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class WelcomeBannerPhaseTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    private WelcomeBannerPhase phase;

    public void initWelcomeBannerPhaseTest(WelcomeBannerPhase phase) {
        this.phase = phase;
    }

    public static List<Object[]> parameters() {
        return parameterize(WelcomeBannerPhase.VALUES);
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(WelcomeBannerPhaseTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(WelcomeBannerPhaseTest.class);
        client.start();
    }

    @AfterAll
    static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void welcomeBannerPhase(WelcomeBannerPhase phase) throws Exception {
        initWelcomeBannerPhaseTest(phase);
        CoreModuleProperties.WELCOME_BANNER_PHASE.set(sshd, phase);
        CoreModuleProperties.WELCOME_BANNER.set(sshd, phase.name());

        AtomicReference<String> welcomeHolder = new AtomicReference<>(null);
        client.setUserInteraction(new UserInteraction() {
            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public void welcome(ClientSession session, String banner, String lang) {
                assertNull(welcomeHolder.getAndSet(banner), "Multiple banner invocations");
            }

            @Override
            public String getUpdatedPassword(ClientSession clientSession, String prompt, String lang) {
                throw new UnsupportedOperationException("Unexpected call");
            }

            @Override
            public String[] interactive(
                    ClientSession session, String name, String instruction,
                    String lang, String[] prompt, boolean[] echo) {
                return null;
            }
        });

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
        }

        Object banner = welcomeHolder.getAndSet(null);
        if (WelcomeBannerPhase.NEVER.equals(phase)) {
            assertNull(banner, "Unexpected banner");
        } else {
            WelcomeBannerPhase value
                    = PropertyResolverUtils.toEnum(WelcomeBannerPhase.class, banner, false, WelcomeBannerPhase.VALUES);
            assertSame(phase, value, "Mismatched banner value");
        }
    }
}
