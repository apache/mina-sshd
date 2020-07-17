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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class WelcomeBannerPhaseTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    private WelcomeBannerPhase phase;

    public WelcomeBannerPhaseTest(WelcomeBannerPhase phase) {
        this.phase = phase;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(WelcomeBannerPhase.VALUES);
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(WelcomeBannerPhaseTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(WelcomeBannerPhaseTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
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

    @Test
    public void testWelcomeBannerPhase() throws Exception {
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
                assertNull("Multiple banner invocations", welcomeHolder.getAndSet(banner));
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
            assertNull("Unexpected banner", banner);
        } else {
            WelcomeBannerPhase value
                    = PropertyResolverUtils.toEnum(WelcomeBannerPhase.class, banner, false, WelcomeBannerPhase.VALUES);
            assertSame("Mismatched banner value", phase, value);
        }
    }
}
