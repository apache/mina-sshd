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

package org.apache.sshd.server;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.MacFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ServerSessionListenerTest extends BaseTestSupport {
    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    public ServerSessionListenerTest() {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ServerSessionListenerTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ServerSessionListenerTest.class);
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

    @Test // see https://issues.apache.org/jira/browse/SSHD-456
    public void testServerStillListensIfSessionListenerThrowsException() throws Exception {
        final Map<String, SocketAddress> eventsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        final Logger log = LoggerFactory.getLogger(getClass());
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                throwException("SessionCreated", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                throwException("SessionEvent", session);
            }

            @Override
            public void sessionClosed(Session session) {
                throwException("SessionClosed", session);
            }

            private void throwException(String phase, Session session) {
                IoSession ioSession = session.getIoSession();
                SocketAddress addr = ioSession.getRemoteAddress();
                synchronized (eventsMap) {
                    if (eventsMap.put(phase, addr) != null) {
                        return; // already generated an event for this phase
                    }
                }

                RuntimeException e = new RuntimeException("Synthetic exception at phase=" + phase + ": " + addr);
                log.info(e.getMessage());
                throw e;
            }
        };
        sshd.addSessionListener(listener);

        int curCount = 0;
        try {
            for (int retryCount = 0; retryCount < Byte.SIZE; retryCount++) {
                synchronized (eventsMap) {
                    curCount = eventsMap.size();
                    if (curCount >= 3) {
                        return;
                    }
                }

                try {
                    try (ClientSession s = createTestClientSession()) {
                        log.info("Retry #" + retryCount + " successful");
                    }

                    synchronized (eventsMap) {
                        assertTrue("Unexpected premature success at retry # " + retryCount + ": " + eventsMap,
                                eventsMap.size() >= 3);
                    }
                } catch (IOException e) {
                    // expected - ignored
                    synchronized (eventsMap) {
                        int nextCount = eventsMap.size();
                        assertTrue("No session event generated at retry #" + retryCount, nextCount > curCount);
                    }
                }
            }
        } finally {
            sshd.removeSessionListener(listener);
        }
        fail("No success to authenticate");
    }

    @Test
    public void testSessionListenerCanModifyKEXNegotiation() throws Exception {
        Map<KexProposalOption, NamedResource> kexParams = new EnumMap<>(KexProposalOption.class);
        kexParams.put(KexProposalOption.ALGORITHMS, getLeastFavorite(KeyExchangeFactory.class, sshd.getKeyExchangeFactories()));
        kexParams.put(KexProposalOption.S2CENC, getLeastFavorite(CipherFactory.class, sshd.getCipherFactories()));
        kexParams.put(KexProposalOption.S2CMAC, getLeastFavorite(MacFactory.class, sshd.getMacFactories()));

        SessionListener listener = new SessionListener() {
            @Override
            @SuppressWarnings("unchecked")
            public void sessionCreated(Session session) {
                session.setKeyExchangeFactories(
                        Collections.singletonList((KeyExchangeFactory) kexParams.get(KexProposalOption.ALGORITHMS)));
                session.setCipherFactories(
                        Collections.singletonList((NamedFactory<Cipher>) kexParams.get(KexProposalOption.S2CENC)));
                session.setMacFactories(
                        Collections.singletonList((NamedFactory<Mac>) kexParams.get(KexProposalOption.S2CMAC)));
            }
        };
        sshd.addSessionListener(listener);

        try (ClientSession session = createTestClientSession()) {
            kexParams.forEach((option, factory) -> {
                String expected = factory.getName();
                String actual = session.getNegotiatedKexParameter(option);
                assertEquals("Mismatched values for KEX=" + option, expected, actual);
            });
        } finally {
            sshd.removeSessionListener(listener);
        }
    }

    @Test
    public void testSessionListenerCanModifyAuthentication() throws Exception {
        AtomicInteger passCount = new AtomicInteger(0);
        PasswordAuthenticator defaultPassAuth = sshd.getPasswordAuthenticator();
        PasswordAuthenticator passAuth = (username, password, session) -> {
            passCount.incrementAndGet();
            return defaultPassAuth.authenticate(username, password, session);
        };
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                if ((!session.isAuthenticated()) && (session instanceof ServerSession)) {
                    ServerSession serverSession = (ServerSession) session;
                    serverSession.setPasswordAuthenticator(passAuth);
                    serverSession.setUserAuthFactories(
                            Collections.singletonList(
                                    ServerAuthenticationManager.DEFAULT_USER_AUTH_PASSWORD_FACTORY));
                }
            }
        };
        sshd.addSessionListener(listener);

        try (ClientSession session = createTestClientSession()) {
            assertNotSame("Mismatched default password authenticator",
                    passAuth, sshd.getPasswordAuthenticator());
            assertNotSame("Mismatched default kb authenticator",
                    KeyboardInteractiveAuthenticator.NONE, sshd.getKeyboardInteractiveAuthenticator());
            assertEquals("Authenticator override not invoked", 1, passCount.get());
        } finally {
            sshd.removeSessionListener(listener);
        }
    }

    private static <V extends NamedResource> NamedResource getLeastFavorite(
            Class<V> type, List<? extends NamedResource> factories) {
        int numFactories = GenericUtils.size(factories);
        assertTrue("No factories for " + type.getSimpleName(), numFactories > 0);
        return factories.get(numFactories - 1);
    }

    private ClientSession createTestClientSession() throws Exception {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession();
        try {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }
}
