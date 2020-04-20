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

package org.apache.sshd.client;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.MacFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientSessionListenerTest extends BaseTestSupport {
    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    public ClientSessionListenerTest() {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ClientSessionListenerTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ClientSessionListenerTest.class);
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
    public void testSessionListenerCanModifyKEXNegotiation() throws Exception {
        Map<KexProposalOption, NamedResource> kexParams = new EnumMap<>(KexProposalOption.class);
        kexParams.put(KexProposalOption.ALGORITHMS, getLeastFavorite(KeyExchange.class, client.getKeyExchangeFactories()));
        kexParams.put(KexProposalOption.C2SENC, getLeastFavorite(CipherFactory.class, client.getCipherFactories()));
        kexParams.put(KexProposalOption.C2SMAC, getLeastFavorite(MacFactory.class, client.getMacFactories()));

        SessionListener listener = new SessionListener() {
            @Override
            @SuppressWarnings("unchecked")
            public void sessionCreated(Session session) {
                session.setKeyExchangeFactories(
                        Collections.singletonList((KeyExchangeFactory) kexParams.get(KexProposalOption.ALGORITHMS)));
                session.setCipherFactories(
                        Collections.singletonList((NamedFactory<Cipher>) kexParams.get(KexProposalOption.C2SENC)));
                session.setMacFactories(
                        Collections.singletonList((NamedFactory<Mac>) kexParams.get(KexProposalOption.C2SMAC)));
            }
        };
        client.addSessionListener(listener);

        try (ClientSession session = createTestClientSession()) {
            kexParams.forEach((option, factory) -> {
                String expected = factory.getName();
                String actual = session.getNegotiatedKexParameter(option);
                assertEquals("Mismatched values for KEX=" + option, expected, actual);
            });
        } finally {
            client.removeSessionListener(listener);
        }
    }

    @Test
    public void testSessionListenerCanInfluenceAuthentication() throws IOException {
        AtomicInteger verificationCount = new AtomicInteger();
        ServerKeyVerifier verifier = (sshClientSession, remoteAddress, serverKey) -> {
            verificationCount.incrementAndGet();
            return true;
        };
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionEvent(Session session, Event event) {
                if ((!session.isAuthenticated())
                        && (session instanceof ClientSession)
                        && Event.KexCompleted.equals(event)) {
                    ClientSession clientSession = (ClientSession) session;
                    clientSession.setServerKeyVerifier(verifier);
                    clientSession.setUserInteraction(UserInteraction.NONE);
                }
            }
        };
        client.addSessionListener(listener);

        try (ClientSession session = createTestClientSession()) {
            assertNotSame("Invalid default user interaction", UserInteraction.NONE, client.getUserInteraction());
            assertNotSame("Invalid default server key verifier", verifier, client.getServerKeyVerifier());
            assertSame("Mismatched session user interaction", UserInteraction.NONE, session.getUserInteraction());
            assertSame("Mismatched session server key verifier", verifier, session.getServerKeyVerifier());
            assertEquals("Mismatched verification count", 1, verificationCount.get());
        } finally {
            client.removeSessionListener(listener);
        }
    }

    private static <V extends NamedResource> NamedResource getLeastFavorite(
            Class<V> type, List<? extends NamedResource> factories) {
        int numFactories = GenericUtils.size(factories);
        assertTrue("No factories for " + type.getSimpleName(), numFactories > 0);
        return factories.get(numFactories - 1);
    }

    private ClientSession createTestClientSession() throws IOException {
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
