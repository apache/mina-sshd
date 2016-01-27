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
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientSessionListenerTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    public ClientSessionListenerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        client = setupTestClient();
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testSessionListenerCanModifyKEXNegotiation() throws Exception {
        final Map<KexProposalOption, NamedFactory<?>> kexParams = new EnumMap<>(KexProposalOption.class);
        kexParams.put(KexProposalOption.ALGORITHMS, getLeastFavorite(KeyExchange.class, client.getKeyExchangeFactories()));
        kexParams.put(KexProposalOption.C2SENC, getLeastFavorite(Cipher.class, client.getCipherFactories()));
        kexParams.put(KexProposalOption.C2SMAC, getLeastFavorite(Mac.class, client.getMacFactories()));

        client.addSessionListener(new SessionListener() {
            @Override
            @SuppressWarnings("unchecked")
            public void sessionCreated(Session session) {
                session.setKeyExchangeFactories(Collections.singletonList((NamedFactory<KeyExchange>) kexParams.get(KexProposalOption.ALGORITHMS)));
                session.setCipherFactories(Collections.singletonList((NamedFactory<Cipher>) kexParams.get(KexProposalOption.C2SENC)));
                session.setMacFactories(Collections.singletonList((NamedFactory<Mac>) kexParams.get(KexProposalOption.C2SMAC)));
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                // ignored
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
        try (ClientSession session = createTestClientSession()) {
            for (Map.Entry<KexProposalOption, ? extends NamedResource> ke : kexParams.entrySet()) {
                KexProposalOption option = ke.getKey();
                String expected = ke.getValue().getName();
                String actual = session.getNegotiatedKexParameter(option);
                assertEquals("Mismatched values for KEX=" + option, expected, actual);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testSessionListenerCanInfluenceAuthentication() throws IOException {
        final AtomicInteger verificationCount = new AtomicInteger();
        final ServerKeyVerifier verifier = new ServerKeyVerifier() {
            @Override
            public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                verificationCount.incrementAndGet();
                return true;
            }
        };

        client.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if ((!session.isAuthenticated()) && (session instanceof ClientSession) && Event.KexCompleted.equals(event)) {
                    ClientSession clientSession = (ClientSession) session;
                    clientSession.setServerKeyVerifier(verifier);
                    clientSession.setUserInteraction(UserInteraction.NONE);
                }
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
        try (ClientSession session = createTestClientSession()) {
            assertNotSame("Invalid default user interaction", UserInteraction.NONE, client.getUserInteraction());
            assertNotSame("Invalid default server key verifier", verifier, client.getServerKeyVerifier());
            assertSame("Mismatched session user interaction", UserInteraction.NONE, session.getUserInteraction());
            assertSame("Mismatched session server key verifier", verifier, session.getServerKeyVerifier());
            assertEquals("Mismatched verification count", 1, verificationCount.get());
        } finally {
            client.stop();
        }
    }

    private static <V> NamedFactory<V> getLeastFavorite(Class<V> type, List<? extends NamedFactory<V>> factories) {
        int numFactories = GenericUtils.size(factories);
        assertTrue("No factories for " + type.getSimpleName(), numFactories > 0);
        return factories.get(numFactories - 1);
    }

    private ClientSession createTestClientSession() throws IOException {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
        try {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

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
