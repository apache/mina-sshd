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

package org.apache.sshd.common.kex.extension;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests for message handling during "strict KEX" is active: initial KEX must fail and disconnect if the KEX_INIT
 * message is not first, or if there are spurious extra messages like IGNORE or DEBUG during KEX. Later KEXes must
 * succeed even if there are spurious messages.
 * <p>
 * The other part of "strict KEX" is resetting the message sequence numbers after KEX. This is not tested here but in
 * the {@link StrictKexInteroperabilityTest}, which runs an Apache MINA sshd client against OpenSSH servers that have or
 * do not have the "strict KEX" extension. If the sequence number handling was wrong, those tests would fail.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/apache/mina-sshd/issues/445">Terrapin Mitigation: &quot;strict-kex&quot;</A>
 */
@TestMethodOrder(MethodName.class)
public class StrictKexTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;

    public StrictKexTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestServer();
        client = setupTestClient();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    void connectionClosedIfFirstPacketFromClientNotKexInit() throws Exception {
        testConnectionClosedIfFirstPacketFromPeerNotKexInit(true);
    }

    @Test
    void connectionClosedIfFirstPacketFromServerNotKexInit() throws Exception {
        testConnectionClosedIfFirstPacketFromPeerNotKexInit(false);
    }

    private void testConnectionClosedIfFirstPacketFromPeerNotKexInit(boolean clientInitiates) throws Exception {
        AtomicReference<IoWriteFuture> debugMsg = new AtomicReference<>();
        SessionListener messageInitiator = new SessionListener() {
            @Override // At this stage KEX-INIT not sent yet
            public void sessionNegotiationOptionsCreated(Session session, Map<KexProposalOption, String> proposal) {
                try {
                    debugMsg.set(session.sendDebugMessage(true, getCurrentTestName(), null));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        if (clientInitiates) {
            client.addSessionListener(messageInitiator);
        } else {
            sshd.addSessionListener(messageInitiator);
        }

        try (ClientSession session = obtainInitialTestClientSession()) {
            fail("Unexpected session success");
        } catch (SshException e) {
            IoWriteFuture future = debugMsg.get();
            assertNotNull(future, "No SSH_MSG_DEBUG");
            assertTrue(future.isWritten(), "SSH_MSG_DEBUG should have been sent");
            // Due to a race condition in the Nio2 transport when closing a connection due to an exception it's possible
            // that we do _not_ get the expected disconnection code. The race condition may lead to the IoSession being
            // closed in the peer before it has sent the DISCONNECT message. Happens in particular on Windows.
            if (e.getDisconnectCode() == SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED) {
                assertTrue(e.getMessage()
                        .startsWith("Strict KEX negotiated but sequence number of first KEX_INIT received is not 1"),
                        "Unexpected disconnect reason: " + e.getMessage());
            }
        }
    }

    @Test
    void connectionClosedIfSpuriousPacketFromClientInKex() throws Exception {
        testConnectionClosedIfSupriousPacketInKex(true);
    }

    @Test
    void connectionClosedIfSpuriousPacketFromServerInKex() throws Exception {
        testConnectionClosedIfSupriousPacketInKex(false);
    }

    private void testConnectionClosedIfSupriousPacketInKex(boolean clientInitiates) throws Exception {
        AtomicReference<IoWriteFuture> debugMsg = new AtomicReference<>();
        SessionListener messageInitiator = new SessionListener() {
            @Override // At this stage the peer's KEX_INIT has been received
            public void sessionNegotiationEnd(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                try {
                    debugMsg.set(session.sendDebugMessage(true, getCurrentTestName(), null));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        if (clientInitiates) {
            client.addSessionListener(messageInitiator);
        } else {
            sshd.addSessionListener(messageInitiator);
        }

        try (ClientSession session = obtainInitialTestClientSession()) {
            fail("Unexpected session success");
        } catch (SshException e) {
            IoWriteFuture future = debugMsg.get();
            assertNotNull(future, "No SSH_MSG_DEBUG");
            assertTrue(future.isWritten(), "SSH_MSG_DEBUG should have been sent");
            if (e.getDisconnectCode() == SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED) {
                assertEquals("SSH_MSG_DEBUG not allowed during initial key exchange in strict KEX", e.getMessage(),
                        "Unexpected disconnect reason");
            }
        }
    }

    @Test
    void reKeyAllowsDebugInKexFromClient() throws Exception {
        testReKeyAllowsDebugInKex(true);
    }

    @Test
    void reKeyAllowsDebugInKexFromServer() throws Exception {
        testReKeyAllowsDebugInKex(false);
    }

    private void testReKeyAllowsDebugInKex(boolean clientInitiates) throws Exception {
        AtomicBoolean sendDebug = new AtomicBoolean();
        AtomicReference<IoWriteFuture> debugMsg = new AtomicReference<>();
        SessionListener messageInitiator = new SessionListener() {
            @Override // At this stage the peer's KEX_INIT has been received
            public void sessionNegotiationEnd(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                if (sendDebug.get()) {
                    try {
                        debugMsg.set(session.sendDebugMessage(true, getCurrentTestName(), null));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        };

        if (clientInitiates) {
            client.addSessionListener(messageInitiator);
        } else {
            sshd.addSessionListener(messageInitiator);
        }

        try (ClientSession session = obtainInitialTestClientSession()) {
            assertTrue(session.isOpen(), "Session should be stablished");
            sendDebug.set(true);
            assertTrue(session.reExchangeKeys().verify(CONNECT_TIMEOUT).isDone(), "KEX not done");
            IoWriteFuture future = debugMsg.get();
            assertNotNull(future, "No SSH_MSG_DEBUG");
            assertTrue(future.isWritten(), "SSH_MSG_DEBUG should have been sent");
            assertTrue(session.isOpen());
        }
    }

    @Test
    void strictKexWorksWithServerFlagInClientProposal() throws Exception {
        testStrictKexWorksWithWrongFlag(true);
    }

    @Test
    void strictKexWorksWithClientFlagInServerProposal() throws Exception {
        testStrictKexWorksWithWrongFlag(false);
    }

    private void testStrictKexWorksWithWrongFlag(boolean clientInitiates) throws Exception {
        SessionListener messageInitiator = new SessionListener() {
            @Override
            public void sessionNegotiationOptionsCreated(Session session, Map<KexProposalOption, String> proposal) {
                // Modify the proposal by including the *wrong* flag. (The framework will also add the correct flag.)
                String value = proposal.get(KexProposalOption.ALGORITHMS);
                String toAdd = clientInitiates
                        ? KexExtensions.STRICT_KEX_SERVER_EXTENSION
                        : KexExtensions.STRICT_KEX_CLIENT_EXTENSION;
                if (GenericUtils.isEmpty(value)) {
                    value = toAdd;
                } else {
                    value += ',' + toAdd;
                }
                proposal.put(KexProposalOption.ALGORITHMS, value);
            }
        };

        if (clientInitiates) {
            client.addSessionListener(messageInitiator);
        } else {
            sshd.addSessionListener(messageInitiator);
        }

        try (ClientSession session = obtainInitialTestClientSession()) {
            assertTrue(session.isOpen(), "Session should be stablished");
        }
    }

    private ClientSession obtainInitialTestClientSession() throws IOException {
        sshd.start();
        int port = sshd.getPort();

        client.start();
        return createAuthenticatedClientSession(client, port);
    }
}
