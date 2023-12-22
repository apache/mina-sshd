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
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.helpers.SessionCountersDetails;
import org.apache.sshd.common.session.helpers.SessionKexDetails;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoCommand;
import org.apache.sshd.util.test.EchoCommandFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/apache/mina-sshd/issues/445">Terrapin Mitigation: &quot;strict-kex&quot;</A>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount") // Number of private methods is 6 (max allowed is 5)
public class StrictKexTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;

    public StrictKexTest() {
        super();
    }

    @Override
    protected SshServer setupTestServer() {
        SshServer server = super.setupTestServer();
        CoreModuleProperties.USE_STRICT_KEX.set(server, true);
        return server;
    }

    @Override
    protected SshClient setupTestClient() {
        SshClient sshc = super.setupTestClient();
        CoreModuleProperties.USE_STRICT_KEX.set(sshc, true);
        return sshc;
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        client = setupTestClient();
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
    public void testConnectionClosedIfFirstPacketFromClientNotKexInit() throws Exception {
        testConnectionClosedIfFirstPacketFromPeerNotKexInit(true);
    }

    @Test
    public void testConnectionClosedIfFirstPacketFromServerNotKexInit() throws Exception {
        testConnectionClosedIfFirstPacketFromPeerNotKexInit(false);
    }

    private void testConnectionClosedIfFirstPacketFromPeerNotKexInit(boolean clientInitiates) throws Exception {
        AtomicBoolean disconnectSignalled = new AtomicBoolean();
        SessionListener disconnectListener = new SessionListener() {
            @Override
            public void sessionDisconnect(Session session, int reason, String msg, String language, boolean initiator) {
                if (reason != SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR) {
                    failWithWrittenErrorMessage("Invalid disconnect reason(%d): %s", reason, msg);
                }

                synchronized (disconnectSignalled) {
                    disconnectSignalled.set(true);
                    disconnectSignalled.notifyAll();
                }
            }
        };

        SessionListener messageInitiator = new SessionListener() {
            @Override // At this stage KEX-INIT not sent yet
            public void sessionNegotiationOptionsCreated(Session session, Map<KexProposalOption, String> proposal) {
                try {
                    IoWriteFuture future = session.sendDebugMessage(true, getCurrentTestName(), null);
                    boolean completed = future.verify(CONNECT_TIMEOUT).isWritten();
                    if (!completed) {
                        failWithWrittenErrorMessage("Debug message not sent on time");
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        if (clientInitiates) {
            client.addSessionListener(messageInitiator);
            sshd.addSessionListener(disconnectListener);
        } else {
            sshd.addSessionListener(messageInitiator);
            client.addSessionListener(disconnectListener);
        }

        try (ClientSession session = obtainInitialTestClientSession()) {
            fail("Unexpected session success");
        } catch (SshException e) {
            synchronized (disconnectSignalled) {
                for (long remWait = CONNECT_TIMEOUT.toMillis(); remWait > 0L;) {
                    if (disconnectSignalled.get()) {
                        break;
                    }

                    long waitStart = System.currentTimeMillis();
                    disconnectSignalled.wait(remWait);
                    long waitEnd = System.currentTimeMillis();

                    // Handle spurious wake-up
                    if (waitEnd > waitStart) {
                        remWait -= (waitEnd - waitStart);
                    } else {
                        remWait -= 125L;
                    }
                }
            }

            assertTrue("Disconnect signalled", disconnectSignalled.get());
        } finally {
            client.stop();
        }
    }

    @Test
    @Ignore("TODO implement KEX-INIT re-send by server")
    public void testStrictKexIgnoredByClientIfNotFirstKexInit() throws Exception {
        testStrictKexIgnoredByPeerIfNotFirstKexInit(false);
    }

    @Test
    public void testStrictKexIgnoredByServerIfNotFirstKexInit() throws Exception {
        testStrictKexIgnoredByPeerIfNotFirstKexInit(true);
    }

    private void testStrictKexIgnoredByPeerIfNotFirstKexInit(boolean clientInitiates) throws Exception {
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionEvent(Session session, Event event) {
                if (event == Event.KeyEstablished) {
                    handleKeyEstablishedEvent(session, clientInitiates);
                }
            }

            private SessionKexDetails handleKeyEstablishedEvent(Session session, boolean clientInitiates) {
                SessionKexDetails details = session.getSessionKexDetails();
                int newKeysSentCount = details.getNewKeysSentCount();
                int newKeysRcvdCount = details.getNewKeysReceivedCount();
                boolean serverSession = session.isServerSession();
                String sessionType = serverSession ? "SERVER" : "CLIENT";
                // Restore the usage of strict keys
                CoreModuleProperties.USE_STRICT_KEX.set(session, true);

                if ((newKeysSentCount <= 1) && (newKeysRcvdCount <= 1)) {
                    assertFalse(sessionType + ": strict KEX unexpectedly enabled", details.isStrictKexEnabled());
                } else {
                    assertTrue(sessionType + ": strict KEX not enabled", details.isStrictKexEnabled());
                }

                assertFalse(sessionType + ": strict KEX unexpectedly signalled", details.isStrictKexSignalled());
                return details;
            }
        };

        CoreModuleProperties.USE_STRICT_KEX.set(sshd, false);
        CoreModuleProperties.USE_STRICT_KEX.set(client, false);

        try (ClientSession session = obtainInitialTestClientSession()) {
            if (clientInitiates) {
                triggerSessionRekey(session);
            } else {
                fail("TODO implement KEX-INIT re-send by server");
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testRekeyResetsPacketSequenceNumbers() throws Exception {
        sshd.addSessionListener(new SessionListener() {
            private SessionKexDetails beforeDetails;
            private SessionCountersDetails beforeCounters;

            @Override
            public void sessionNegotiationEnd(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                SessionKexDetails details = session.getSessionKexDetails();
                assertTrue("StrictKexSignalled[server]", details.isStrictKexSignalled());

                SessionCountersDetails counters = session.getSessionCountersDetails();
                if (beforeDetails == null) {
                    beforeDetails = details;
                }
                if (beforeCounters == null) {
                    beforeCounters = counters;
                }

                if ((details.getNewKeysSentCount() > 1) && (details.getNewKeysReceivedCount() > 1)) {
                    assertSessionSequenceNumbersReset(session, beforeDetails, beforeCounters);
                }
            }
        });
        sshd.setCommandFactory(new TestEchoCommandFactory());

        TestEchoCommand.latch = new CountDownLatch(1);
        try (ClientSession session = obtainInitialTestClientSession()) {
            SessionKexDetails beforeDetails = session.getSessionKexDetails();
            assertTrue("StrictKexSignalled[client]", beforeDetails.isStrictKexSignalled());

            /*
             * Create some traffic in order to "inflate" the sequence numbers
             * enough so that when we re-key and (we assume) the sequence number
             * are reset they will not have increased to the same values due to
             * the NEWKEY exchange.
             */
            String response = session.executeRemoteCommand(getCurrentTestName());
            assertNotNull("No shell echo response", response);

            boolean shellFinished = TestEchoCommand.latch.await(AUTH_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            assertTrue("Shell finished", shellFinished);

            SessionCountersDetails beforeCounters = session.getSessionCountersDetails();
            triggerSessionRekey(session);

            assertSessionSequenceNumbersReset(session, beforeDetails, beforeCounters);
        } finally {
            client.stop();
        }
    }

    private static void triggerSessionRekey(Session session) throws IOException {
        KeyExchangeFuture rekeyFuture = session.reExchangeKeys();
        boolean exchanged = rekeyFuture.verify(AUTH_TIMEOUT).isDone();
        assertTrue("Rekey exchange completed", exchanged);
    }

    // NOTE: we use failWithWrittenErrorMessage in order to compensate for
    // session timeout in case of a debug breakpoint
    static void assertSessionSequenceNumbersReset(
            Session session, SessionKexDetails beforeDetails,
            SessionCountersDetails beforeCounters) {
        long incomingPacketSequenceNumberBefore = beforeCounters.getInputPacketSequenceNumber();
        long outputPacketSequenceNumberBefore = beforeCounters.getOutputPacketSequenceNumber();

        SessionCountersDetails afterCounters = session.getSessionCountersDetails();
        long incomingPacketSequenceNumberAfter = afterCounters.getInputPacketSequenceNumber();
        long outputPacketSequenceNumberAfter = afterCounters.getOutputPacketSequenceNumber();

        String sessionType = session.isServerSession() ? "server" : "client";
        if (incomingPacketSequenceNumberAfter > incomingPacketSequenceNumberBefore) {
            failWithWrittenErrorMessage(sessionType + ": Incoming packet sequence number not reset: before="
                                        + incomingPacketSequenceNumberBefore + ", after=" + incomingPacketSequenceNumberAfter);
        }

        if (outputPacketSequenceNumberAfter > outputPacketSequenceNumberBefore) {
            failWithWrittenErrorMessage(sessionType + ": Outgoing packet sequence number not reset: before="
                                        + incomingPacketSequenceNumberBefore + ", after=" + incomingPacketSequenceNumberAfter);
        }

        SessionKexDetails afterDetails = session.getSessionKexDetails();
        int beforeSentNewKeys = beforeDetails.getNewKeysSentCount();
        int afterSentNewKeys = afterDetails.getNewKeysSentCount();
        if (beforeSentNewKeys >= afterSentNewKeys) {
            failWithWrittenErrorMessage(sessionType + ": sent NEWKEY count not updated: before=" + beforeSentNewKeys
                                        + ", after=" + afterSentNewKeys);
        }

        int beforeRcvdNewKeys = beforeDetails.getNewKeysReceivedCount();
        int afterRcvdNewKeys = afterDetails.getNewKeysReceivedCount();
        if (beforeRcvdNewKeys >= afterRcvdNewKeys) {
            failWithWrittenErrorMessage(sessionType + ": received NEWKEY count not updated: before=" + beforeRcvdNewKeys
                                        + ", after=" + afterRcvdNewKeys);
        }
    }

    @Test
    public void testStrictKexNotActivatedIfClientDoesNotSupportIt() throws Exception {
        testStrictKexNotActivatedIfNotSupportByPeer(false);
    }

    @Test
    public void testStrictKexNotActivatedIfServerDoesNotSupportIt() throws Exception {
        testStrictKexNotActivatedIfNotSupportByPeer(true);
    }

    private void testStrictKexNotActivatedIfNotSupportByPeer(boolean clientSupported) throws Exception {
        if (clientSupported) {
            CoreModuleProperties.USE_STRICT_KEX.set(sshd, false);
        } else {
            CoreModuleProperties.USE_STRICT_KEX.set(client, false);
        }

        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionNegotiationEnd(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                SessionKexDetails details = session.getSessionKexDetails();
                assertEquals("StrictKexEnabled[server]", !clientSupported, details.isStrictKexEnabled());
                assertFalse("StrictKexSignalled[server]", details.isStrictKexSignalled());
            }
        });

        try (ClientSession session = obtainInitialTestClientSession()) {
            SessionKexDetails details = session.getSessionKexDetails();
            assertEquals("StrictKexEnabled[client]", clientSupported, details.isStrictKexEnabled());
            assertFalse("StrictKexSignalled[client]", details.isStrictKexSignalled());
        } finally {
            client.stop();
        }
    }

    private ClientSession obtainInitialTestClientSession() throws IOException {
        sshd.start();
        int port = sshd.getPort();

        client.start();
        return createTestClientSession(port);
    }

    private ClientSession createTestClientSession(int port) throws IOException {
        ClientSession session = createTestClientSession(TEST_LOCALHOST, port);
        try {
            InetSocketAddress addr = SshdSocketAddress.toInetSocketAddress(session.getConnectAddress());
            assertEquals("Mismatched connect host", TEST_LOCALHOST, addr.getHostString());

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    private ClientSession createTestClientSession(String host, int port) throws IOException {
        ClientSession session = client.connect(getCurrentTestName(), host, port).verify(CONNECT_TIMEOUT).getSession();
        try {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            InetSocketAddress addr = SshdSocketAddress.toInetSocketAddress(session.getConnectAddress());
            assertNotNull("No reported connect address", addr);
            assertEquals("Mismatched connect port", port, addr.getPort());

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////

    public static class TestEchoCommandFactory extends EchoCommandFactory {
        public TestEchoCommandFactory() {
            super();
        }

        @Override
        public Command createCommand(ChannelSession channel, String command) throws IOException {
            return new TestEchoCommand(command);
        }
    }

    public static class TestEchoCommand extends EchoCommand {
        // CHECKSTYLE:OFF
        public static CountDownLatch latch;
        // CHECKSTYLE:ON

        public TestEchoCommand(String command) {
            super(command);
        }

        @Override
        public void destroy(ChannelSession channel) throws Exception {
            if (latch != null) {
                latch.countDown();
            }
            super.destroy(channel);
        }
    }
}
