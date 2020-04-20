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

package org.apache.sshd.common.session;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.session.helpers.ReservedSessionMessagesHandlerAdapter;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
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
public class ReservedSessionMessagesHandlerTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    public ReservedSessionMessagesHandlerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();

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
    public void testClientToServer() throws Exception {
        AccumulatingHandler handler = new AccumulatingHandler();
        sshd.setReservedSessionMessagesHandler(handler);

        client.start();
        try (ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            testReservedSessionMessagesHandler(session, handler);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testServerToClient() throws Exception {
        final AccumulatingHandler handler = new AccumulatingHandler();
        client.setReservedSessionMessagesHandler(handler);

        final ExecutorService service = ThreadUtils.newSingleThreadExecutor(getCurrentTestName());
        try {
            final Semaphore signal = new Semaphore(0);
            sshd.addSessionListener(new SessionListener() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void sessionEvent(final Session session, Event event) {
                    if (Event.Authenticated.equals(event)) {
                        service.execute(() -> {
                            try {
                                testReservedSessionMessagesHandler(session, handler);
                                outputDebugMessage("Release test signal for %s", session);
                                signal.release();
                            } catch (Throwable t) {
                                outputDebugMessage("Failed (%s) to run test: %s", t.getClass().getSimpleName(), t.getMessage());
                                session.exceptionCaught(t);
                            }
                        });
                    }
                }
            });

            client.start();
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue("Failed to complete test on time", signal.tryAcquire(31L, TimeUnit.SECONDS));
            } finally {
                client.stop();
            }
        } finally {
            if (!service.isShutdown()) {
                service.shutdownNow();
            }
        }
    }

    private void testReservedSessionMessagesHandler(Session session, AccumulatingHandler handler) throws Exception {
        testIgnoredMessages(session, handler);
        testDebugMessages(session, handler);
    }

    private void testIgnoredMessages(Session session, AccumulatingHandler handler) throws Exception {
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE)
                .append(getClass().getName()).append('#').append(getCurrentTestName()).append("-ignored-");
        int sbLen = sb.length();
        List<String> expected = new ArrayList<>();
        for (int index = 1; index <= Byte.SIZE; index++) {
            sb.setLength(sbLen);
            sb.append(index);

            String data = sb.toString();
            expected.add(data);
            session.sendIgnoreMessage(data.getBytes(StandardCharsets.UTF_8));
        }

        assertTrue("Failed to accumulate ignored messages on time",
                handler.waitForIgnoreCount(expected.size(), TimeUnit.SECONDS, expected.size() * 2));

        List<byte[]> actual = handler.getIgnoredMessages();
        assertEquals("Mismatched size of ignored messages", expected.size(), actual.size());

        for (int index = 0; index < actual.size(); index++) {
            String expValue = expected.get(index);
            String actValue = new String(actual.get(index), StandardCharsets.UTF_8);
            assertEquals("Mismatched ignored message payload at index=" + index, expValue, actValue);
        }
    }

    private void testDebugMessages(Session session, AccumulatingHandler handler) throws Exception {
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE)
                .append(getClass().getName()).append('#').append(getCurrentTestName()).append("-debug-");
        int sbLen = sb.length();
        List<Map.Entry<String, Boolean>> expected = new ArrayList<>();
        for (int index = 1; index <= Byte.SIZE; index++) {
            sb.setLength(sbLen);
            sb.append(index);

            Map.Entry<String, Boolean> entry = new SimpleImmutableEntry<>(sb.toString(), (index & 0x01) == 0);
            expected.add(entry);
            session.sendDebugMessage(entry.getValue(), entry.getKey(), null);
        }

        assertTrue("Failed to accumulate debug messages on time",
                handler.waitForDebugCount(expected.size(), TimeUnit.SECONDS, expected.size() * 2));

        List<? extends Map.Entry<String, Boolean>> actual = handler.getDebugMessages();
        assertEquals("Mismatched size of debug messages", expected.size(), actual.size());

        for (int index = 0; index < actual.size(); index++) {
            Map.Entry<String, Boolean> expEntry = expected.get(index);
            Map.Entry<String, Boolean> actEntry = actual.get(index);
            assertEquals("Mismatched debug entry at index " + index, expEntry, actEntry);
        }
    }

    public static class AccumulatingHandler extends ReservedSessionMessagesHandlerAdapter {
        private final Semaphore ignoredSignal = new Semaphore(0);
        private final List<byte[]> ignoredMessages = new ArrayList<>();
        private final Semaphore debugSignal = new Semaphore(0);
        private final List<SimpleImmutableEntry<String, Boolean>> debugMessages = new ArrayList<>();

        public AccumulatingHandler() {
            super();
        }

        public List<byte[]> getIgnoredMessages() {
            return ignoredMessages;
        }

        public boolean waitForIgnoreCount(int count, TimeUnit unit, long duration) throws InterruptedException {
            return ignoredSignal.tryAcquire(count, duration, unit);
        }

        @Override
        public void handleIgnoreMessage(Session session, byte[] data, Buffer buffer) throws Exception {
            ignoredMessages.add(data.clone());
            super.handleIgnoreMessage(session, data, buffer);
            ignoredSignal.release();
        }

        public List<SimpleImmutableEntry<String, Boolean>> getDebugMessages() {
            return debugMessages;
        }

        public boolean waitForDebugCount(int count, TimeUnit unit, long duration) throws InterruptedException {
            return debugSignal.tryAcquire(count, duration, unit);
        }

        @Override
        public void handleDebugMessage(Session session, boolean display, String msg, String lang, Buffer buffer)
                throws Exception {
            debugMessages.add(new SimpleImmutableEntry<>(msg, display));
            super.handleDebugMessage(session, display, msg, lang, buffer);
            debugSignal.release();
        }
    }
}
