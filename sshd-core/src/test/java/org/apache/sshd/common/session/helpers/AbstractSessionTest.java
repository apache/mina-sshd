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
package org.apache.sshd.common.session.helpers;

import java.io.EOFException;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.io.WriteAbortedException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.IoWriteFutureImpl;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * Test basic stuff on AbstractSession.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class AbstractSessionTest extends BaseTestSupport {
    private MySession session;

    public AbstractSessionTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        session = new MySession();
    }

    @After
    public void tearDown() throws Exception {
        if (session != null) {
            session.close();
        }
    }

    @Test
    public void testReadIdentSimple() throws Exception {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithoutCR() throws Exception {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithHeaders() throws Exception {
        Buffer buf = new ByteArrayBuffer("a header line\r\nSSH-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithSplitPackets() throws Exception {
        Buffer buf = new ByteArrayBuffer("header line\r\nSSH".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertNull("Unexpected identification for header only", ident);

        buf.putRawBytes("-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test(expected = StreamCorruptedException.class)
    public void testReadIdentBadLineEnding() throws Exception {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\ra".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = StreamCorruptedException.class)
    public void testReadIdentLongLine() throws Exception {
        StringBuilder sb = new StringBuilder(SessionContext.MAX_VERSION_LINE_LENGTH + Integer.SIZE);
        sb.append("SSH-2.0-software");
        do {
            sb.append("01234567890123456789012345678901234567890123456789");
        } while (sb.length() < SessionContext.MAX_VERSION_LINE_LENGTH);

        Buffer buf = new ByteArrayBuffer(sb.toString().getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = StreamCorruptedException.class)
    public void testReadIdentWithNullChar() throws Exception {
        String id = "SSH-2.0" + '\0' + "-software\r\n";
        Buffer buf = new ByteArrayBuffer(id.getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = StreamCorruptedException.class)
    public void testReadIdentLongHeader() throws Exception {
        int maxIdentSize = CoreModuleProperties.MAX_IDENTIFICATION_SIZE.getRequiredDefault();
        StringBuilder sb = new StringBuilder(maxIdentSize + Integer.SIZE);
        do {
            sb.append("01234567890123456789012345678901234567890123456789\r\n");
        } while (sb.length() < maxIdentSize);
        sb.append("SSH-2.0-software\r\n");

        Buffer buf = new ByteArrayBuffer(sb.toString().getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test // see SSHD-619
    public void testMsgIgnorePadding() throws Exception {
        final long frequency = Byte.SIZE;
        CoreModuleProperties.IGNORE_MESSAGE_SIZE.set(session, Short.SIZE);
        CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.set(session, frequency);
        CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.set(session, 0);
        session.refreshConfiguration();

        Buffer msg = session.createBuffer(SshConstants.SSH_MSG_DEBUG, Long.SIZE);
        msg.putBoolean(true); // display ?
        msg.putString(getCurrentTestName()); // message
        msg.putString(""); // language

        MyIoSession ioSession = (MyIoSession) session.getIoSession();
        Queue<Buffer> queue = ioSession.getOutgoingMessages();
        int numIgnores = 0;
        for (int cycle = 0; cycle < Byte.SIZE; cycle++) {
            for (long index = 0; index <= frequency; index++) {
                session.writePacket(msg);

                Buffer data = queue.remove();
                if (data != msg) {
                    int cmd = data.getUByte();
                    assertEquals("Mismatched buffer command at cycle " + cycle + "[" + index + "]", SshConstants.SSH_MSG_IGNORE,
                            cmd);

                    int len = data.getInt();
                    assertTrue("Mismatched random padding data length at cycle " + cycle + "[" + index + "]: " + len,
                            len >= Short.SIZE);
                    numIgnores++;
                }
            }
        }

        assertEquals("Mismatched number of ignore messages", Byte.SIZE, numIgnores);
    }

    @Test // see SSHD-652
    public void testCloseFutureListenerRegistration() throws Exception {
        AtomicInteger closeCount = new AtomicInteger();
        session.addCloseFutureListener(future -> {
            assertTrue("Future not marked as closed", future.isClosed());
            assertEquals("Unexpected multiple call to callback", 1, closeCount.incrementAndGet());
        });
        session.close();
        assertEquals("Close listener not called", 1, closeCount.get());
    }

    @Test // see SSHD-699
    public void testMalformedUnimplementedMessage() throws Exception {
        session.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
            @Override
            public boolean handleUnimplementedMessage(Session session, int cmd, Buffer buffer) throws Exception {
                fail("Unexpected invocation: available=" + buffer.available());
                return false;
            }
        });

        Buffer buffer = new ByteArrayBuffer(Long.SIZE);
        for (int index = 0; index < (Integer.BYTES - 1); index++) {
            buffer.putByte((byte) index);
            session.handleUnimplemented(buffer);
        }
    }

    @Test // see SSHD-699
    public void testMalformedIgnoreMessageBadLength() throws Exception {
        session.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
            @Override
            public void handleIgnoreMessage(Session session, Buffer buffer) throws Exception {
                fail("Unexpected invocation: available=" + buffer.available());
            }
        });

        Buffer buffer = new ByteArrayBuffer(Long.SIZE);
        for (int index = 0; index < (Integer.BYTES - 1); index++) {
            buffer.putByte((byte) index);
            session.handleIgnore(buffer);
        }
    }

    @Test // see SSHD-699
    public void testMalformedIgnoreMessageCorruptedData() throws Exception {
        session.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
            @Override
            public void handleIgnoreMessage(Session session, Buffer buffer) throws Exception {
                fail("Unexpected invocation: available=" + buffer.available());
            }
        });

        Buffer buffer = new ByteArrayBuffer(Long.SIZE + Byte.MAX_VALUE);
        buffer.putInt(Byte.MAX_VALUE + 1); // bad message length
        for (int index = 0; index < Byte.MAX_VALUE; index++) {
            buffer.putByte((byte) index);
            session.handleIgnore(buffer);
        }
    }

    @Test
    public void testMalformedDebugMessageContent() throws Exception {
        session.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
            @Override
            public void handleDebugMessage(Session session, Buffer buffer) throws Exception {
                fail("Unexpected invocation: available=" + buffer.available());
            }
        });

        Buffer buffer = new ByteArrayBuffer(Long.SIZE + Byte.MAX_VALUE);
        session.handleDebug(buffer); // no boolean field

        buffer.putBoolean(true);
        session.handleDebug(buffer); // no message field

        buffer.putInt(Byte.MAX_VALUE + 1); // bad message field length
        for (int index = 0; index < Byte.MAX_VALUE; index++) {
            buffer.putByte((byte) index);
            session.handleDebug(buffer);
        }
    }

    @Test
    public void testMalformedDebugMessageLanguage() throws Exception {
        session.setReservedSessionMessagesHandler(new ReservedSessionMessagesHandler() {
            @Override
            public void handleDebugMessage(Session session, Buffer buffer) throws Exception {
                fail("Unexpected invocation: available=" + buffer.available());
            }
        });

        Buffer buffer = new ByteArrayBuffer(Long.SIZE);
        buffer.putBoolean(true);
        buffer.putString(getCurrentTestName());
        session.handleDebug(buffer); // no language tag

        buffer.putInt(Byte.SIZE + 1); // bad language tag length
        for (int index = 0; index < Byte.SIZE; index++) {
            buffer.putByte((byte) index);
            session.handleDebug(buffer);
        }
    }

    private static String readIdentification(MySession session, Buffer buf) throws Exception {
        List<String> lines = session.doReadIdentification(buf);
        return GenericUtils.isEmpty(lines) ? null : lines.get(lines.size() - 1);
    }

    public static class MyIoSession implements IoSession {
        private final Queue<Buffer> outgoing = new LinkedBlockingQueue<>();
        private final AtomicBoolean open = new AtomicBoolean(true);
        private final CloseFuture closeFuture;

        public MyIoSession() {
            closeFuture = new DefaultCloseFuture(Test.class.getSimpleName(), open);
        }

        @Override
        public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            closeFuture.addListener(listener);
        }

        @Override
        public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            closeFuture.addListener(listener);
        }

        public Queue<Buffer> getOutgoingMessages() {
            return outgoing;
        }

        @Override
        public boolean isClosed() {
            return !isOpen();
        }

        @Override
        public boolean isClosing() {
            return !isOpen();
        }

        @Override
        public boolean isOpen() {
            return open.get();
        }

        @Override
        public void close() throws IOException {
            close(true);
        }

        @Override
        public long getId() {
            return 0;
        }

        @Override
        public Object getAttribute(Object key) {
            return null;
        }

        @Override
        public Object setAttribute(Object key, Object value) {
            return null;
        }

        @Override
        public Object setAttributeIfAbsent(Object key, Object value) {
            return null;
        }

        @Override
        public Object removeAttribute(Object key) {
            return null;
        }

        @Override
        public SocketAddress getRemoteAddress() {
            return null;
        }

        @Override
        public SocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public SocketAddress getAcceptanceAddress() {
            return null;
        }

        @Override
        public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
            if (!isOpen()) {
                throw new EOFException("Not open");
            }
            if (!outgoing.offer(buffer)) {
                throw new WriteAbortedException("Failed to offer outgoing buffer", new IllegalStateException("Offer failure"));
            }

            IoWriteFutureImpl future = new IoWriteFutureImpl(Test.class.getSimpleName(), buffer);
            future.setValue(Boolean.TRUE);
            return future;
        }

        @Override
        public CloseFuture close(boolean immediately) {
            if (open.getAndSet(false)) {
                outgoing.clear();
                closeFuture.setClosed();
            }

            return closeFuture;
        }

        @Override
        public IoService getService() {
            return null;
        }

        @Override
        public void shutdownOutputStream() {
            // do nothing
        }
    }

    public static class MySession extends AbstractSession {
        public MySession() {
            super(true, org.apache.sshd.util.test.CoreTestSupportUtils.setupTestServer(AbstractSessionTest.class),
                  new MyIoSession());
        }

        @Override
        protected void handleMessage(Buffer buffer) throws Exception {
            // ignored
        }

        @Override
        protected boolean readIdentification(Buffer buffer) {
            return false;
        }

        public List<String> doReadIdentification(Buffer buffer) throws Exception {
            return super.doReadIdentification(buffer, false);
        }

        @Override
        protected Buffer encode(Buffer buffer) throws IOException {
            return buffer;
        }

        @Override
        protected byte[] sendKexInit() throws IOException {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        @Override
        protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
            // ignored
        }

        @Override
        protected void setKexSeed(byte... seed) {
            // ignored
        }

        @Override
        protected String resolveAvailableSignaturesProposal(FactoryManager manager) {
            return null;
        }

        @Override
        protected void checkKeys() {
            // ignored
        }

        @Override
        public void startService(String name, Buffer buffer) throws Exception {
            // ignored
        }

        @Override
        public Instant resetIdleTimeout() {
            return null; // ignored
        }

        @Override
        public Instant resetAuthTimeout() {
            return null; // ignored
        }

        @Override
        protected ConnectionService getConnectionService() {
            return null;
        }
    }
}
