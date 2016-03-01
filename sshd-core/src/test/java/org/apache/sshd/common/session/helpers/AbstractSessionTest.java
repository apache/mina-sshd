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

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.IoWriteFutureImpl;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Test basic stuff on AbstractSession.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AbstractSessionTest extends BaseTestSupport {

    private MySession session;

    public AbstractSessionTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        session = new MySession();
    }

    public void tearDown() throws Exception {
        if (session != null) {
            session.close();
        }
    }

    @Test
    public void testReadIdentSimple() {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithoutCR() {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithHeaders() {
        Buffer buf = new ByteArrayBuffer("a header line\r\nSSH-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test
    public void testReadIdentWithSplitPackets() {
        Buffer buf = new ByteArrayBuffer("header line\r\nSSH".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        assertNull("Unexpected identification for header only", ident);
        buf.putRawBytes("-2.0-software\r\n".getBytes(StandardCharsets.UTF_8));
        ident = readIdentification(session, buf);
        assertEquals("SSH-2.0-software", ident);
    }

    @Test(expected = IllegalStateException.class)
    public void testReadIdentBadLineEnding() {
        Buffer buf = new ByteArrayBuffer("SSH-2.0-software\ra".getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = IllegalStateException.class)
    public void testReadIdentLongLine() {
        StringBuilder sb = new StringBuilder(Session.MAX_VERSION_LINE_LENGTH + Integer.SIZE);
        sb.append("SSH-2.0-software");
        do {
            sb.append("01234567890123456789012345678901234567890123456789");
        } while (sb.length() < Session.MAX_VERSION_LINE_LENGTH);

        Buffer buf = new ByteArrayBuffer(sb.toString().getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = IllegalStateException.class)
    public void testReadIdentWithNullChar() {
        StringBuilder sb = new StringBuilder(Session.MAX_VERSION_LINE_LENGTH + Integer.SIZE);
        sb.append("SSH-2.0").append('\0').append("-software\r\n");
        Buffer buf = new ByteArrayBuffer(sb.toString().getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test(expected = IllegalStateException.class)
    public void testReadIdentLongHeader() {
        StringBuilder sb = new StringBuilder(FactoryManager.DEFAULT_MAX_IDENTIFICATION_SIZE + Integer.SIZE);
        do {
            sb.append("01234567890123456789012345678901234567890123456789\r\n");
        } while (sb.length() < FactoryManager.DEFAULT_MAX_IDENTIFICATION_SIZE);
        sb.append("SSH-2.0-software\r\n");

        Buffer buf = new ByteArrayBuffer(sb.toString().getBytes(StandardCharsets.UTF_8));
        String ident = readIdentification(session, buf);
        fail("Unexpected success: " + ident);
    }

    @Test   // see SSHD-619
    public void testMsgIgnorePadding() throws Exception {
        final long frequency = Byte.SIZE;
        PropertyResolverUtils.updateProperty(session, FactoryManager.IGNORE_MESSAGE_SIZE, Short.SIZE);
        PropertyResolverUtils.updateProperty(session, FactoryManager.IGNORE_MESSAGE_FREQUENCY, frequency);
        PropertyResolverUtils.updateProperty(session, FactoryManager.IGNORE_MESSAGE_VARIANCE, 0);
        session.refreshConfiguration();

        Buffer msg = session.createBuffer(SshConstants.SSH_MSG_DEBUG, Long.SIZE);
        msg.putBoolean(true);   // display ?
        msg.putString(getCurrentTestName());    // message
        msg.putString("");  // language

        MyIoSession ioSession = (MyIoSession) session.getIoSession();
        Queue<Buffer> queue = ioSession.getOutgoingMessages();
        int numIgnores = 0;
        for (int cycle = 0; cycle < Byte.SIZE; cycle++) {
            for (long index = 0; index <= frequency; index++) {
                session.writePacket(msg);

                Buffer data = queue.remove();
                if (data != msg) {
                    int cmd = data.getUByte();
                    assertEquals("Mismatched buffer command at cycle " + cycle + "[" + index + "]", SshConstants.SSH_MSG_IGNORE, cmd);

                    int len = data.getInt();
                    assertTrue("Mismatched random padding data length at cycle " + cycle + "[" + index + "]: " + len, len >= Short.SIZE);
                    numIgnores++;
                }
            }
        }

        assertEquals("Mismatched number of ignore messages", Byte.SIZE, numIgnores);
    }

    @Test   // see SSHD-652
    public void testCloseFutureListenerRegistration() throws Exception {
        final AtomicInteger closeCount = new AtomicInteger();
        session.addCloseFutureListener(new SshFutureListener<CloseFuture>() {
            @Override
            public void operationComplete(CloseFuture future) {
                assertTrue("Future not marted as closed", future.isClosed());
                assertEquals("Unexpected multiple call to callback", 1, closeCount.incrementAndGet());
            }
        });
        session.close();
        assertEquals("Close listener not called", 1, closeCount.get());
    }

    private static String readIdentification(MySession session, Buffer buf) {
        List<String> lines = session.doReadIdentification(buf);
        return GenericUtils.isEmpty(lines) ? null : lines.get(lines.size() - 1);
    }

    public static class MyIoSession implements IoSession {
        private final Queue<Buffer> outgoing = new LinkedBlockingQueue<>();
        private final AtomicBoolean open = new AtomicBoolean(true);
        private final CloseFuture closeFuture;

        public MyIoSession() {
            closeFuture = new DefaultCloseFuture(open);
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
        public SocketAddress getRemoteAddress() {
            return null;
        }

        @Override
        public SocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public IoWriteFuture write(Buffer buffer) {
            if (!isOpen()) {
                throw new IllegalStateException("Not open");
            }
            if (!outgoing.offer(buffer)) {
                throw new IllegalStateException("Failed to offer outgoing buffer");
            }

            IoWriteFutureImpl future = new IoWriteFutureImpl(buffer);
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
    }

    public static class MySession extends AbstractSession {
        public MySession() {
            super(true, org.apache.sshd.util.test.Utils.setupTestServer(AbstractSessionTest.class), new MyIoSession());
        }

        @Override
        protected void handleMessage(Buffer buffer) throws Exception {
            // ignored
        }

        @Override
        protected boolean readIdentification(Buffer buffer) {
            return false;
        }

        public List<String> doReadIdentification(Buffer buffer) {
            return super.doReadIdentification(buffer, false);
        }

        @Override
        protected void encode(Buffer buffer) throws IOException {
            // ignored
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
        public void startService(String name) throws Exception {
            // ignored
        }

        @Override
        public void resetIdleTimeout() {
            // ignored
        }
    }
}
