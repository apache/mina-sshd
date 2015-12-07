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
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.io.NullOutputStream;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.OutputCountTrackingOutputStream;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.apache.sshd.util.test.TeeOutputStream;
import org.junit.After;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.jcraft.jsch.JSch;

/**
 * Test key exchange algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyReExchangeTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    public KeyReExchangeTest() {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    protected void setUp(long bytesLimit, long timeLimit, long packetsLimit) throws Exception {
        sshd = setupTestServer();
        if (bytesLimit > 0L) {
            PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.REKEY_BYTES_LIMIT, bytesLimit);
        }
        if (timeLimit > 0L) {
            PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.REKEY_TIME_LIMIT, timeLimit);
        }
        if (packetsLimit > 0L) {
            PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.REKEY_PACKETS_LIMIT, packetsLimit);
        }

        sshd.start();
        port = sshd.getPort();
    }

    @Test
    public void testSwitchToNoneCipher() throws Exception {
        setUp(0L, 0L, 0L);

        sshd.getCipherFactories().add(BuiltinCiphers.none);
        try (SshClient client = setupTestClient()) {
            client.getCipherFactories().add(BuiltinCiphers.none);
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                KeyExchangeFuture switchFuture = session.switchToNoneCipher();
                switchFuture.verify(5L, TimeUnit.SECONDS);
                try (ClientChannel channel = session.createSubsystemChannel(SftpConstants.SFTP_SUBSYSTEM_NAME)) {
                    channel.open().verify(5L, TimeUnit.SECONDS);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-558
    public void testKexFutureExceptionPropagation() throws Exception {
        setUp(0L, 0L, 0L);
        sshd.getCipherFactories().add(BuiltinCiphers.none);

        try (SshClient client = setupTestClient()) {
            client.getCipherFactories().add(BuiltinCiphers.none);
            // replace the original KEX factories with wrapped ones that we can fail intentionally
            List<NamedFactory<KeyExchange>> kexFactories = new ArrayList<>();
            final AtomicBoolean successfulInit = new AtomicBoolean(true);
            final AtomicBoolean successfulNext = new AtomicBoolean(true);
            final ClassLoader loader = getClass().getClassLoader();
            final Class<?>[] interfaces = { KeyExchange.class };
            for (final NamedFactory<KeyExchange> factory : client.getKeyExchangeFactories()) {
                kexFactories.add(new NamedFactory<KeyExchange>() {
                    @Override
                    public String getName() {
                        return factory.getName();
                    }

                    @Override
                    public KeyExchange create() {
                        final KeyExchange proxiedInstance = factory.create();
                        return (KeyExchange) Proxy.newProxyInstance(loader, interfaces, new InvocationHandler() {
                            @Override
                            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                                String name = method.getName();
                                if ("init".equals(name) && (!successfulInit.get())) {
                                    throw new UnsupportedOperationException("Intentionally failing 'init'");
                                } else if ("next".equals(name) && (!successfulNext.get())) {
                                    throw new UnsupportedOperationException("Intentionally failing 'next'");
                                } else {
                                    return method.invoke(proxiedInstance, args);
                                }
                            }
                        });
                    }
                });
            }
            client.setKeyExchangeFactories(kexFactories);
            client.start();

            try {
                try {
                    testKexFutureExceptionPropagation("init", successfulInit, client);
                } finally {
                    successfulInit.set(true);
                }

                try {
                    testKexFutureExceptionPropagation("next", successfulNext, client);
                } finally {
                    successfulNext.set(true);
                }
            } finally {
                client.stop();
            }
        }
    }

    private void testKexFutureExceptionPropagation(String failureType, AtomicBoolean successFlag, SshClient client) throws Exception {
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            successFlag.set(false);
            KeyExchangeFuture kexFuture = session.switchToNoneCipher();
            assertTrue(failureType + ": failed to complete KEX on time", kexFuture.await(7L, TimeUnit.SECONDS));
            assertNotNull(failureType + ": unexpected success", kexFuture.getException());
        }
    }

    @Test
    public void testReExchangeFromJschClient() throws Exception {
        Assume.assumeTrue("DH Group Exchange not supported", SecurityUtils.isDHGroupExchangeSupported());
        setUp(0L, 0L, 0L);

        JSch.setConfig("kex", BuiltinDHFactories.Constants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1);
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
        try {
            s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
            s.connect();

            com.jcraft.jsch.Channel c = s.openChannel("shell");
            c.connect();
            try (OutputStream os = c.getOutputStream();
                 InputStream is = c.getInputStream()) {

                String expected = "this is my command\n";
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                byte[] data = new byte[bytes.length + Long.SIZE];
                for (int i = 1; i <= 10; i++) {
                    os.write(bytes);
                    os.flush();

                    int len = is.read(data);
                    String str = new String(data, 0, len);
                    assertEquals("Mismatched data at iteration " + i, expected, str);
                    s.rekey();
                }
            } finally {
                c.disconnect();
            }
        } finally {
            s.disconnect();
        }
    }

    @Test
    public void testReExchangeFromSshdClient() throws Exception {
        setUp(0L, 0L, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     ByteArrayOutputStream sent = new ByteArrayOutputStream();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn);
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     ByteArrayOutputStream out = new ByteArrayOutputStream();
                     ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
                    for (int i = 0; i < 10; i++) {
                        sb.append("0123456789");
                    }
                    sb.append('\n');

                    byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
                    for (int i = 1; i <= 10; i++) {
                        teeOut.write(data);
                        teeOut.flush();

                        KeyExchangeFuture kexFuture = session.reExchangeKeys();
                        assertTrue("Failed to complete KEX on time at iteration " + i, kexFuture.await(5L, TimeUnit.SECONDS));
                        assertNull("KEX exception signalled at iteration " + i, kexFuture.getException());
                    }
                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannel.ClientChannelEvent> result =
                            channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));
                    assertArrayEquals("Mismatched sent data content", sent.toByteArray(), out.toByteArray());
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testReExchangeFromServerBySize() throws Exception {
        final long LIMIT = 10 * 1024L;
        setUp(LIMIT, 0L, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     OutputStream err = new NullOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn)) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder(101 * 10);
                    for (int i = 0; i < 100; i++) {
                        sb.append("0123456789");
                    }
                    sb.append('\n');

                    final AtomicInteger exchanges = new AtomicInteger();
                    session.addSessionListener(new SessionListener() {
                        @Override
                        public void sessionCreated(Session session) {
                            // ignored
                        }

                        @Override
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }

                        @Override
                        public void sessionClosed(Session session) {
                            // ignored
                        }
                    });

                    byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
                    for (long sentSize = 0L; sentSize < (LIMIT + Byte.MAX_VALUE + data.length); sentSize += data.length) {
                        teeOut.write(data);
                        teeOut.flush();
                        // no need to wait until the limit is reached if a re-key occurred
                        if (exchanges.get() > 0) {
                            outputDebugMessage("Stop sending after %d bytes - exchanges=%s", sentSize + data.length, exchanges);
                            break;
                        }
                    }

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannel.ClientChannelEvent> result =
                            channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

                byte[] sentData = sent.toByteArray();
                byte[] outData = out.toByteArray();
                assertEquals("Mismatched sent data length", sentData.length, outData.length);
                assertArrayEquals("Mismatched sent data content", sentData, outData);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testReExchangeFromServerByTime() throws Exception {
        final long TIME = TimeUnit.SECONDS.toMillis(2L);
        setUp(0L, TIME, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     OutputStream err = new NullOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn)) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder(101 * 10);
                    for (int i = 0; i < 100; i++) {
                        sb.append("0123456789");
                    }
                    sb.append('\n');

                    final AtomicInteger exchanges = new AtomicInteger();
                    session.addSessionListener(new SessionListener() {
                        @Override
                        public void sessionCreated(Session session) {
                            // ignored
                        }

                        @Override
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }

                        @Override
                        public void sessionClosed(Session session) {
                            // ignored
                        }
                    });

                    byte[] data = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
                    final long MAX_WAIT_NANOS = TimeUnit.MILLISECONDS.toNanos(3L * TIME);
                    final long MIN_WAIT = 10L;
                    final long MIN_WAIT_NANOS = TimeUnit.MILLISECONDS.toNanos(MIN_WAIT);
                    for (long timePassed = 0L, sentSize = 0L; timePassed < MAX_WAIT_NANOS; timePassed++) {
                        long nanoStart = System.nanoTime();
                        teeOut.write(data);
                        teeOut.write('\n');
                        teeOut.flush();

                        long nanoEnd = System.nanoTime();
                        long nanoDuration = nanoEnd - nanoStart;

                        timePassed += nanoDuration;
                        sentSize += data.length + 1;

                        // no need to wait until the timeout expires if a re-key occurred
                        if (exchanges.get() > 0) {
                            outputDebugMessage("Stop sending after %d nanos and size=%d - exchanges=%s",
                                               timePassed, sentSize, exchanges);
                            break;
                        }

                        if ((timePassed < MAX_WAIT_NANOS) && (nanoDuration < MIN_WAIT_NANOS)) {
                            Thread.sleep(MIN_WAIT);
                        }
                    }

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannel.ClientChannelEvent> result =
                            channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

                byte[] sentData = sent.toByteArray();
                byte[] outData = out.toByteArray();
                assertEquals("Mismatched sent data length", sentData.length, outData.length);
                assertArrayEquals("Mismatched sent data content", sentData, outData);
            } finally {
                client.stop();
            }
        }
    }

    @Test   // see SSHD-601
    public void testReExchangeFromServerByPackets() throws Exception {
        final int PACKETS = 135;
        setUp(0L, 0L, PACKETS);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     OutputStream sentTracker = new OutputCountTrackingOutputStream(sent) {
                         @Override
                         protected long updateWriteCount(long delta) {
                             long result = super.updateWriteCount(delta);
                             outputDebugMessage("SENT write count=%d", result);
                             return result;
                         }
                     };
                     OutputStream teeOut = new TeeOutputStream(sentTracker, pipedIn);
                     OutputStream stderr = new NullOutputStream();
                     OutputStream stdout = new OutputCountTrackingOutputStream(out) {
                        @Override
                        protected long updateWriteCount(long delta) {
                            long result = super.updateWriteCount(delta);
                            outputDebugMessage("OUT write count=%d", result);
                            return result;
                        }
                     };
                     InputStream inPipe = new PipedInputStream(pipedIn)) {

                    channel.setIn(inPipe);
                    channel.setOut(stdout);
                    channel.setErr(stderr);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    final AtomicInteger exchanges = new AtomicInteger();
                    session.addSessionListener(new SessionListener() {
                        @Override
                        public void sessionCreated(Session session) {
                            // ignored
                        }

                        @Override
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }

                        @Override
                        public void sessionClosed(Session session) {
                            // ignored
                        }
                    });

                    byte[] data = (getClass().getName() + "#" + getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8);
                    for (int index = 0; index < (PACKETS * 2); index++) {
                        teeOut.write(data);
                        teeOut.flush();

                        // no need to wait until the packets limit is reached if a re-key occurred
                        if (exchanges.get() > 0) {
                            outputDebugMessage("Stop sending after %d packets and %d bytes - exchanges=%s",
                                               (index + 1), (index + 1L) * data.length, exchanges);
                            break;
                        }
                    }

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannel.ClientChannelEvent> result =
                            channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

                byte[] sentData = sent.toByteArray();
                byte[] outData = out.toByteArray();
                assertEquals("Mismatched sent data length", sentData.length, outData.length);
                assertArrayEquals("Mismatched sent data content", sentData, outData);
            } finally {
                client.stop();
            }
        }
    }
}
