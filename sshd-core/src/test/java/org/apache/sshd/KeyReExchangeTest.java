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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.jcraft.jsch.JSch;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ProxyUtils;
import org.apache.sshd.common.util.io.NullOutputStream;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
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

    protected void setUp(long bytesLimit, Duration timeLimit, long packetsLimit) throws Exception {
        sshd = setupTestFullSupportServer();
        sshd.setSubsystemFactories(Collections.singletonList(new TestSubsystemFactory()));
        if (bytesLimit > 0L) {
            CoreModuleProperties.REKEY_BYTES_LIMIT.set(sshd, bytesLimit);
        }
        if (GenericUtils.isPositive(timeLimit)) {
            CoreModuleProperties.REKEY_TIME_LIMIT.set(sshd, timeLimit);
        }
        if (packetsLimit > 0L) {
            CoreModuleProperties.REKEY_PACKETS_LIMIT.set(sshd, packetsLimit);
        }

        sshd.start();
        port = sshd.getPort();
    }

    @Test
    public void testSwitchToNoneCipher() throws Exception {
        setUp(0L, Duration.ZERO, 0L);

        sshd.getCipherFactories().add(BuiltinCiphers.none);
        try (SshClient client = setupTestClient()) {
            client.getCipherFactories().add(BuiltinCiphers.none);
            client.start();

            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                outputDebugMessage("Request switch to none cipher for %s", session);
                KeyExchangeFuture switchFuture = session.switchToNoneCipher();
                switchFuture.verify(DEFAULT_TIMEOUT);
                try (ClientChannel channel = session.createSubsystemChannel(TestSubsystemFactory.NAME)) {
                    channel.open().verify(OPEN_TIMEOUT);
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-558
    public void testKexFutureExceptionPropagation() throws Exception {
        setUp(0L, Duration.ZERO, 0L);
        sshd.getCipherFactories().add(BuiltinCiphers.none);

        try (SshClient client = setupTestClient()) {
            client.getCipherFactories().add(BuiltinCiphers.none);
            // replace the original KEX factories with wrapped ones that we can fail intentionally
            List<KeyExchangeFactory> kexFactories = new ArrayList<>();
            AtomicBoolean successfulInit = new AtomicBoolean(true);
            AtomicBoolean successfulNext = new AtomicBoolean(true);
            ClassLoader loader = getClass().getClassLoader();
            for (KeyExchangeFactory factory : client.getKeyExchangeFactories()) {
                kexFactories.add(new KeyExchangeFactory() {
                    @Override
                    public String getName() {
                        return factory.getName();
                    }

                    @Override
                    public KeyExchange createKeyExchange(Session s) throws Exception {
                        KeyExchange proxiedInstance = factory.createKeyExchange(s);
                        return ProxyUtils.newProxyInstance(loader, KeyExchange.class, (proxy, method, args) -> {
                            String name = method.getName();
                            if ("init".equals(name) && (!successfulInit.get())) {
                                throw new UnsupportedOperationException("Intentionally failing 'init'");
                            } else if ("next".equals(name) && (!successfulNext.get())) {
                                throw new UnsupportedOperationException("Intentionally failing 'next'");
                            } else {
                                return method.invoke(proxiedInstance, args);
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

    private void testKexFutureExceptionPropagation(String failureType, AtomicBoolean successFlag, SshClient client)
            throws Exception {
        try (ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            successFlag.set(false);
            KeyExchangeFuture kexFuture = session.switchToNoneCipher();
            assertTrue(failureType + ": failed to complete KEX on time", kexFuture.await(DEFAULT_TIMEOUT));
            assertNotNull(failureType + ": unexpected success", kexFuture.getException());
        }
    }

    @Test
    public void testReExchangeFromJschClient() throws Exception {
        Assume.assumeTrue("DH Group Exchange not supported", SecurityUtils.isDHGroupExchangeSupported());
        setUp(0L, Duration.ZERO, 0L);

        JSch.setConfig("kex", BuiltinDHFactories.Constants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1);
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
        try {
            s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
            s.connect();

            com.jcraft.jsch.Channel c = s.openChannel(Channel.CHANNEL_SHELL);
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
                    String str = new String(data, 0, len, StandardCharsets.UTF_8);
                    assertEquals("Mismatched data at iteration " + i, expected, str);

                    outputDebugMessage("Request re-key #%d", i);
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
        setUp(0L, Duration.ZERO, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                final Semaphore pipedCount = new Semaphore(0, true);
                try (ChannelShell channel = session.createShellChannel();
                     ByteArrayOutputStream sent = new ByteArrayOutputStream();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn);
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     ByteArrayOutputStream out = new ByteArrayOutputStream() {
                         private long writeCount;

                         @Override
                         public synchronized void write(int b) {
                             super.write(b);
                             updateWriteCount(1L);
                             pipedCount.release(1);
                         }

                         @Override
                         public synchronized void write(byte[] b, int off, int len) {
                             super.write(b, off, len);
                             updateWriteCount(len);
                             pipedCount.release(len);
                         }

                         private void updateWriteCount(long delta) {
                             writeCount += delta;
                             outputDebugMessage("OUT write count=%d", writeCount);
                         }
                     };
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
                        assertTrue("Failed to complete KEX on time at iteration " + i, kexFuture.await(DEFAULT_TIMEOUT));
                        assertNull("KEX exception signalled at iteration " + i, kexFuture.getException());
                    }
                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), DEFAULT_TIMEOUT);
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));

                    byte[] expected = sent.toByteArray();
                    if (!pipedCount.tryAcquire(expected.length, DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                        fail("Failed to await sent data signal for len=" + expected.length + " (available="
                             + pipedCount.availablePermits() + ")");
                    }

                    assertArrayEquals("Mismatched sent data content", expected, out.toByteArray());
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testReExchangeFromServerBySize() throws Exception {
        final long bytesLImit = 10 * 1024L;
        setUp(bytesLImit, Duration.ZERO, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            final Semaphore pipedCount = new Semaphore(0, true);
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream() {
                     private long writeCount;

                     @Override
                     public synchronized void write(int b) {
                         super.write(b);
                         updateWriteCount(1L);
                         pipedCount.release(1);
                     }

                     @Override
                     public synchronized void write(byte[] b, int off, int len) {
                         super.write(b, off, len);
                         updateWriteCount(len);
                         pipedCount.release(len);
                     }

                     private void updateWriteCount(long delta) {
                         writeCount += delta;
                         outputDebugMessage("OUT write count=%d", writeCount);
                     }
                 }) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                byte[] sentData;
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
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }
                    });

                    byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
                    for (long sentSize = 0L; sentSize < (bytesLImit + Byte.MAX_VALUE + data.length); sentSize += data.length) {
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

                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), DEFAULT_TIMEOUT);
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));

                    sentData = sent.toByteArray();
                    if (!pipedCount.tryAcquire(sentData.length, DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                        fail("Failed to await sent data signal for len=" + sentData.length + " (available="
                             + pipedCount.availablePermits() + ")");
                    }
                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

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
        final Duration timeLimit = Duration.ofSeconds(2L);
        setUp(0L, timeLimit, 0L);

        try (SshClient client = setupTestClient()) {
            client.start();

            final Semaphore pipedCount = new Semaphore(0, true);
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream() {
                     private long writeCount;

                     @Override
                     public synchronized void write(int b) {
                         super.write(b);
                         updateWriteCount(1L);
                         pipedCount.release(1);
                     }

                     @Override
                     public synchronized void write(byte[] b, int off, int len) {
                         super.write(b, off, len);
                         updateWriteCount(len);
                         pipedCount.release(len);
                     }

                     private void updateWriteCount(long delta) {
                         writeCount += delta;
                         outputDebugMessage("OUT write count=%d", writeCount);
                     }
                 }) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                byte[] sentData;
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

                    AtomicInteger exchanges = new AtomicInteger();
                    session.addSessionListener(new SessionListener() {
                        @Override
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }
                    });

                    byte[] data = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
                    final long maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(3L * timeLimit.toMillis());
                    final long minWaitValue = 10L;
                    final long minWaitNanos = TimeUnit.MILLISECONDS.toNanos(minWaitValue);
                    for (long timePassed = 0L, sentSize = 0L; timePassed < maxWaitNanos; timePassed++) {
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

                        if ((timePassed < maxWaitNanos) && (nanoDuration < minWaitNanos)) {
                            Thread.sleep(minWaitValue);
                        }
                    }

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), DEFAULT_TIMEOUT);
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));

                    sentData = sent.toByteArray();
                    if (!pipedCount.tryAcquire(sentData.length, DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                        fail("Failed to await sent data signal for len=" + sentData.length + " (available="
                             + pipedCount.availablePermits() + ")");
                    }

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

                byte[] outData = out.toByteArray();
                assertEquals("Mismatched sent data length", sentData.length, outData.length);
                assertArrayEquals("Mismatched sent data content", sentData, outData);
            } finally {
                client.stop();
            }
        }
    }

    @Test // see SSHD-601
    public void testReExchangeFromServerByPackets() throws Exception {
        final int packetsLimit = 135;
        setUp(0L, Duration.ZERO, packetsLimit);

        try (SshClient client = setupTestClient()) {
            client.start();

            final Semaphore pipedCount = new Semaphore(0, true);
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession();
                 ByteArrayOutputStream sent = new ByteArrayOutputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream() {
                     private long writeCount;

                     @Override
                     public synchronized void write(int b) {
                         super.write(b);
                         updateWriteCount(1L);
                         pipedCount.release(1);
                     }

                     @Override
                     public synchronized void write(byte[] b, int off, int len) {
                         super.write(b, off, len);
                         updateWriteCount(len);
                         pipedCount.release(len);
                     }

                     private void updateWriteCount(long delta) {
                         writeCount += delta;
                         outputDebugMessage("OUT write count=%d", writeCount);
                     }
                 }) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                byte[] sentData;
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
                        public void sessionEvent(Session session, Event event) {
                            if (Event.KeyEstablished.equals(event)) {
                                int count = exchanges.incrementAndGet();
                                outputDebugMessage("Key established for %s - count=%d", session, count);
                            }
                        }
                    });

                    byte[] data = (getClass().getName() + "#" + getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8);
                    for (int index = 0; index < (packetsLimit * 2); index++) {
                        teeOut.write(data);
                        teeOut.flush();

                        // no need to wait until the packets limit is reached if a re-key occurred
                        if (exchanges.get() > 0) {
                            outputDebugMessage("Stop sending after %d packets and %d bytes - exchanges=%s",
                                    index + 11L, (index + 1L) * data.length, exchanges);
                            break;
                        }
                    }

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Duration timeout = CoreTestSupportUtils.getTimeout("KeyReExchangeTest", Duration.ofSeconds(15));

                    Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), timeout);
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));

                    sentData = sent.toByteArray();
                    if (!pipedCount.tryAcquire(sentData.length, timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                        fail("Failed to await sent data signal for len=" + sentData.length + " (available="
                             + pipedCount.availablePermits() + ")");
                    }

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                }

                byte[] outData = out.toByteArray();
                assertEquals("Mismatched sent data length", sentData.length, outData.length);
                assertArrayEquals("Mismatched sent data content", sentData, outData);
            } finally {
                client.stop();
            }
        }
    }

    static class TestSubsystemFactory implements SubsystemFactory {

        public static final String NAME = "test-subsystem";

        TestSubsystemFactory() {
            super();
        }

        @Override
        public Command createSubsystem(ChannelSession channel) throws IOException {
            return new Command() {
                private ExitCallback callback;

                @Override
                public void setInputStream(InputStream in) {
                    // Do nothing
                }

                @Override
                public void setOutputStream(OutputStream out) {
                    // Do nothing
                }

                @Override
                public void setErrorStream(OutputStream err) {
                    // Do nothing
                }

                @Override
                public void setExitCallback(ExitCallback callback) {
                    this.callback = callback;
                }

                @Override
                public void start(ChannelSession channel, Environment env) throws IOException {
                    // Do nothing
                }

                @Override
                public void destroy(ChannelSession channel) throws Exception {
                    callback.onExit(0);
                }
            };
        }

        @Override
        public String getName() {
            return NAME;
        }
    }
}
