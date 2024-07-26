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
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.RemoteWindow;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusChannel;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ChannelSessionTest extends BaseTestSupport {
    public ChannelSessionTest() {
        super();
    }

    /*
     * Testing a command closing output stream when it completes
     */
    // see SSHD-1257
    @Test
    void closeOutputStream() throws Exception {
        try (SshServer server = setupTestServer();
             SshClient client = setupTestClient()) {

            server.setShellFactory(session -> new CommandExecutionHelper(null) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream out = getOutputStream();
                    out.write((command + "\n").getBytes(StandardCharsets.UTF_8));
                    boolean more = !"exit".equals(command);
                    if (!more) {
                        out.close();
                    }
                    return more;
                }
            });
            server.start();
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, server.getPort())
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                    channel.open().verify(OPEN_TIMEOUT);

                    OutputStream invertedIn = channel.getInvertedIn();
                    String cmdSent = "echo foo\nexit\n";
                    invertedIn.write(cmdSent.getBytes());
                    invertedIn.flush();

                    long waitStart = System.currentTimeMillis();
                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(11L));
                    long waitEnd = System.currentTimeMillis();
                    assertTrue(result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)),
                            "Wrong channel state after " + (waitEnd - waitStart) + " ms.: " + result);

                    byte[] b = new byte[1024];
                    InputStream invertedOut = channel.getInvertedOut();
                    int l = invertedOut.read(b);
                    String cmdReceived = (l > 0) ? new String(b, 0, l) : "";

                    assertEquals(cmdSent, cmdReceived, "Mismatched echoed command");
                }
            }
        }
    }

    private void chainedCommands(ClientSession session) throws Exception {
        try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
            channel.open().verify(OPEN_TIMEOUT);
            try (ClientChannel second = session.createChannel(Channel.CHANNEL_SHELL)) {
                // Chain stdout of the first command to stdin of the second.
                second.setIn(channel.getInvertedOut());
                second.open().verify(OPEN_TIMEOUT);

                // Write to the first command
                OutputStream invertedIn = channel.getInvertedIn();
                String cmdSent = "echo foo\nexit\n";
                invertedIn.write(cmdSent.getBytes());
                invertedIn.flush();

                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = second.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), 10_000);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)),
                        "Wrong channel state after " + (waitEnd - waitStart) + " ms.: " + result);
                // Read from the second command's stdout and check the result.
                try (InputStream invertedOut = second.getInvertedOut()) {
                    byte[] b = new byte[1024];
                    int l = invertedOut.read(b);
                    String cmdReceived = (l > 0) ? new String(b, 0, l) : "";
                    assertEquals(cmdSent, cmdReceived, "Mismatched echoed command");
                }
            }
        }
    }

    @Test
    void pipedInputStream() throws Exception {
        try (SshServer server = setupTestServer();
             SshClient client = setupTestClient()) {

            server.setShellFactory(session -> new CommandExecutionHelper(null) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream out = getOutputStream();
                    out.write((command + "\n").getBytes(StandardCharsets.UTF_8));
                    return !"exit".equals(command);
                }
            });
            server.start();
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, server.getPort())
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);
                chainedCommands(session);
            }
        }
    }

    @Test
    void noFlush() throws Exception {
        try (SshServer server = setupTestServer();
             SshClient client = setupTestClient()) {

            server.setShellFactory(session -> new CommandExecutionHelper(null) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream out = getOutputStream();
                    out.write((command + "\n").getBytes(StandardCharsets.UTF_8));
                    return !"exit".equals(command);
                }
            });
            server.start();
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, server.getPort())
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                    channel.open().verify(OPEN_TIMEOUT);

                    OutputStream invertedIn = channel.getInvertedIn();
                    String cmdSent = "echo foo\nexit\n";
                    invertedIn.write(cmdSent.getBytes());
                    invertedIn.flush();

                    long waitStart = System.currentTimeMillis();
                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(11L));
                    long waitEnd = System.currentTimeMillis();
                    assertTrue(result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)),
                            "Wrong channel state after " + (waitEnd - waitStart) + " ms.: " + result);

                    byte[] b = new byte[1024];
                    InputStream invertedOut = channel.getInvertedOut();
                    int l = invertedOut.read(b);
                    String cmdReceived = (l > 0) ? new String(b, 0, l) : "";

                    assertEquals(cmdSent, cmdReceived, "Mismatched echoed command");
                }
            }
        }
    }

    /*
     * Test whether onWindowExpanded is called from server session
     */
    @Test
    void handleWindowAdjust() throws Exception {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putUInt(1234L);

        try (ChannelSession channelSession = new ChannelSession() {
            {
                RemoteWindow wRemote = getRemoteWindow();
                wRemote.init(32768, 2048, PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
            }
        }) {
            AtomicBoolean expanded = new AtomicBoolean(false);
            channelSession.asyncOut = new ChannelAsyncOutputStream(new BogusChannel(), (byte) 0) {
                @Override
                public void onWindowExpanded() throws IOException {
                    expanded.set(true);
                    super.onWindowExpanded();
                }
            };
            channelSession.handleWindowAdjust(buffer);
            assertTrue(expanded.get(), "Expanded ?");
        }
    }

    // see SSHD-652
    @Test
    void closeFutureListenerRegistration() throws Exception {
        AtomicInteger closeCount = new AtomicInteger();
        try (ChannelSession session = new ChannelSession()) {
            session.addCloseFutureListener(future -> {
                assertTrue(future.isClosed(), "Future not marted as closed");
                assertEquals(1, closeCount.incrementAndGet(), "Unexpected multiple call to callback");
            });
            session.close();
        }

        assertEquals(1, closeCount.get(), "Close listener not called");
    }

    // SSHD-1244
    @Test
    void largeWindowSizeAdjust() throws Exception {
        try (ChannelSession session = new ChannelSession() {
            {
                RemoteWindow wRemote = getRemoteWindow();
                wRemote.init(1024, 256, PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
            }
        }) {
            RemoteWindow wRemote = session.getRemoteWindow();
            long initialSize = wRemote.getSize();
            assertEquals(1024, initialSize, "Bad initial window size");

            Buffer buffer = new ByteArrayBuffer();
            buffer.putUInt(BufferUtils.MAX_UINT32_VALUE);
            session.handleWindowAdjust(buffer);

            long updatedSize = wRemote.getSize();
            assertEquals(BufferUtils.MAX_UINT32_VALUE, updatedSize, "Mismatched updated window size");
        }
    }
}
