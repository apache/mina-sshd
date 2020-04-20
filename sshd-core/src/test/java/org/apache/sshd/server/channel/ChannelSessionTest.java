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
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusChannel;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ChannelSessionTest extends BaseTestSupport {
    public ChannelSessionTest() {
        super();
    }

    @Test
    public void testNoFlush() throws Exception {
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
                    assertTrue("Wrong channel state after " + (waitEnd - waitStart) + " ms.: " + result,
                            result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)));

                    byte[] b = new byte[1024];
                    InputStream invertedOut = channel.getInvertedOut();
                    int l = invertedOut.read(b);
                    String cmdReceived = (l > 0) ? new String(b, 0, l) : "";

                    assertEquals("Mismatched echoed command", cmdSent, cmdReceived);
                }
            }
        }
    }

    /*
     * Test whether onWindowExpanded is called from server session
     */
    @Test
    public void testHandleWindowAdjust() throws Exception {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(1234);

        try (ChannelSession channelSession = new ChannelSession() {
            {
                Window wRemote = getRemoteWindow();
                wRemote.init(PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
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
            assertTrue("Expanded ?", expanded.get());
        }
    }

    @Test // see SSHD-652
    public void testCloseFutureListenerRegistration() throws Exception {
        AtomicInteger closeCount = new AtomicInteger();
        try (ChannelSession session = new ChannelSession() {
            {
                Window wRemote = getRemoteWindow();
                wRemote.init(PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
            }
        }) {
            session.addCloseFutureListener(future -> {
                assertTrue("Future not marted as closed", future.isClosed());
                assertEquals("Unexpected multiple call to callback", 1, closeCount.incrementAndGet());
            });
            session.close();
        }

        assertEquals("Close listener not called", 1, closeCount.get());
    }
}
