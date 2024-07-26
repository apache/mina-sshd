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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.Random;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the behaviour of {@link ChannelAsyncOutputStream} regarding the chunking of the data to sent.
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ChannelAsyncOutputStreamTest extends BaseTestSupport {

    private static final String CLIENT_WITH_COMPATIBILITY_ISSUE = "specialClient";
    private RemoteWindow remoteWindow;
    private ChannelStreamWriter channelStreamWriter;
    private AbstractChannel channel;
    private Session session;
    private IoWriteFuture ioWriteFuture;

    public ChannelAsyncOutputStreamTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        channel = Mockito.mock(AbstractChannel.class);
        channelStreamWriter = Mockito.mock(ChannelStreamWriter.class);
        remoteWindow = new RemoteWindow(channel, true);
        ioWriteFuture = Mockito.mock(IoWriteFuture.class);
        session = Mockito.mock(Session.class);

        Mockito.when(channel.getRemoteWindow()).thenReturn(remoteWindow);
        Mockito.when(channel.getSession()).thenReturn(session);

        Mockito.when(channel.resolveChannelStreamWriter(ArgumentMatchers.any(Channel.class), ArgumentMatchers.anyByte()))
                .thenReturn(channelStreamWriter);
        Mockito.when(channelStreamWriter.writeData(ArgumentMatchers.any())).thenReturn(ioWriteFuture);

        Mockito.when(session.createBuffer(ArgumentMatchers.anyByte(), ArgumentMatchers.anyInt()))
                .thenReturn(new ByteArrayBuffer());

        Mockito.when(session.getClientVersion()).thenReturn(CLIENT_WITH_COMPATIBILITY_ISSUE);

    }

    @Test
    void completeDataSentIfDataFitsIntoPacketAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 30000, 40000 - 30000);
    }

    /*
     * Only partial Data of packet size should be sent if data is larger than packet size and packet size fits into
     * remote window
     */
    @Test
    void chunkOfPacketSizeSentIfDataLargerThanPacketSizeAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 35000, 40000 - 32000);
    }

    @Test
    void chunkOfPacketSizeSentIfDataLargerThanRemoteWindowAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 50000, 40000 - 32000);
    }

    @Test
    void chunkingIfRemoteWindowSmallerThanPacketSize() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 30000, 32000, 50000, 0);
    }

    private void checkChangeOfRemoteWindowSizeOnBufferWrite(
            ChannelAsyncOutputStream channelAsyncOutputStream, int initialWindowSize, int packetSize, int totalDataToSent,
            int expectedWindowSize)
            throws IOException {

        remoteWindow.init(initialWindowSize, packetSize, PropertyResolver.EMPTY);
        Buffer buffer = createBuffer(totalDataToSent);
        channelAsyncOutputStream.writeBuffer(buffer);

        assertEquals(expectedWindowSize, remoteWindow.getSize());
    }

    private ByteArrayBuffer createBuffer(int size) {
        byte[] randomBytes = new byte[size];
        new Random().nextBytes(randomBytes);
        return new ByteArrayBuffer(randomBytes);
    }
}
