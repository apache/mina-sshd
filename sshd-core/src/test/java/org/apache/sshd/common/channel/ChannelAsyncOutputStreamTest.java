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
import java.util.Collections;
import java.util.Random;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * Tests the behaviour of {@link ChannelAsyncOutputStream} regarding the chunking of the data to sent.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ChannelAsyncOutputStreamTest extends BaseTestSupport {

    private static final String CLIENT_WITH_COMPATIBILITY_ISSUE = "specialClient";
    private Window remoteWindow;
    private ChannelStreamWriter channelStreamWriter;
    private AbstractChannel channel;
    private Session session;
    private IoWriteFuture ioWriteFuture;

    public ChannelAsyncOutputStreamTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        channel = Mockito.mock(AbstractChannel.class);
        channelStreamWriter = Mockito.mock(ChannelStreamWriter.class);
        remoteWindow = new Window(channel, null, true, true);
        ioWriteFuture = Mockito.mock(IoWriteFuture.class);
        session = Mockito.mock(Session.class);

        Mockito.when(channel.getRemoteWindow()).thenReturn(remoteWindow);
        Mockito.when(channel.getSession()).thenReturn(session);

        Mockito.when(channel.resolveChannelStreamWriter(Mockito.any(Channel.class), Mockito.anyByte()))
                .thenReturn(channelStreamWriter);
        Mockito.when(channelStreamWriter.writeData(Mockito.any())).thenReturn(ioWriteFuture);

        Mockito.when(session.createBuffer(Mockito.anyByte(), Mockito.anyInt())).thenReturn(new ByteArrayBuffer());

        Mockito.when(session.getClientVersion()).thenReturn(CLIENT_WITH_COMPATIBILITY_ISSUE);

    }

    @Test
    public void testCompleteDataSentIfDataFitsIntoPacketAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 30000, 40000 - 30000);
    }

    /**
     * Only partial Data of packet size should be sent if data is larger than packet size and packet size fits into
     * remote window
     */
    @Test
    public void testChunkOfPacketSizeSentIfDataLargerThanPacketSizeAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 35000, 40000 - 32000);
    }

    @Test
    public void testChunkOfPacketSizeSentIfDataLargerThanRemoteWindowAndPacketFitsInRemoteWindow() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 40000, 32000, 50000, 40000 - 32000);
    }

    @Test
    public void testNoChunkingIfRemoteWindowSmallerThanPacketSize() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 30000, 32000, 50000, 30000);
    }

     @Test
    public void testChunkingIfRemoteWindowSmallerThanPacketSize() throws IOException {
        ChannelAsyncOutputStream channelAsyncOutputStream = new ChannelAsyncOutputStream(channel, (byte) 0, true);
        checkChangeOfRemoteWindowSizeOnBufferWrite(channelAsyncOutputStream, 30000, 32000, 50000, 0);
    }

    protected void checkChangeOfRemoteWindowSizeOnBufferWrite(
            ChannelAsyncOutputStream channelAsyncOutputStream, int initialWindowSize, int packetSize, int totalDataToSent,
            int expectedWindowSize)
            throws IOException {

        remoteWindow.init(initialWindowSize, packetSize, PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
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
