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
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusChannel;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ChannelSessionTest extends BaseTestSupport {
    public ChannelSessionTest() {
        super();
    }

    /*
     * Test whether onWindowExpanded is called from server session
     */
    @Test
    public void testHandleWindowAdjust() throws Exception {
        final Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(1234);

        try (ChannelSession channelSession = new ChannelSession() {
                {
                    Window wRemote = getRemoteWindow();
                    wRemote.init(PropertyResolverUtils.toPropertyResolver(Collections.<String, Object>emptyMap()));
                }
        }) {
            final AtomicBoolean expanded = new AtomicBoolean(false);
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

    @Test   // see SSHD-652
    public void testCloseFutureListenerRegistration() throws Exception {
        final AtomicInteger closeCount = new AtomicInteger();
        try (ChannelSession session = new ChannelSession() {
            {
                Window wRemote = getRemoteWindow();
                wRemote.init(PropertyResolverUtils.toPropertyResolver(Collections.<String, Object>emptyMap()));
            }
        }) {
            session.addCloseFutureListener(new SshFutureListener<CloseFuture>() {
                @Override
                public void operationComplete(CloseFuture future) {
                    assertTrue("Future not marted as closed", future.isClosed());
                    assertEquals("Unexpected multiple call to callback", 1, closeCount.incrementAndGet());
                }
            });
            session.close();
        }

        assertEquals("Close listener not called", 1, closeCount.get());
    }
}