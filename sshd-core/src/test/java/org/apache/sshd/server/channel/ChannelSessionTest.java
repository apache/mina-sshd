/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.SignalListener;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusChannel;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ChannelSessionTest extends BaseTestSupport {

    private boolean expanded = false;

    /**
     * Test whether onWindowExpanded is called from server session
     */
    @Test
    public void testHandleWindowAdjust() throws Exception {
        final Buffer buffer = new ByteArrayBuffer();
        buffer.putInt(1234);

        try(ChannelSession channelSession = new ChannelSession()) {
            channelSession.asyncOut = new ChannelAsyncOutputStream(new BogusChannel(), (byte) 0) {
                @SuppressWarnings("synthetic-access")
                @Override
                public void onWindowExpanded() throws IOException {
                    expanded = true;
                    super.onWindowExpanded();
                }
            };
            channelSession.handleWindowAdjust(buffer);
            assertTrue(expanded);
        }
    }

    @Test
    public void testAddSignalListenerOnDuplicateSignals() {
        ChannelSession.StandardEnvironment environ = new ChannelSession.StandardEnvironment();
        SignalListener listener = new SignalListener() {
            @Override
            public void signal(Signal signal) {
                // ignored
            }
        };

        for (Signal s : Signal.SIGNALS) {
            environ.addSignalListener(listener, s, s, s, s, s, s);

            Collection<SignalListener> ls = environ.getSignalListeners(s, false);
            int numListeners = (ls == null) ? 0 : ls.size();
            assertEquals("Mismatched registered listeners count for signal=" + s, 1, numListeners);
        }
    }
}