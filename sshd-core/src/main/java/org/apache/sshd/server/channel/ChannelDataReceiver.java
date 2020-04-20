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

import java.io.Closeable;
import java.io.IOException;

/**
 * <p>
 * Receiving end of the data stream from the client.
 * </p>
 *
 * <p>
 * Sequence of bytes that SSH client sends to the server is eventually sent to this interface to be passed on to the
 * final consumer. By default {@link ChannelSession} spools this in a buffer so that you can read it from the input
 * stream you get from {@link org.apache.sshd.server.command.Command#setInputStream(java.io.InputStream)}, but if
 * command wants to do a callback-driven I/O for the data it receives from the client, it can call
 * {@link ChannelSession#setDataReceiver(ChannelDataReceiver)} to do so. (And to grab a reference to
 * {@link ChannelSession}, a {@link org.apache.sshd.server.command.Command} should implement
 * {@link org.apache.sshd.server.ChannelSessionAware}.)
 * </p>
 *
 * @see ChannelSession#setDataReceiver(ChannelDataReceiver)
 * @see org.apache.sshd.server.ChannelSessionAware
 */
public interface ChannelDataReceiver extends Closeable {
    /**
     * <p>
     * Called when the server receives additional bytes from the client. When {@link #close()}-d then indicates EOF -
     * The client will no longer send us any more data.
     * </p>
     *
     * <p>
     * SSH channels use the windowing mechanism to perform flow control, much like TCP does. The server gives the client
     * the initial window size, which represents the number of bytes the client can send to the server. As the server
     * receives data, it can send a message to the client to allow it to send more data.
     * </p>
     *
     * <p>
     * The return value from this method is used to control this behaviour. Intuitively speaking, the callee returns the
     * number of bytes consumed by this method, by the time this method returns. Picture a one-way long bridge (for
     * example Golden Gate Bridge) with toll plazas on both sides. The window size is the maximum number of cars allowed
     * on the bridge. Here we are on the receiving end, so our job here is to count the number of cars as it leaves the
     * bridge, and if enough of them left, we'll signal the sending end that they can let in more cars. The return value
     * of this method counts the number of cars that are leaving in this batch.
     * </p>
     *
     * <p>
     * In simple cases, where the callee has consumed the bytes before it returns, the return value must be the same
     * value as the 'len' parameter given.
     * </p>
     *
     * <p>
     * On the other hand, if the callee is queueing up the received bytes somewhere to be consumed later (for example by
     * another thread), then this method should return 0, for the bytes aren't really consumed yet. And when at some
     * later point the bytes are actually used, then you'll invoke {@code channel.getLocalWindow().consumeAndCheck(len)}
     * to let the channel know that bytes are consumed.
     * </p>
     *
     * <p>
     * This behaviour will result in a better flow control, as the server will not allow the SSH client to overflow its
     * buffer. If instead you always return the value passed in the 'len' parameter, the place where you are queueing up
     * bytes may overflow.
     * </p>
     *
     * <p>
     * In either case, the callee must account for every bytes it receives in this method. Returning 0 and failing to
     * call back {@code channel.getLocalWindow().consumeAndCheck(len)} later will dry up the window size, and eventually
     * the client will stop sending you any data.
     * </p>
     *
     * <p>
     * In the SSH protocol, this method invocation is triggered by a <tt>SSH_MSG_CHANNEL_DATA</tt> message.
     * </p>
     *
     * @param  channel     The caller to which this {@link ChannelDataReceiver} is assigned. Never null.
     * @param  buf         Holds the bytes received. This buffer belongs to the caller, and it might get reused by the
     *                     caller as soon as this method returns.
     * @param  start       buf[start] is the first byte that received from the client.
     * @param  len         the length of the bytes received. Can be zero.
     * @return             The number of bytes consumed, for the purpose of the flow control. For a simple use case, you
     *                     return the value given by the 'len' parameter. See the method javadoc for more details.
     * @throws IOException if failed to consume the data
     */
    int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException;
}
