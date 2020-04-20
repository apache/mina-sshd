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

import org.apache.sshd.common.util.SshdEventListener;

/**
 * Provides a simple listener for client / server channels being established or torn down. <B>Note:</B> for server-side
 * listeners, some of the established channels may be <U>client</U> - especially where connection proxy or forwarding is
 * concerned
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ChannelListener extends SshdEventListener {
    ChannelListener EMPTY = new ChannelListener() {
        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * Called to inform about initial setup of a channel via the
     * {@link Channel#init(org.apache.sshd.common.session.ConnectionService, org.apache.sshd.common.session.Session, int)}
     * method. <B>Note:</B> this method is guaranteed to be called before either of the
     * {@link #channelOpenSuccess(Channel)} or {@link #channelOpenFailure(Channel, Throwable)} will be called
     *
     * @param channel The initialized {@link Channel}
     */
    default void channelInitialized(Channel channel) {
        // ignored
    }

    /**
     * Called to inform about a channel being successfully opened for a session. <B>Note:</B> when the call is made, the
     * channel is known to be open but nothing beyond that.
     *
     * @param channel The newly opened {@link Channel}
     */
    default void channelOpenSuccess(Channel channel) {
        // ignored
    }

    /**
     * Called to inform about the failure to open a channel
     *
     * @param channel The failed {@link Channel}
     * @param reason  The {@link Throwable} reason - <B>Note:</B> if the {@link #channelOpenSuccess(Channel)}
     *                notification throws an exception it will cause this method to be invoked
     */
    default void channelOpenFailure(Channel channel, Throwable reason) {
        // ignored
    }

    /**
     * Called to inform that the channel state may have changed - e.g., received EOF, window adjustment, etc..
     *
     * @param channel The {@link Channel} whose state has changed
     * @param hint    A &quot;hint&quot; as to the nature of the state change. it can be a request name or a
     *                {@code SSH_MSG_CHANNEL_XXX} command or the name of an exception class
     */
    default void channelStateChanged(Channel channel, String hint) {
        // ignored
    }

    /**
     * Called to inform about a channel being closed. <B>Note:</B> when the call is made there are no guarantees about
     * the channel's actual state except that it either has been already closed or may be in the process of being
     * closed. <B>Note:</B> this method is guaranteed to be called regardless of whether
     * {@link #channelOpenSuccess(Channel)} or {@link #channelOpenFailure(Channel, Throwable)} have been called
     *
     * @param channel The referenced {@link Channel}
     * @param reason  The reason why the channel is being closed - if {@code null} then normal closure
     */
    default void channelClosed(Channel channel, Throwable reason) {
        // ignored
    }

    static <L extends ChannelListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, ChannelListener.class.getSimpleName());
    }
}
