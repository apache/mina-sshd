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

package org.apache.sshd.common.session;

import org.apache.sshd.common.util.SshdEventListener;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides a way to listen and handle the {@code SSH_MSG_IGNORE} and
 * {@code SSH_MSG_DEBUG} messages that are received by a session, as well
 * as proprietary and/or extension messages.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ReservedSessionMessagesHandler extends SshdEventListener {
    /**
     * Invoked when an {@code SSH_MSG_IGNORE} packet is received
     *
     * @param session The {@code Session} through which the message was received
     * @param buffer The {@code Buffer} containing the data
     * @throws Exception If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-11.2">RFC 4253 - section 11.2</A>
     */
    default void handleIgnoreMessage(Session session, Buffer buffer) throws Exception {
        // ignored
    }

    /**
     * Invoked when an {@code SSH_MSG_DEBUG} packet is received
     *
     * @param session The {@code Session} through which the message was received
     * @param buffer The {@code Buffer} containing the data
     * @throws Exception If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-11.3">RFC 4253 - section 11.3</A>
     */
    default void handleDebugMessage(Session session, Buffer buffer) throws Exception {
        // ignored
    }

    /**
     * Invoked when a packet with an un-implemented message is received - including
     * {@code SSH_MSG_UNIMPLEMENTED} itself
     *
     * @param session The {@code Session} through which the message was received
     * @param cmd The received (un-implemented) command
     * @param buffer The {@code Buffer} containing the data - positioned just beyond the command
     * @return {@code true} if message handled internally, {@code false} if should
     * return a {@code SSH_MSG_UNIMPLEMENTED} reply (default behavior)
     * @throws Exception If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-11.4">RFC 4253 - section 11.4</A>
     */
    default boolean handleUnimplementedMessage(Session session, int cmd, Buffer buffer) throws Exception {
        return false;
    }

    /**
     * Invoked if the user configured usage of a proprietary heartbeat mechanism.
     * <B>Note:</B> by default throws {@code UnsupportedOperationException} so
     * users who configure a proprietary heartbeat mechanism option must provide
     * an implementation for this method.
     *
     * @param service The {@link ConnectionService} through which the heartbeat
     * is being executed.
     * @return {@code true} whether heartbeat actually sent - <B>Note:</B> used
     * mainly for debugging purposes.
     * @throws Exception If failed to send the heartbeat - <B>Note:</B> causes
     * associated session termination.
     */
    default boolean sendReservedHeartbeat(ConnectionService service) throws Exception {
        throw new UnsupportedOperationException("Reserved heartbeat not implemented for " + service);
    }
}
