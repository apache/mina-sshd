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

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides a way to listen and handle the {@code SSH_MSG_IGNORE} and
 * {@code SSH_MSG_DEBUG} messages that are received by a session.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ReservedSessionMessagesHandler {
    /**
     * Invoked when an {@code SSH_MSG_IGNORE} packet is received
     *
     * @param session The {@code Session} through which the message was received
     * @param buffer The {@code Buffer} containing the data
     * @throws Exception If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-11.2">RFC 4253 - section 11.2</A>
     */
    void handleIgnoreMessage(Session session, Buffer buffer) throws Exception;

    /**
     * Invoked when an {@code SSH_MSG_DEBUG} packet is received
     *
     * @param session The {@code Session} through which the message was received
     * @param buffer The {@code Buffer} containing the data
     * @throws Exception If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-11.3">RFC 4253 - section 11.3</A>
     */
    void handleDebugMessage(Session session, Buffer buffer) throws Exception;
}
