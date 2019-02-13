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

package org.apache.sshd.common.kex.extension;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Used to support <A HREF="https://tools.ietf.org/html/rfc8308">RFC 8308</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KexExtensionHandler {
    enum KexPhase {
        NEWKEYS,
        AUTHOK;

        public static final Set<KexPhase> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(KexPhase.class));
    }

    /**
     * @param session The {@link Session} about to execute KEX
     * @return {@code true} whether to declare KEX extensions availability for the session
     * @throws IOException If failed to process the request
     */
    default boolean isKexExtensionsAvailable(Session session) throws IOException {
        return true;
    }

    /**
     * Invoked in order to allow the handler to send an {@code SSH_MSG_EXT_INFO} message.
     *
     * @param session The {@link Session}
     * @param phase The phase at which the handler is invoked
     * @throws IOException If failed to handle the invocation
     * @see <A HREF="https://tools.ietf.org/html/rfc8308#section-2.4">RFC-8308 - section 2.4</A>
     */
    default void sendKexExtensions(Session session, KexPhase phase) throws IOException {
        // do nothing
    }

    /**
     * Parses the {@code SSH_MSG_EXT_INFO} message
     *
     * @param session The {@link Session} through which the message was received
     * @param buffer The message buffer
     * @throws IOException If failed to handle the message
     * @see <A HREF="https://tools.ietf.org/html/rfc8308#section-2.3">RFC-8308 - section 2.3</A>
     * @see #handleKexExtensionRequest(Session, int, int, String, byte[])
     */
    default void handleKexExtensionsMessage(Session session, Buffer buffer) throws IOException {
        int count = buffer.getInt();
        for (int index = 0; index < count; index++) {
            String name = buffer.getString();
            byte[] data = buffer.getBytes();
            if (!handleKexExtensionRequest(session, index, count, name, data)) {
                return;
            }
        }
    }

    /**
     * Invoked by {@link #handleKexExtensionsMessage(Session, Buffer)} in order to
     * handle a specific extension.
     *
     * @param session The {@link Session} through which the message was received
     * @param index The 0-based extension index
     * @param count The total extensions in the message
     * @param name The extension name
     * @param data The extension data
     * @return {@code true} whether to proceed to the next extension or
     * stop processing the rest
     * @throws IOException If failed to handle the extension
     */
    default boolean handleKexExtensionRequest(
            Session session, int index, int count, String name, byte[] data) throws IOException {
        return true;
    }
}
