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
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Used to support <A HREF="https://tools.ietf.org/html/rfc8308">RFC 8308</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KexExtensionHandler {
    /**
     * Provides a hint as to the context in which {@code isKexExtensionsAvailable} is invoked
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    enum AvailabilityPhase {
        /**
         * Decide whether to delay sending the KEX-INIT message until the peer one has been received. <B>Note:</B>
         * currently invoked only by client sessions, but code should not rely on this implicit assumption.
         */
        PREKEX,

        /**
         * About to create the KEX-INIT proposal - should this session declare it support the KEX negotiation extension
         * mechanism or not.
         */
        PROPOSAL,

        /**
         * About to send the {@code SSH_MSG_NEWKEYS} message
         */
        NEWKEYS,

        /**
         * About to send {@code SSH_MSG_USERAUTH_SUCCESS} message. <B>Note:</B> currently invoked only by server
         * sessions, but code should not rely on this implicit assumption.
         */
        AUTHOK;
    }

    /**
     * @param  session     The {@link Session} about to execute KEX
     * @param  phase       The {@link AvailabilityPhase} hint as to why the query is being made
     * @return             {@code true} whether to KEX extensions are supported/allowed for the session
     * @throws IOException If failed to process the request
     */
    default boolean isKexExtensionsAvailable(Session session, AvailabilityPhase phase) throws IOException {
        return true;
    }

    /**
     * Invoked when a peer is ready to send the KEX options proposal or has received such a proposal. <B>Note:</B> this
     * method is called during the negotiation phase even if {@code isKexExtensionsAvailable} returns {@code false} for
     * the session.
     *
     * @param  session   The {@link Session} initiating or receiving the proposal
     * @param  initiator {@code true} if the proposal is about to be sent, {@code false} if this is a proposal received
     *                   from the peer.
     * @param  proposal  The proposal contents - <B>Caveat emptor:</B> the proposal is <U>modifiable</U> i.e., the
     *                   handler can modify it before being sent or before being processed (if incoming)
     * @throws Exception If failed to handle the request
     */
    default void handleKexInitProposal(
            Session session, boolean initiator, Map<KexProposalOption, String> proposal)
            throws Exception {
        // ignored
    }

    /**
     * Invoked during the KEX negotiation phase to inform about option being negotiated. <B>Note:</B> this method is
     * called during the negotiation phase even if {@code isKexExtensionsAvailable} returns {@code false} for the
     * session.
     *
     * @param  session    The {@link Session} executing the negotiation
     * @param  option     The negotiated {@link KexProposalOption}
     * @param  nValue     The negotiated option value (may be {@code null}/empty).
     * @param  c2sOptions The client proposals
     * @param  cValue     The client-side value for the option (may be {@code null}/empty).
     * @param  s2cOptions The server proposals
     * @param  sValue     The server-side value for the option (may be {@code null}/empty).
     * @throws Exception  If failed to handle the invocation
     */
    default void handleKexExtensionNegotiation(
            Session session, KexProposalOption option, String nValue,
            Map<KexProposalOption, String> c2sOptions, String cValue,
            Map<KexProposalOption, String> s2cOptions, String sValue)
            throws Exception {
        // do nothing
    }

    /**
     * The phase at which {@code sendKexExtensions} is invoked
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    enum KexPhase {
        NEWKEYS,
        AUTHOK;

        public static final Set<KexPhase> VALUES = Collections.unmodifiableSet(EnumSet.allOf(KexPhase.class));
    }

    /**
     * Invoked in order to allow the handler to send an {@code SSH_MSG_EXT_INFO} message. <B>Note:</B> this method is
     * called only if {@code isKexExtensionsAvailable} returns {@code true} for the session.
     *
     * @param  session   The {@link Session}
     * @param  phase     The phase at which the handler is invoked
     * @throws Exception If failed to handle the invocation
     * @see              <A HREF="https://tools.ietf.org/html/rfc8308#section-2.4">RFC-8308 - section 2.4</A>
     */
    default void sendKexExtensions(Session session, KexPhase phase) throws Exception {
        // do nothing
    }

    /**
     * Parses the {@code SSH_MSG_EXT_INFO} message. <B>Note:</B> this method is called regardless of whether
     * {@code isKexExtensionsAvailable} returns {@code true} for the session.
     *
     * @param  session   The {@link Session} through which the message was received
     * @param  buffer    The message buffer
     * @return           {@code true} if message handled - if {@code false} then {@code SSH_MSG_UNIMPLEMENTED} will be
     *                   generated
     * @throws Exception If failed to handle the message
     * @see              <A HREF="https://tools.ietf.org/html/rfc8308#section-2.3">RFC-8308 - section 2.3</A>
     * @see              #handleKexExtensionRequest(Session, int, int, String, byte[])
     */
    default boolean handleKexExtensionsMessage(Session session, Buffer buffer) throws Exception {
        int count = buffer.getInt();
        for (int index = 0; index < count; index++) {
            String name = buffer.getString();
            byte[] data = buffer.getBytes();
            if (!handleKexExtensionRequest(session, index, count, name, data)) {
                break;
            }
        }

        return true;
    }

    /**
     * Parses the {@code SSH_MSG_NEWCOMPRESS} message. <B>Note:</B> this method is called regardless of whether
     * {@code isKexExtensionsAvailable} returns {@code true} for the session.
     *
     * @param  session   The {@link Session} through which the message was received
     * @param  buffer    The message buffer
     * @return           {@code true} if message handled - if {@code false} then {@code SSH_MSG_UNIMPLEMENTED} will be
     *                   generated
     * @throws Exception If failed to handle the message
     * @see              <A HREF="https://tools.ietf.org/html/rfc8308#section-3.2">RFC-8308 - section 3.2</A>
     */
    default boolean handleKexCompressionMessage(Session session, Buffer buffer) throws Exception {
        return true;
    }

    /**
     * Invoked by {@link #handleKexExtensionsMessage(Session, Buffer)} in order to handle a specific extension.
     *
     * @param  session   The {@link Session} through which the message was received
     * @param  index     The 0-based extension index
     * @param  count     The total extensions in the message
     * @param  name      The extension name
     * @param  data      The extension data
     * @return           {@code true} whether to proceed to the next extension or stop processing the rest
     * @throws Exception If failed to handle the extension
     */
    default boolean handleKexExtensionRequest(
            Session session, int index, int count, String name, byte[] data)
            throws Exception {
        return true;
    }
}
