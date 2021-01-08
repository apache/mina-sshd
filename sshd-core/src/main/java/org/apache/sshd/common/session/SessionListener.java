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

import java.util.List;
import java.util.Map;

import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.util.SshdEventListener;

/**
 * Represents an interface receiving session events.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionListener extends SshdEventListener {
    enum Event {
        KeyEstablished,
        Authenticated,
        KexCompleted
    }

    /**
     * An initial session connection has been established - <B>Caveat emptor:</B> the main difference between this
     * callback and {@link #sessionCreated(Session)} is that when this callback is called, the session is not yet fully
     * initialized so not all API(s) will respond as expected. The main purpose of this callback is to allow the user to
     * customize some session properties based on the peer's address and/or any provided connection context.
     *
     * @param session The established {@code Session}
     */
    default void sessionEstablished(Session session) {
        // ignored
    }

    /**
     * A new session just been created
     *
     * @param session The created {@link Session}
     */
    default void sessionCreated(Session session) {
        // ignored
    }

    /**
     * About to send identification to peer
     *
     * @param session    The {@link Session} instance
     * @param version    The resolved identification version
     * @param extraLines Extra data preceding the identification to be sent. <B>Note:</B> the list is modifiable only if
     *                   this is a server session. The user may modify it based on the peer.
     * @see              <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2 - Protocol
     *                   Version Exchange</A>
     */
    default void sessionPeerIdentificationSend(
            Session session, String version, List<String> extraLines) {
        // ignored
    }

    /**
     * Successfully read a line as part of the initial peer identification
     *
     * @param session    The {@link Session} instance
     * @param line       The data that was read so far - <B>Note:</B> might not be a full line if more packets are
     *                   required for full identification data. Furthermore, it may be <U>repeated</U> data due to
     *                   packets segmentation and re-assembly mechanism
     * @param extraLines Previous lines that were before this one - <B>Note:</B> it may be <U>repeated</U> data due to
     *                   packets segmentation and re-assembly mechanism
     * @see              <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2 - Protocol
     *                   Version Exchange</A>
     */
    default void sessionPeerIdentificationLine(
            Session session, String line, List<String> extraLines) {
        // ignored
    }

    /**
     * The peer's identification version was received
     *
     * @param session    The {@link Session} instance
     * @param version    The retrieved identification version
     * @param extraLines Extra data preceding the identification
     * @see              <A HREF="https://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - section 4.2 - Protocol
     *                   Version Exchange</A>
     */
    default void sessionPeerIdentificationReceived(
            Session session, String version, List<String> extraLines) {
        // ignored
    }

    /**
     *
     * @param session  The referenced {@link Session}
     * @param proposal The proposals that will be sent to the peer - <B>Caveat emptor:</B> the proposal is
     *                 <U>modifiable</U> i.e., the handler can modify it before being sent
     */
    default void sessionNegotiationOptionsCreated(Session session, Map<KexProposalOption, String> proposal) {
        // ignored
    }

    /**
     * Signals the start of the negotiation options handling
     *
     * @param session        The referenced {@link Session}
     * @param clientProposal The client proposal options (un-modifiable)
     * @param serverProposal The server proposal options (un-modifiable)
     */
    default void sessionNegotiationStart(
            Session session,
            Map<KexProposalOption, String> clientProposal,
            Map<KexProposalOption, String> serverProposal) {
        // ignored
    }

    /**
     * Signals the end of the negotiation options handling
     *
     * @param session           The referenced {@link Session}
     * @param clientProposal    The client proposal options (un-modifiable)
     * @param serverProposal    The server proposal options (un-modifiable)
     * @param negotiatedOptions The successfully negotiated options so far - even if exception occurred (un-modifiable)
     * @param reason            Negotiation end reason - {@code null} if successful
     */
    default void sessionNegotiationEnd(
            Session session,
            Map<KexProposalOption, String> clientProposal,
            Map<KexProposalOption, String> serverProposal,
            Map<KexProposalOption, String> negotiatedOptions,
            Throwable reason) {
        // ignored
    }

    /**
     * An event has been triggered
     *
     * @param session The referenced {@link Session}
     * @param event   The generated {@link Event}
     */
    default void sessionEvent(Session session, Event event) {
        // ignored
    }

    /**
     * An exception was caught and the session will be closed (if not already so). <B>Note:</B> the code makes no
     * guarantee that at this stage {@link #sessionClosed(Session)} will be called or perhaps has already been called
     *
     * @param session The referenced {@link Session}
     * @param t       The caught exception
     */
    default void sessionException(Session session, Throwable t) {
        // ignored
    }

    /**
     * Invoked when {@code SSH_MSG_DISCONNECT} message was sent/received
     *
     * @param session   The referenced {@link Session}
     * @param reason    The signaled reason code
     * @param msg       The provided description message (may be empty)
     * @param language  The language tag indicator (may be empty)
     * @param initiator Whether the session is the sender or recipient of the message
     * @see             <a href="https://tools.ietf.org/html/rfc4253#section-11.1">RFC 4253 - section 11.1</a>
     */
    default void sessionDisconnect(
            Session session, int reason, String msg, String language, boolean initiator) {
        // ignored
    }

    /**
     * A session has been closed
     *
     * @param session The closed {@link Session}
     */
    default void sessionClosed(Session session) {
        // ignored
    }

    static <L extends SessionListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, SessionListener.class.getSimpleName());
    }
}
