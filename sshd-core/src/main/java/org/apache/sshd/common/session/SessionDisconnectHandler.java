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

import java.io.IOException;
import java.util.Map;

import org.apache.sshd.common.Service;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.helpers.TimeoutIndicator;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Invoked when the internal session code decides it should disconnect a session due to some consideration. Usually
 * allows intervening in the decision and even canceling it.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionDisconnectHandler {
    /**
     * Invoked when an internal timeout has expired (e.g., authentication, idle).
     *
     * @param  session       The session whose timeout has expired
     * @param  timeoutStatus The expired timeout
     * @return               {@code true} if expired timeout should be reset (i.e., no disconnect). If {@code false}
     *                       then session will disconnect due to the expired timeout
     * @throws IOException   If failed to handle the event
     */
    default boolean handleTimeoutDisconnectReason(
            Session session, TimeoutIndicator timeoutStatus)
            throws IOException {
        return false;
    }

    /**
     * Called to inform that the maximum allowed concurrent sessions threshold has been exceeded. <B>Note:</B> when
     * handler is invoked the session is not yet marked as having been authenticated, nor has the authentication success
     * been acknowledged to the peer.
     *
     * @param  session             The session that caused the excess
     * @param  service             The {@link Service} instance through which the request was received
     * @param  username            The authenticated username that is associated with the session.
     * @param  currentSessionCount The current sessions count
     * @param  maxSessionCount     The maximum allowed sessions count
     * @return                     {@code true} if accept the exceeding session regardless of the threshold. If
     *                             {@code false} then exceeding session will be disconnected
     * @throws IOException         If failed to handle the event, <B>Note:</B> choosing to ignore this disconnect reason
     *                             does not reset the current concurrent sessions counter in any way - i.e., the handler
     *                             will be re-invoked every time the threshold is exceeded.
     * @see                        CoreModuleProperties#MAX_CONCURRENT_SESSIONS
     */
    default boolean handleSessionsCountDisconnectReason(
            Session session, Service service, String username, int currentSessionCount, int maxSessionCount)
            throws IOException {
        return false;
    }

    /**
     * Invoked when a request has been made related to an unknown SSH service as described in
     * <A HREF="https://tools.ietf.org/html/rfc4253#section-10">RFC 4253 - section 10</A>.
     *
     * @param  session     The session through which the command was received
     * @param  cmd         The service related command
     * @param  serviceName The service name
     * @param  buffer      Any extra data received in the packet containing the request
     * @return             {@code true} if disregard the request (e.g., the handler handled it)
     * @throws IOException If failed to handle the request
     */
    default boolean handleUnsupportedServiceDisconnectReason(
            Session session, int cmd, String serviceName, Buffer buffer)
            throws IOException {
        return false;
    }

    /**
     * Invoked if the number of authentication attempts exceeded the maximum allowed
     *
     * @param  session          The session being authenticated
     * @param  service          The {@link Service} instance through which the request was received
     * @param  serviceName      The authentication service name
     * @param  method           The authentication method name
     * @param  user             The authentication username
     * @param  currentAuthCount The authentication attempt count
     * @param  maxAuthCount     The maximum allowed attempts
     * @return                  {@code true} if OK to ignore the exceeded attempt count and allow more attempts.
     *                          <B>Note:</B> choosing to ignore this disconnect reason does not reset the current count
     *                          - i.e., it will be re-invoked on the next attempt.
     * @throws IOException      If failed to handle the event
     */
    default boolean handleAuthCountDisconnectReason(
            Session session, Service service, String serviceName, String method, String user, int currentAuthCount,
            int maxAuthCount)
            throws IOException {
        return false;
    }

    /**
     * Invoked if the authentication parameters changed in mid-authentication process.
     *
     * @param  session     The session being authenticated
     * @param  service     The {@link Service} instance through which the request was received
     * @param  authUser    The original username being authenticated
     * @param  username    The requested username
     * @param  authService The original authentication service name
     * @param  serviceName The requested service name
     * @return             {@code true} if OK to ignore the change
     * @throws IOException If failed to handle the event
     */
    default boolean handleAuthParamsDisconnectReason(
            Session session, Service service, String authUser, String username, String authService, String serviceName)
            throws IOException {
        return false;
    }

    /**
     * Invoked if after KEX negotiation parameters resolved one of the options violates some internal constraint (e.g.,
     * cannot negotiate a value, or <A HREF="https://tools.ietf.org/html/rfc8308#section-2.2">RFC 8308 - section
     * 2.2</A>).
     *
     * @param  session         The session where the violation occurred
     * @param  c2sOptions      The client options
     * @param  s2cOptions      The server options
     * @param  negotiatedGuess The negotiated KEX options
     * @param  option          The violating {@link KexProposalOption}
     * @return                 {@code true} if disregard the violation - if {@code false} then session will disconnect
     * @throws IOException     if attempted to exchange some packets to fix the situation
     */
    default boolean handleKexDisconnectReason(
            Session session, Map<KexProposalOption, String> c2sOptions, Map<KexProposalOption, String> s2cOptions,
            Map<KexProposalOption, String> negotiatedGuess, KexProposalOption option)
            throws IOException {
        if (KexProposalOption.S2CLANG.equals(option) || KexProposalOption.C2SLANG.equals(option)) {
            return true; // OK if cannot agree on a language
        }

        return false;
    }
}
