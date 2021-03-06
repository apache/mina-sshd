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

package org.apache.sshd.client.auth.password;

import java.util.List;

import org.apache.sshd.client.session.ClientSession;

/**
 * Used to inform the about the progress of a password authentication
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://tools.ietf.org/html/rfc4252#section-8">RFC-4252 section 8</a>
 */
public interface PasswordAuthenticationReporter {
    /**
     * @param  session     The {@link ClientSession}
     * @param  service     The requesting service name
     * @param  oldPassword The password being attempted
     * @param  modified    {@code true} if this is an attempt due to {@code SSH_MSG_USERAUTH_PASSWD_CHANGEREQ}
     * @param  newPassword The changed password
     * @throws Exception   If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationAttempt(
            ClientSession session, String service, String oldPassword, boolean modified, String newPassword)
            throws Exception {
        // ignored
    }

    /**
     * Signals end of passwords attempts and optionally switching to other authentication methods. <B>Note:</B> neither
     * {@link #signalAuthenticationSuccess(ClientSession, String, String) signalAuthenticationSuccess} nor
     * {@link #signalAuthenticationFailure(ClientSession, String, String, boolean, List) signalAuthenticationFailure}
     * are invoked.
     *
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationExhausted(ClientSession session, String service) throws Exception {
        // ignored
    }

    /**
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @param  password  The password that was attempted
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationSuccess(ClientSession session, String service, String password) throws Exception {
        // ignored
    }

    /**
     * @param  session       The {@link ClientSession}
     * @param  service       The requesting service name
     * @param  password      The password that was attempted
     * @param  partial       {@code true} if some partial authentication success so far
     * @param  serverMethods The {@link List} of authentication methods that can continue
     * @throws Exception     If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationFailure(
            ClientSession session, String service, String password, boolean partial, List<String> serverMethods)
            throws Exception {
        // ignored
    }
}
