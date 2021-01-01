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

package org.apache.sshd.client.auth.hostbased;

import java.security.KeyPair;
import java.util.List;

import org.apache.sshd.client.session.ClientSession;

/**
 * Provides report about the client side host-based authentication progress
 *
 * @see    <a href="https://tools.ietf.org/html/rfc4252#section-9">RFC-4252 section 9</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface HostBasedAuthenticationReporter {
    /**
     * Sending the initial request to use host based authentication
     *
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @param  identity  The {@link KeyPair} identity being attempted
     * @param  hostname  The host name value sent to the server
     * @param  username  The username value sent to the server
     * @param  signature The signature data that is being sent to the server
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationAttempt(
            ClientSession session, String service, KeyPair identity, String hostname, String username, byte[] signature)
            throws Exception {
        // ignored
    }

    /**
     * Signals end of host based attempts and optionally switching to other authentication methods. <B>Note:</B> neither
     * {@link #signalAuthenticationSuccess(ClientSession, String, KeyPair, String, String) signalAuthenticationSuccess}
     * nor {@link #signalAuthenticationFailure(ClientSession, String, KeyPair, String, String, boolean, List)
     * signalAuthenticationFailure} are invoked.
     *
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @param  hostname  The host name value sent to the server
     * @param  username  The username value sent to the server
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationExhausted(
            ClientSession session, String service, String hostname, String username)
            throws Exception {
        // ignored
    }

    /**
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @param  identity  The {@link KeyPair} identity being attempted
     * @param  hostname  The host name value sent to the server
     * @param  username  The username value sent to the server
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationSuccess(
            ClientSession session, String service, KeyPair identity, String hostname, String username)
            throws Exception {
        // ignored
    }

    /**
     * @param  session       The {@link ClientSession}
     * @param  service       The requesting service name
     * @param  identity      The {@link KeyPair} identity being attempted
     * @param  hostname      The host name value sent to the server
     * @param  username      The username value sent to the server
     * @param  partial       {@code true} if some partial authentication success so far
     * @param  serverMethods The {@link List} of authentication methods that can continue
     * @throws Exception     If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthenticationFailure(
            ClientSession session, String service, KeyPair identity,
            String hostname, String username, boolean partial, List<String> serverMethods)
            throws Exception {
        // ignored
    }
}
