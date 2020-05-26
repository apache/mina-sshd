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

package org.apache.sshd.server.auth.keyboard;

import java.util.List;

import org.apache.sshd.server.session.ServerSession;

/**
 * Provides pluggable authentication using the &quot;keyboard-interactive&quot; method as specified by
 * <A HREF="https://tools.ietf.org/html/rfc4256">RFC-4256</A>?
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyboardInteractiveAuthenticator {
    /**
     * An authenticator that rejects any attempt to use it
     */
    KeyboardInteractiveAuthenticator NONE = new KeyboardInteractiveAuthenticator() {
        @Override
        public InteractiveChallenge generateChallenge(
                ServerSession session, String username, String lang, String subMethods)
                throws Exception {
            return null;
        }

        @Override
        public boolean authenticate(
                ServerSession session, String username, List<String> responses)
                throws Exception {
            return false;
        }

        @Override
        public String toString() {
            return "NONE";
        }
    };

    /**
     * Generates the interactive &quot;challenge&quot; to send to the client
     *
     * @param  session    The {@link ServerSession} through which the request was received
     * @param  username   The username
     * @param  lang       The language tag
     * @param  subMethods Sub-methods hints sent by the client
     * @return            The {@link InteractiveChallenge} - if {@code null} then authentication attempt via
     *                    &quot;keyboard-interactive&quot; method is rejected
     * @throws Exception  If unable to generate the challenge
     */
    InteractiveChallenge generateChallenge(
            ServerSession session, String username, String lang, String subMethods)
            throws Exception;

    /**
     * Called to authenticate the response to the challenge(s) sent previously
     *
     * @param  session   The {@link ServerSession} through which the response was received
     * @param  username  The username
     * @param  responses The received responses - <B>Note:</B> it is up to the authenticator to make sure that the
     *                   number of responses matches the number of prompts sent in the initial challenge. The
     *                   <U>order</U> of the responses matches the order of the prompts sent to the client
     * @return           {@code true} if responses have been validated
     * @throws Exception if bad responses and server should terminate the connection
     */
    boolean authenticate(
            ServerSession session, String username, List<String> responses)
            throws Exception;
}
