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
package org.apache.sshd.client.auth;

import java.util.List;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.auth.UserAuthInstance;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents a user authentication mechanism
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface UserAuth extends ClientSessionHolder, UserAuthInstance<ClientSession> {
    /**
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @throws Exception If failed to initialize the mechanism
     */
    void init(ClientSession session, String service) throws Exception;

    /**
     * @param  buffer    The {@link Buffer} to process - {@code null} if not a response buffer, i.e., the underlying
     *                   authentication mechanism should initiate whatever challenge/response mechanism is required
     * @return           {@code true} if request handled - {@code false} if the next authentication mechanism should be
     *                   used
     * @throws Exception If failed to process the request
     */
    boolean process(Buffer buffer) throws Exception;

    /**
     * Signal reception of {@code SSH_MSG_USERAUTH_SUCCESS} message
     *
     * @param  session   The {@link ClientSession}
     * @param  service   The requesting service name
     * @param  buffer    The {@link Buffer} containing the success message (after having consumed the relevant data from
     *                   it)
     * @throws Exception If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthMethodSuccess(ClientSession session, String service, Buffer buffer) throws Exception {
        // ignored
    }

    /**
     * Signals reception of {@code SSH_MSG_USERAUTH_FAILURE} message
     *
     * @param  session       The {@link ClientSession}
     * @param  service       The requesting service name
     * @param  partial       {@code true} if some partial authentication success so far
     * @param  serverMethods The {@link List} of authentication methods that can continue
     * @param  buffer        The {@link Buffer} containing the failure message (after having consumed the relevant data
     *                       from it)
     * @throws Exception     If failed to handle the callback - <B>Note:</B> may cause session close
     */
    default void signalAuthMethodFailure(
            ClientSession session, String service, boolean partial, List<String> serverMethods, Buffer buffer)
            throws Exception {
        // ignored
    }

    /**
     * Called to release any allocated resources
     */
    void destroy();
}
