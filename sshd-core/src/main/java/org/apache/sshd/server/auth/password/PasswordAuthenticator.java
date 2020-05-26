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
package org.apache.sshd.server.auth.password;

import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.session.ServerSession;

/**
 * Used to authenticate users based on a password.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PasswordAuthenticator {
    /**
     * Check the validity of a password.
     *
     * @param  username                        The username credential
     * @param  password                        The provided password
     * @param  session                         The {@link ServerSession} attempting the authentication
     * @return                                 {@code true} indicating if authentication succeeded
     * @throws PasswordChangeRequiredException If the password is expired or not strong enough to suit the server's
     *                                         policy
     * @throws AsyncAuthException              If the authentication is performed asynchronously
     */
    boolean authenticate(String username, String password, ServerSession session)
            throws PasswordChangeRequiredException, AsyncAuthException;

    /**
     * Invoked when the client sends a {@code SSH_MSG_USERAUTH_REQUEST} indicating a password change. This can happen if
     * the {@code authenticate} method threw {@link PasswordChangeRequiredException} thus telling the client that it
     * needs to provide a new password. Throws {@link UnsupportedOperationException} by default.
     *
     * @param  session     The {@link ServerSession} attempting the authentication
     * @param  username    The username credential
     * @param  oldPassword The old password
     * @param  newPassword The new password
     * @return             {@code true} if password change accepted
     */
    default boolean handleClientPasswordChangeRequest(
            ServerSession session, String username, String oldPassword, String newPassword) {
        throw new UnsupportedOperationException("Password change not supported");
    }
}
