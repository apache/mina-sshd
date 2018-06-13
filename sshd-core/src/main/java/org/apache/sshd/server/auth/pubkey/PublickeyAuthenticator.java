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
package org.apache.sshd.server.auth.pubkey;

import java.security.PublicKey;

import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.session.ServerSession;

/**
 * The <code>PublickeyAuthenticator</code> is used on the server side
 * to authenticate user public keys.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PublickeyAuthenticator {

    /**
     * Check the validity of a public key.
     *
     * @param username the username
     * @param key      the key
     * @param session  the server session
     * @return a boolean indicating if authentication succeeded or not
     * @throws AsyncAuthException If the authentication is performed asynchronously
     */
    boolean authenticate(String username, PublicKey key, ServerSession session) throws AsyncAuthException;
}
