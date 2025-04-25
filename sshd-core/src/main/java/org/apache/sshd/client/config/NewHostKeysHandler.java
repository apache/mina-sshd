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
package org.apache.sshd.client.config;

import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.client.session.ClientSession;

/**
 * A handler that knows what to do when a {@link ClientSession} got new host keys from a server via the OpenSSH
 * "hostkeys-00@openssh.com" host key rotation extension.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://github.com/openssh/openssh-portable/blob/b5b405fee/PROTOCOL#L367">OpenSSH host key
 *         rotation</a>
 */
@FunctionalInterface
public interface NewHostKeysHandler {

    /**
     * Invoked when new keys have been received and verified.
     * <p>
     * If this method updates the {@code known_hosts} file or other key database with the new keys, it is recommended to
     * do so in a separate thread to avoid blocking the calling thread.
     * </p>
     *
     * @param session  the {@link ClientSession} that received the keys; can be used to figure out which server sent
     *                 these keys (via the session's host config entry or server address)
     * @param hostKeys the verified host keys received; never {@code null} and never containing {@code null}; may
     *                 contain host certificates
     */
    void receiveNewHostKeys(ClientSession session, Collection<PublicKey> hostKeys);
}
