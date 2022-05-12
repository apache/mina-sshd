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

package org.apache.sshd.server.session;

import java.net.SocketAddress;
import java.security.KeyPair;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerFactoryManager;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerSession
        extends Session,
        ServerProxyAcceptorHolder,
        ServerAuthenticationManager {

    /**
     * @return The {@link ServerFactoryManager} for this session
     */
    @Override
    ServerFactoryManager getFactoryManager();

    /**
     * @return The {@link SocketAddress} of the remote client. If no proxy wrapping was used then this is the same as
     *         the {@code IoSession#getRemoteAddress()}. Otherwise, it indicates the real client's address that was
     *         somehow transmitted via the proxy meta-data
     */
    SocketAddress getClientAddress();

    /**
     * @return The {@link KeyPair} representing the current session's used keys on KEX - {@code null} if not negotiated
     *         yet
     */
    KeyPair getHostKey();

    /**
     * Retrieve the current number of sessions active for a given username.
     *
     * @param  userName The name of the user - ignored if {@code null}/empty
     * @return          The current number of live <code>SshSession</code> objects associated with the user
     */
    int getActiveSessionCountForUser(String userName);

    /**
     * <UL>
     * <P>
     * <LI>Marks the session as authenticated.</LI>
     * </P>
     *
     * <P>
     * <LI>Starts the specified service.</LI>
     * </P>
     *
     * <P>
     * <LI>Sends the {@code SSH_MSG_USERAUTH_SUCCESS} message.</LI>
     * </P>
     * </UL>
     * 
     * @param  username    The authenticated username
     * @param  authService The service to start
     * @param  buffer      Any extra data received to use to start the service
     * @return             An {@link IoWriteFuture} that can be used to wait for the {@code SSH_MSG_USERAUTH_SUCCESS}
     *                     message send result
     * @throws Exception   if cannot handle the request
     */
    IoWriteFuture signalAuthenticationSuccess(String username, String authService, Buffer buffer) throws Exception;
}
