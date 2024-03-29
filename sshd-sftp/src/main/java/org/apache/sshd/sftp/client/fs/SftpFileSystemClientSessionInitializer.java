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

package org.apache.sshd.sftp.client.fs;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.auth.PasswordHolder;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.session.SessionHeartbeatController;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.sftp.client.SftpErrorDataHandler;
import org.apache.sshd.sftp.client.SftpVersionSelector;

/**
 * Provides user hooks into the process of creating a {@link SftpFileSystem} via a {@link SftpFileSystemProvider}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpFileSystemClientSessionInitializer {
    SftpFileSystemClientSessionInitializer DEFAULT = new SftpFileSystemClientSessionInitializer() {
        @Override
        public String toString() {
            return SftpFileSystemClientSessionInitializer.class.getSimpleName() + "[DEFAULT]";
        }
    };

    /**
     * Invoked by the {@link SftpFileSystemProvider#newFileSystem(java.net.URI, Map)} method in order to obtain an
     * initial (non-authenticated) {@link ClientSession}.
     *
     * @param  provider    The {@link SftpFileSystemProvider} instance requesting the session
     * @param  context     The initialization {@link SftpFileSystemInitializationContext}
     * @return             The created {@link ClientSession}
     * @throws IOException If failed to connect
     */
    default ClientSession createClientSession(
            SftpFileSystemProvider provider, SftpFileSystemInitializationContext context)
            throws IOException {
        UsernameHolder user = context.getCredentials();
        ClientSessionCreator client = provider.getClientInstance();
        return client.connect(user.getUsername(), context.getHost(), context.getPort())
                .verify(context.getMaxConnectTime())
                .getSession();
    }

    /**
     * Invoked by the {@link SftpFileSystemProvider#newFileSystem(java.net.URI, Map)} method in order to authenticate
     * the session obtained from
     * {@link #createClientSession(SftpFileSystemProvider, SftpFileSystemInitializationContext)}
     *
     * @param  provider    The {@link SftpFileSystemProvider} instance requesting the session
     * @param  context     The initialization {@link SftpFileSystemInitializationContext}
     * @param  session     The created {@link ClientSession}
     * @throws IOException If failed to authenticate
     */
    default void authenticateClientSession(
            SftpFileSystemProvider provider, SftpFileSystemInitializationContext context, ClientSession session)
            throws IOException {
        PasswordHolder passwordHolder = context.getCredentials();
        String password = passwordHolder.getPassword();
        // If no password provided perhaps the client is set-up to use registered public keys
        if (password != null) {
            session.addPasswordIdentity(password);
        }
        session.auth().verify(context.getMaxAuthTime());

        // Keep this session open for as long as the filesystem is in use.
        // TODO: the interval should be configurable somehow.
        session.setSessionHeartbeat(SessionHeartbeatController.HeartbeatType.IGNORE, Duration.ofSeconds(10));
    }

    /**
     * Invoked by the {@link SftpFileSystemProvider#newFileSystem(java.net.URI, Map)} method in order to create the
     * {@link SftpFileSystem} once session has been authenticated.
     *
     * @param      provider         The {@link SftpFileSystemProvider} instance requesting the session
     * @param      context          The initialization {@link SftpFileSystemInitializationContext}
     * @param      session          The authenticated {@link ClientSession}
     * @param      selector         The <U>resolved</U> {@link SftpVersionSelector} to use
     * @param      errorDataHandler The {@link SftpErrorDataHandler} to handle incoming data through the error stream -
     *                              if {@code null} the data is silently ignored
     * @return                      The created {@link SftpFileSystem}
     * @throws     IOException      If failed to create the file-system
     * @deprecated                  since 2.10.1
     */
    @Deprecated
    default SftpFileSystem createSftpFileSystem(
            SftpFileSystemProvider provider, SftpFileSystemInitializationContext context, ClientSession session,
            SftpVersionSelector selector, SftpErrorDataHandler errorDataHandler)
            throws IOException {
        return createSftpFileSystem(provider, context, x -> session, selector, errorDataHandler);
    }

    /**
     * Invoked by the {@link SftpFileSystemProvider#newFileSystem(java.net.URI, Map)} method in order to create the
     * {@link SftpFileSystem} once session has been authenticated.
     *
     * @param  provider         The {@link SftpFileSystemProvider} instance requesting the session
     * @param  context          The initialization {@link SftpFileSystemInitializationContext}
     * @param  sessionProvider  A factory for authenticated {@link ClientSession}s
     * @param  selector         The <U>resolved</U> {@link SftpVersionSelector} to use
     * @param  errorDataHandler The {@link SftpErrorDataHandler} to handle incoming data through the error stream - if
     *                          {@code null} the data is silently ignored
     * @return                  The created {@link SftpFileSystem}
     * @throws IOException      If failed to create the file-system
     */
    default SftpFileSystem createSftpFileSystem(
            SftpFileSystemProvider provider, SftpFileSystemInitializationContext context,
            IOFunction<Boolean, ClientSession> sessionProvider, SftpVersionSelector selector,
            SftpErrorDataHandler errorDataHandler) throws IOException {
        return new SftpFileSystemAutomatic(provider, context.getId(), sessionProvider, provider.getSftpClientFactory(),
                selector, errorDataHandler);
    }
}
