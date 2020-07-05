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
package org.apache.sshd.git.transport;

import java.io.IOException;
import java.util.Objects;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.eclipse.jgit.errors.TransportException;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.RemoteSession;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.util.FS;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitSshdSessionFactory
        extends SshSessionFactory
        implements SessionHolder<ClientSession>, ClientSessionHolder {
    public static final GitSshdSessionFactory INSTANCE = new GitSshdSessionFactory();

    private final SshClient client;
    private final ClientSession session;

    public GitSshdSessionFactory() {
        this(null, null);
    }

    /**
     * Used to provide an externally managed {@link SshClient} instance. In this case, the caller is responsible for
     * start/stop-ing the client once no longer needed.
     *
     * @param client The (never {@code null}) client instance
     */
    public GitSshdSessionFactory(SshClient client) {
        this(Objects.requireNonNull(client, "No client instance provided"), null);
    }

    /**
     * Used to provide an externally managed {@link ClientSession} instance. In this case, the caller is responsible for
     * connecting and disconnecting the session once no longer needed. <B>Note:</B> in this case, the connection and
     * authentication phase are <U>skipped</U> - i.e., any specific host/port/user/password(s) specified in the GIT URI
     * are <U>not used</U>.
     *
     * @param session The (never {@code null}) client session instance
     */
    public GitSshdSessionFactory(ClientSession session) {
        this(null, session);
    }

    protected GitSshdSessionFactory(SshClient client, ClientSession session) {
        this.client = client;
        this.session = session;
    }

    @Override
    public String getType() {
        return "sshd-jgit";
    }

    @Override
    public RemoteSession getSession(
            URIish uri, CredentialsProvider credentialsProvider, FS fs, int tms)
            throws TransportException {
        try {
            return new GitSshdSession(uri, credentialsProvider, fs, tms) {
                @Override
                protected SshClient createClient() {
                    SshClient thisClient = getClient();
                    if (thisClient != null) {
                        return thisClient;
                    }

                    return super.createClient();
                }

                @Override
                protected ClientSession createClientSession(
                        SshClient clientInstance, String host, String username, int port, String... passwords)
                        throws IOException, InterruptedException {
                    ClientSession thisSession = getClientSession();
                    if (thisSession != null) {
                        return thisSession;
                    }

                    return super.createClientSession(clientInstance, host, username, port, passwords);
                }

                @Override
                protected void disconnectSession(ClientSession sessionInstance) {
                    ClientSession thisSession = getClientSession();
                    if (GenericUtils.isSameReference(thisSession, sessionInstance)) {
                        return; // do not use the session instance we were given
                    }

                    super.disconnectSession(sessionInstance);
                }

                @Override
                protected void disconnectClient(SshClient clientInstance) {
                    SshClient thisClient = getClient();
                    if (GenericUtils.isSameReference(thisClient, clientInstance)) {
                        return; // do not close the client the user gave us
                    }

                    super.disconnectClient(clientInstance);
                }
            };
        } catch (Exception e) {
            throw new TransportException("Unable to connect", e);
        }
    }

    protected SshClient getClient() {
        return client;
    }

    @Override
    public ClientSession getClientSession() {
        return session;
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }
}
