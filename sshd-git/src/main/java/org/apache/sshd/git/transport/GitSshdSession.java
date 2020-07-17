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

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.git.GitModuleProperties;
import org.eclipse.jgit.transport.CredentialItem;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.RemoteSession;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.util.FS;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitSshdSession extends AbstractLoggingBean implements RemoteSession {

    private final SshClient client;
    private final ClientSession session;

    public GitSshdSession(URIish uri, CredentialsProvider credentialsProvider, FS fs, int tms)
                                                                                               throws IOException,
                                                                                               InterruptedException {
        String user = uri.getUser();
        final String pass1 = uri.getPass();
        String host = uri.getHost();
        int port = uri.getPort();
        char[] pass2 = null;

        if (!credentialsProvider.isInteractive()) {
            CredentialItem.Username usrItem = new CredentialItem.Username();
            CredentialItem.Password pwdItem = new CredentialItem.Password();
            if (credentialsProvider.get(uri, usrItem, pwdItem)) {
                if (user == null) {
                    user = usrItem.getValue();
                } else if (user.equals(usrItem.getValue())) {
                    pass2 = pwdItem.getValue();
                }
            }
        }

        client = createClient();
        try {
            if (!client.isStarted()) {
                client.start();
            }

            session = createClientSession(client, host, user, port, pass1, (pass2 != null) ? new String(pass2) : null);
        } catch (IOException | InterruptedException e) {
            disconnectClient(client);
            throw e;
        }
    }

    protected ClientSession createClientSession(
            SshClient clientInstance, String host, String username, int port, String... passwords)
            throws IOException, InterruptedException {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Connecting to {}:{}", host, port);
        }

        ClientSession s = clientInstance.connect(username, host, port)
                .verify(GitModuleProperties.CONNECT_TIMEOUT.getRequired(clientInstance))
                .getSession();

        if (debugEnabled) {
            log.debug("Connected to {}:{}", host, port);
        }

        try {
            if (passwords == null) {
                passwords = GenericUtils.EMPTY_STRING_ARRAY;
            }

            for (String p : passwords) {
                if (p == null) {
                    continue;
                }
                s.addPasswordIdentity(p);
            }

            if (debugEnabled) {
                log.debug("Authenticating: {}", s);
            }

            s.auth().verify(GitModuleProperties.AUTH_TIMEOUT.getRequired(s));

            if (debugEnabled) {
                log.debug("Authenticated: {}", s);
            }

            ClientSession result = s;
            s = null; // avoid auto-close at finally clause
            return result;
        } finally {
            if (s != null) {
                s.close(true);
            }
        }
    }

    @Override
    public Process exec(String commandName, int timeout) throws IOException {
        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("exec({}) session={}, timeout={} sec.", commandName, session, timeout);
        }

        ChannelExec channel = session.createExecChannel(commandName);
        if (traceEnabled) {
            log.trace("exec({}) session={} - open channel", commandName, session);
        }

        try {
            channel.open().verify(GitModuleProperties.CHANNEL_OPEN_TIMEOUT.getRequired(channel));
            if (traceEnabled) {
                log.trace("exec({}) session={} - channel open", commandName, session);
            }

            GitSshdSessionProcess process = new GitSshdSessionProcess(channel, commandName, timeout);
            channel = null; // disable auto-close on finally clause
            return process;
        } finally {
            if (channel != null) {
                channel.close(true);
            }
        }
    }

    @Override
    public void disconnect() {
        try {
            disconnectSession(session);
        } finally {
            disconnectClient(client);
        }
    }

    protected void disconnectSession(ClientSession sessionInstance) {
        if ((sessionInstance == null) || (!sessionInstance.isOpen())) {
            return; // debug breakpoint
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Disconnecting from {}", sessionInstance);
        }

        sessionInstance.close(true);

        if (debugEnabled) {
            log.debug("Disconnected from {}", sessionInstance);
        }
    }

    protected void disconnectClient(SshClient clientInstance) {
        if ((clientInstance == null) || (!clientInstance.isStarted())) {
            return; // debug breakpoint
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Stopping {}", clientInstance);
        }

        clientInstance.stop();

        if (debugEnabled) {
            log.debug("Stopped {}", clientInstance);
        }
    }

    protected SshClient createClient() {
        return SshClient.setUpDefaultClient();
    }
}
