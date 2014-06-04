/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.git.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.eclipse.jgit.errors.TransportException;
import org.eclipse.jgit.transport.CredentialItem;
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
public class GitSshdSessionFactory extends SshSessionFactory {

    @Override
    public RemoteSession getSession(URIish uri, CredentialsProvider credentialsProvider, FS fs, int tms) throws TransportException {
        try {
            return new SshdSession(uri, credentialsProvider, fs, tms);
        } catch (Exception e) {
            throw new TransportException("Unable to connect", e);
        }
    }

    protected SshClient createClient() {
        return SshClient.setUpDefaultClient();
    }

    public class SshdSession implements RemoteSession {

        private final SshClient client;
        private final ClientSession session;

        public SshdSession(URIish uri, CredentialsProvider credentialsProvider, FS fs, int tms) throws IOException, InterruptedException {
            String user = uri.getUser();
            final String pass = uri.getPass();
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
            client.start();
            session = client.connect(user, host, port).await().getSession();
            if (pass != null) {
                session.addPasswordIdentity(pass);
            }
            if (pass2 != null) {
                session.addPasswordIdentity(new String(pass2));
            }
            session.auth().verify();

        }

        public Process exec(String commandName, int timeout) throws IOException {
            final ChannelExec channel = session.createExecChannel(commandName);
            channel.open().verify();
            return new Process() {
                @Override
                public OutputStream getOutputStream() {
                    return channel.getInvertedIn();
                }

                @Override
                public InputStream getInputStream() {
                    return channel.getInvertedOut();
                }

                @Override
                public InputStream getErrorStream() {
                    return channel.getInvertedErr();
                }

                @Override
                public int waitFor() throws InterruptedException {
                    return channel.waitFor(ClientChannel.CLOSED, 0);
                }

                @Override
                public int exitValue() {
                    return channel.getExitStatus();
                }

                @Override
                public void destroy() {
                    channel.close(true);
                }
            };
        }

        public void disconnect() {
            client.close(true);
        }

    }
}
