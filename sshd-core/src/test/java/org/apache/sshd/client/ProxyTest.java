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
package org.apache.sshd.client;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ProxyTest extends BaseTestSupport {

    public ProxyTest() {
        super();
    }

    @Test
    public void testProxy() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {

            server.start();
            proxy.start();
            client.start();

            String command = "ls -la";
            String result;
            try (ClientSession session = createSession(
                    client,
                    "localhost", server.getPort(), "user1", "user1",
                    "localhost", proxy.getPort(), "user2", "user2")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream errors = new ByteArrayOutputStream();
                session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
                result = out.toString();
            }
            assertEquals(command, result);
        }
    }

    @SuppressWarnings("checkstyle:ParameterNumber")
    protected ClientSession createSession(
            SshClient client,
            String host, int port, String user, String password,
            String proxyHost, int proxyPort, String proxyUser, String proxyPassword)
            throws java.io.IOException {
        ClientSession session;
        if (proxyHost != null) {
            ClientSession proxySession = client.connect(proxyUser, proxyHost, proxyPort)
                    .verify(CONNECT_TIMEOUT).getSession();
            proxySession.addPasswordIdentity(proxyPassword);
            proxySession.auth().verify(AUTH_TIMEOUT);
            SshdSocketAddress address = new SshdSocketAddress(host, port);
            ExplicitPortForwardingTracker tracker = proxySession.createLocalPortForwardingTracker(
                    SshdSocketAddress.LOCALHOST_ADDRESS, address);
            SshdSocketAddress bound = tracker.getBoundAddress();
            session = client.connect(user, bound.getHostName(), bound.getPort())
                    .verify(CONNECT_TIMEOUT).getSession();
            session.addCloseFutureListener(f -> IoUtils.closeQuietly(tracker));
        } else {
            session = client.connect(user, host, port).verify(CONNECT_TIMEOUT).getSession();
        }
        session.addPasswordIdentity(password);
        session.auth().verify(AUTH_TIMEOUT);
        return session;
    }

    @Override
    protected SshServer setupTestServer() {
        SshServer sshd = super.setupTestServer();
        // setup forwarding filter to allow the local port forwarding
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        // setup an echo command
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                return false;
            }
        });
        return sshd;
    }

}
