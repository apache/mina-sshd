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
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.DynamicPortForwardingTracker;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusPasswordAuthenticator;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests for using a SOCKS proxy.
 */
class ProxySocksTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ProxySocksTest.class);

    @Test
    void proxy() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {
            // setup proxy with a forwarding filter to allow the dynamic port forwarding
            proxy.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
            proxy.start();

            // setup server with an echo command
            server.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {

                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream stdout = getOutputStream();
                    stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                    stdout.flush();
                    return false;
                }
            });
            AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();

            server.setPasswordAuthenticator(new BogusPasswordAuthenticator() {

                @Override
                public boolean authenticate(String username, String password, ServerSession session) {
                    SocketAddress rawFrom = session.getClientAddress();
                    if (!(rawFrom instanceof InetSocketAddress)) {
                        return false;
                    }
                    InetSocketAddress from = (InetSocketAddress) rawFrom;
                    InetSocketAddress clientDirect = clientAddress.get();
                    if (clientDirect == null || from.getPort() == clientDirect.getPort()) {
                        LOG.warn("Server got connection not through the proxy");
                        return false;
                    }
                    LOG.info("authenticate({}): Authenticating {} at server", session, username);
                    return super.authenticate(username, password, session);
                };
            });
            server.start();

            LOG.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());

            // setup client
            client.start();
            try (ClientSession proxySession = client.connect("user1", TEST_LOCALHOST, proxy.getPort()).verify(CONNECT_TIMEOUT)
                    .getSession()) {
                proxySession.addPasswordIdentity("user1");
                proxySession.auth().verify(AUTH_TIMEOUT);
                SshdSocketAddress anyLocal = new SshdSocketAddress("localhost", 0); // Let the system choose a port
                try (DynamicPortForwardingTracker dynamic = proxySession.createDynamicPortForwardingTracker(anyLocal)) {
                    SshdSocketAddress socksAddress = dynamic.getBoundAddress();
                    LOG.info("SOCKS proxy listenting on {}", socksAddress);
                    Proxy proxyDescriptor = new Proxy(Proxy.Type.SOCKS,
                            new InetSocketAddress(socksAddress.getHostName(), socksAddress.getPort()));
                    client.setProxyDataFactory(remoteAddress -> {
                        if (SshdSocketAddress.isLoopback(remoteAddress.getAddress())
                                && server.getPort() == remoteAddress.getPort()) {
                            return new ProxyData(proxyDescriptor);
                        }
                        return null;
                    });
                    // Connect through the SOCKS proxy
                    try (ClientSession session = client.connect("user2", TEST_LOCALHOST, server.getPort())
                            .verify(CONNECT_TIMEOUT).getSession()) {
                        SocketAddress myAddress = session.getIoSession().getLocalAddress();
                        if (myAddress instanceof InetSocketAddress) {
                            clientAddress.set((InetSocketAddress) myAddress);
                        }
                        session.addPasswordIdentity("user2");
                        session.auth().verify(AUTH_TIMEOUT);
                        assertTrue(session.isAuthenticated());
                        testCommand(session, "ls -al");
                    }
                }
            }
        }
    }

    private void testCommand(ClientSession session, String command) throws IOException {
        String result;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream errors = new ByteArrayOutputStream();
        session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
        result = out.toString();
        assertEquals(command, result);
    }

}
