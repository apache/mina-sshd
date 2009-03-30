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
package org.apache.sshd;

import java.net.ServerSocket;

import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.mina.core.session.IoSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.Assert;
import org.junit.After;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ServerTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        sshd.stop();
    }

    /**
     * Send bad password.  The server should disconnect after a few attempts
     * @throws Exception
     */
    @Test
    public void testFailAuthentication() throws Exception {
        sshd.getProperties().put(SshServer.MAX_AUTH_REQUESTS, "10");

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        int nbTrials = 0;
        int res = 0;
        while ((res & ClientSession.CLOSED) == 0) {
            nbTrials ++;
            s.authPassword("smx", "buggy");
            res = s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);
        }
        Assert.assertTrue(nbTrials > 10);
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        sshd.getProperties().put(SshServer.AUTH_TIMEOUT, "1000");

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        int res = s.waitFor(ClientSession.CLOSED, 5000);
        Assert.assertTrue((res & ClientSession.CLOSED) != 0);
    }

    @Test
    public void testLanguage() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.setSessionFactory(new SessionFactory() {
            @Override
            protected AbstractSession createSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(client, ioSession) {
                    @Override
                    protected String[] createProposal(String hostKeyTypes) {
                        String[] proposal = super.createProposal(hostKeyTypes);
                        proposal[SshConstants.PROPOSAL_LANG_CTOS] = "en-US";
                        proposal[SshConstants.PROPOSAL_LANG_STOC] = "en-US";
                        return proposal;
                    }
                };
            }
        });
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        s.close(false);
    }

    public static void main(String[] args) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8000);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        Thread.sleep(100000);
    }
}
