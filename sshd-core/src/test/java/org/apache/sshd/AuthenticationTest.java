/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.deprecated.ClientUserAuthServiceOld;
import org.apache.sshd.deprecated.UserAuthKeyboardInteractive;
import org.apache.sshd.deprecated.UserAuthPassword;
import org.apache.sshd.deprecated.UserAuthPublicKey;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthenticationTest extends BaseTestSupport {

    private static final String WELCOME = "Welcome to SSHD";

    private SshServer sshd;
    private int port;

    public AuthenticationTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.WELCOME_BANNER, WELCOME);
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.AUTH_METHODS, "publickey,password publickey,keyboard-interactive");
        sshd.setSessionFactory(new SessionFactory() {
            @Override
            protected AbstractSession doCreateSession(IoSession ioSession) throws Exception {
                return new TestSession(getServer(), ioSession);
            }
        });
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testWrongPassword() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();
            try (ClientSession s = client.connect("user", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.addPasswordIdentity("bad password");
                assertTrue(s.auth().await().isFailure());

            }
        }
    }

    @Test
    public void testChangeUser() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));

            client.start();

            try (ClientSession s = client.connect(null, "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                assertFalse("Unexpected user1 password auth success", authPassword(s, "user1", "the-password").await().isSuccess());
                assertFalse("Unexpected user2 password auth success", authPassword(s, "user2", "the-password").await().isSuccess());

                // Note that WAIT_AUTH flag should be false, but since the internal
                // authentication future is not updated, it's still returned
                assertEquals("Mismatched client session close mask", ClientSession.CLOSED | ClientSession.WAIT_AUTH, s.waitFor(ClientSession.CLOSED, 1000));
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthPasswordOnly() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));
            client.start();

            try (ClientSession s = client.connect(null, "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                assertFalse("Unexpected password auth sucess", authPassword(s, getCurrentTestName(), getCurrentTestName()).await().isSuccess());

                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthKeyPassword() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));
            client.start();

            try (ClientSession s = client.connect(null, "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                assertFalse("Unexpected pubkey auth success", authPublicKey(s, getCurrentTestName(), pair).await().isSuccess());
                assertTrue("Failed password auth", authPassword(s, getCurrentTestName(), getCurrentTestName()).await().isSuccess());
                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testAuthKeyInteractive() throws Exception {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServiceFactories(Arrays.asList(
                    new ClientUserAuthServiceOld.Factory(),
                    ClientConnectionServiceFactory.INSTANCE
            ));
            client.start();

            try (ClientSession s = client.connect(null, "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

                KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                assertFalse("Unexpected pubkey auth success", authPublicKey(s, getCurrentTestName(), pair).await().isSuccess());
                assertTrue("Failed password auth", authInteractive(s, getCurrentTestName(), getCurrentTestName()).await().isSuccess());

                s.close(true);
            } finally {
                client.stop();
            }
        }
    }

    private AuthFuture authPassword(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthPassword(s, "ssh-connection", pswd));
    }

    private AuthFuture authInteractive(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthKeyboardInteractive(s, "ssh-connection", pswd));
    }

    private AuthFuture authPublicKey(ClientSession s, String user, KeyPair pair) throws IOException {
        s.setUsername(user);
        return s.getService(ClientUserAuthServiceOld.class)
                .auth(new UserAuthPublicKey(s, "ssh-connection", pair));
    }

    public static class TestSession extends ServerSessionImpl {
        public TestSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
            super(server, ioSession);
        }

        @Override
        public void handleMessage(Buffer buffer) throws Exception {
            super.handleMessage(buffer);    // debug breakpoint
        }
    }
}
