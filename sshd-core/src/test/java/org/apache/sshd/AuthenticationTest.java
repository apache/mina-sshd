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

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.UserInfo;
import org.apache.mina.core.filterchain.IoFilterChain;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.TransportMetadata;
import org.apache.mina.core.session.AbstractIoSession;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.mina.transport.vmpipe.VmPipeAcceptor;
import org.apache.mina.transport.vmpipe.VmPipeAddress;
import org.apache.mina.transport.vmpipe.VmPipeConnector;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusPublickeyAuthenticator;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.ServerSocket;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthenticationTest {

    private static final String WELCOME = "Welcome to SSHD";

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd.setUserAuthFactories(Arrays.asList(
                new UserAuthDummy.Factory(), new UserAuthPassword.Factory(), new UserAuthPublicKey.Factory()
        ));
        sshd.getProperties().put(SshServer.WELCOME_BANNER, WELCOME);
        sshd.getProperties().put(SshServer.AUTH_METHODS, "publickey,password publickey,dummy");
        sshd.setSessionFactory(new SessionFactory() {
            @Override
            protected AbstractSession doCreateSession(IoSession ioSession) throws Exception {
                return new TestSession(server, ioSession);
            }
        });
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
            Thread.sleep(50);
        }
    }

    @Test
    public void testChangeUser() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

        assertFalse(s.authPassword("user1", "the-password").await().isSuccess());
        assertFalse(s.authPassword("user2", "the-password").await().isSuccess());

        assertEquals(ClientSession.CLOSED, s.waitFor(ClientSession.CLOSED, 1000));
    }

    @Test
    public void testAuth() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 0);

        assertFalse(s.authPassword("smx", "smx").await().isSuccess());

        KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
        assertFalse(s.authPublicKey("smx", pair).await().isSuccess());

        assertTrue(s.authPassword("smx", "smx").await().isSuccess());

        s.close(true);
        client.stop();
    }

    public static class TestSession extends ServerSession {
        public TestSession(FactoryManager server, IoSession ioSession) throws Exception {
            super(server, ioSession);
        }
        public void setState(State state) {
            super.setState(state);
        }
        public void handleMessage(Buffer buffer) throws Exception {
            super.handleMessage(buffer);
        }
    }

    public static class UserAuthDummy implements UserAuth {
        public static class Factory implements NamedFactory<UserAuth> {
            public String getName() {
                return "dummy";
            }
            public UserAuth create() {
                return new UserAuthDummy();
            }
        }
        public Boolean auth(ServerSession session, String username, String service, Buffer buffer) throws Exception {
            return Boolean.TRUE;
        }
    }
}
