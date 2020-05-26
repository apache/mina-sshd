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

import java.io.IOException;
import java.util.Collection;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSession.ClientSessionEvent;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.helpers.MissingAttachedSessionException;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.server.session.SessionFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientDeadlockTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    public ClientDeadlockTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setSessionFactory(new SessionFactory(sshd) {
            @Override
            protected ServerSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                throw new IOException("Closing");
            }
        });
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testSimpleClient() throws Exception {
        client.start();

        ConnectFuture future = client.connect(getCurrentTestName(), TEST_LOCALHOST, port);
        try (ClientSession session = future.verify(CONNECT_TIMEOUT).getSession()) {
            Collection<ClientSessionEvent> events
                    = session.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), TimeUnit.SECONDS.toMillis(7L));
            assertTrue("Close event not signalled: " + events, events.contains(ClientSession.ClientSessionEvent.CLOSED));
            assertFalse("Session not marked as closed", session.isOpen());
        } catch (SshException e) {
            Throwable cause = e.getCause();
            // Due to a race condition we might get this exception
            if (!(cause instanceof MissingAttachedSessionException)) {
                throw e;
            }
        }
    }
}
