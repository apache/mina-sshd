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

package org.apache.sshd.client.channel;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.AbstractServerSession;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class ChannelExecTest extends BaseTestSupport {
    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    public ChannelExecTest() {
        super();
    }

    @BeforeEach
    void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ChannelExecTest.class);
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                return false;
            }
        });
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ChannelExecTest.class);
        client.start();
    }

    @AfterEach
    void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    // see SSHD-692
    @Test
    void multipleRemoteCommandExecutions() throws Exception {
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            for (int index = 1; index <= Byte.SIZE; index++) {
                String expected = getCurrentTestName() + "[" + index + "]";
                String actual = session.executeRemoteCommand(expected + "\n");
                assertEquals(expected, actual, "Mismatched reply");
            }
        }
    }

    @Test
    void highChannelId() throws Exception {
        List<? extends ServiceFactory> factories = sshd.getServiceFactories();
        List<ServiceFactory> newFactories = new ArrayList<>();
        for (ServiceFactory f : factories) {
            if (f instanceof ServerConnectionServiceFactory) {
                ServerConnectionServiceFactory testFactory = new ServerConnectionServiceFactory() {

                    @Override
                    public Service create(Session session) throws IOException {
                        AbstractServerSession abstractSession = ValidateUtils.checkInstanceOf(session,
                                AbstractServerSession.class, "Not a server session: %s", session);

                        class TestServerConnectionService extends ServerConnectionService {
                            TestServerConnectionService(AbstractServerSession session) throws SshException {
                                super(session);
                            }

                            @Override
                            protected long getNextChannelId() {
                                long id = super.getNextChannelId();
                                return id + 100 + Integer.MAX_VALUE;
                            }
                        }

                        ServerConnectionService service = new TestServerConnectionService(abstractSession);
                        service.addPortForwardingEventListenerManager(this);
                        return service;
                    }
                };
                newFactories.add(testFactory);
            } else {
                newFactories.add(f);
            }
        }
        sshd.setServiceFactories(newFactories);
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            String expected = getCurrentTestName();
            String actual = session.executeRemoteCommand(expected + '\n');
            assertEquals(expected, actual, "Mismatched reply");
        }
    }
}
