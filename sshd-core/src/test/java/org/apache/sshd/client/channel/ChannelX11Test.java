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

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.x11.X11ChannelFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.x11.X11ForwardSupport;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.MethodName.class)
public class ChannelX11Test extends BaseTestSupport {

    // @Container
    private static GenericContainer<?> sshdContainer = new GenericContainer<>(
            new ImageFromDockerfile().withDockerfileFromBuilder(builder -> builder.from("linuxserver/openssh-server") //
                    // allows forwarding
                    .run("sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding yes/g' /etc/ssh/sshd_config")
                    .run("sed -i 's/AllowTcpForwarding no/AllowTcpForwarding yes/g' /etc/ssh/sshd_config")
                    .run("sed -i 's/GatewayPorts no/GatewayPorts yes/g' /etc/ssh/sshd_config")
                    .run("sed -i 's/X11Forwarding no/X11Forwarding yes/g' /etc/ssh/sshd_config")
                    // Install xcalc
                    .run("apk update")
                    .run("apk add xcalc xorg-server xinit")
                    .build()))
            .withEnv("PUID", "1000")
            .withEnv("PGID", "1000")
            .withEnv("SUDO_ACCESS", "true")
            .withEnv("PASSWORD_ACCESS", "true")
            .withEnv("USER_NAME", "foo")
            .withEnv("USER_PASSWORD", "bar")
            .withEnv("SUDO_ACCESS", "true")
            .withExposedPorts(2222);

    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    public ChannelX11Test() {
        super();
    }

    @BeforeEach
    void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ChannelX11Test.class);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ChannelX11Test.class);
        client.setChannelFactories(Collections.singletonList(X11ChannelFactory.INSTANCE));
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

    @Test
    void x11Forwarding() throws Exception {
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {

            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ChannelShell channel = session.createShellChannel();
                 PipedInputStream inPis = new PipedInputStream();
                 PipedOutputStream inPos = new PipedOutputStream(inPis);
                 PipedInputStream outPis = new PipedInputStream();
                 PipedOutputStream outPos = new PipedOutputStream(outPis)) {

                channel.setXForwarding(true);
                channel.setIn(inPis);
                channel.setOut(outPos);
                channel.open().verify(OPEN_TIMEOUT).await();

                try (BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(inPos, StandardCharsets.UTF_8));
                     BufferedReader reader = new BufferedReader(
                             new InputStreamReader(outPis, StandardCharsets.UTF_8))) {
                    writer.write("xcalc");
                    writer.newLine();
                    writer.flush();

                    assertEquals("xcalc", reader.readLine());

                    // ENV_DISPLAY
                    try (ChannelSession serverChannel
                            = (ChannelSession) GenericUtils.head(GenericUtils.head(sshd.getActiveSessions())
                                    .getService(ServerConnectionService.class).getChannels())) {
                        assertNotNull(serverChannel.getEnvironment().getEnv().get(X11ForwardSupport.ENV_DISPLAY));
                    }
                }
            }

        }

    }

    //  @Test
    void x11ForwardOnMachine() throws Exception {

        try (ClientSession session = client.connect("foo", "127.0.0.1", sshdContainer.getMappedPort(2222))
                .verify(CONNECT_TIMEOUT).getSession()) {

            session.addPasswordIdentity("bar");
            session.auth().verify(AUTH_TIMEOUT).await();

            final ChannelExec exec = session.createExecChannel("xcalc");
            exec.setXForwarding(true);
            exec.open().verify(CONNECT_TIMEOUT).await();
            Thread.currentThread().join();
        }
    }

}
