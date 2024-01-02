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

package org.apache.sshd.common.kex.extension;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.common.channel.StreamingChannel;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.ContainerTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder;
import org.testcontainers.utility.MountableFile;

/**
 * Tests to ensure that an Apache MINA sshd client can talk to OpenSSH servers with or without "strict KEX". This
 * implicitly tests the message sequence number handling; if sequence numbers get out of sync or are reset wrongly,
 * subsequent messages cannot be decrypted correctly and there will be exceptions.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/apache/mina-sshd/issues/445">Terrapin Mitigation: &quot;strict-kex&quot;</A>
 */
@Category(ContainerTestCase.class)
public class StrictKexInteroperabilityTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(StrictKexInteroperabilityTest.class);

    private static final String TEST_RESOURCES = "org/apache/sshd/common/kex/extensions/client";

    private SshClient client;

    public StrictKexInteroperabilityTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        client = setupTestClient();
        SessionFactory factory = new TestSessionFactory(client);
        client.setSessionFactory(factory);
    }

    @After
    public void tearDown() throws Exception {
        if (client != null) {
            client.stop();
        }
    }

    private DockerfileBuilder strictKexImage(DockerfileBuilder builder, boolean withStrictKex) {
        if (!withStrictKex) {
            return builder
                    // CentOS 7 is EOL and thus unlikely to get the security update for strict KEX.
                    .from("centos:7.9.2009") //
                    .run("yum install -y openssh-server") // Installs OpenSSH 7.4
                    .run("/usr/sbin/sshd-keygen") // Generate multiple host keys
                    .run("adduser bob"); // Add a user
        } else {
            return builder
                    .from("alpine:20231219") //
                    .run("apk --update add openssh-server") // Installs OpenSSH 9.6
                    .run("ssh-keygen -A") // Generate multiple host keys
                    .run("adduser -D bob") // Add a user
                    .run("echo 'bob:passwordBob' | chpasswd"); // Give it a password to unlock the user
        }
    }

    @Test
    public void testStrictKexOff() throws Exception {
        testStrictKex(false);
    }

    @Test
    public void testStrictKexOn() throws Exception {
        testStrictKex(true);
    }

    private void testStrictKex(boolean withStrictKex) throws Exception {
        // This tests that the message sequence numbers are handled correctly. Strict KEX resets them to zero on any
        // KEX, without strict KEX, they're not reset. If sequence numbers get out of sync, received messages are
        // decrypted wrongly and there will be exceptions.
        @SuppressWarnings("resource")
        GenericContainer<?> sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
                .withDockerfileFromBuilder(builder -> strictKexImage(builder, withStrictKex) //
                        .run("mkdir -p /home/bob/.ssh") // Create the SSH config directory
                        .entryPoint("/entrypoint.sh") //
                        .build())) //
                                .withCopyFileToContainer(MountableFile.forClasspathResource(TEST_RESOURCES + "/bob_key.pub"),
                                        "/home/bob/.ssh/authorized_keys")
                                // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
                                .withCopyFileToContainer(
                                        MountableFile.forClasspathResource(TEST_RESOURCES + "/entrypoint.sh", 0x1ff),
                                        "/entrypoint.sh")
                                .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1)) //
                                .withExposedPorts(22) //
                                .withLogConsumer(new Slf4jLogConsumer(LOG));
        sshdContainer.start();
        try {
            FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(TEST_RESOURCES + "/bob_key");
            client.setKeyIdentityProvider(keyPairProvider);
            client.start();
            try (ClientSession session = client.connect("bob", sshdContainer.getHost(), sshdContainer.getMappedPort(22))
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue("Should authenticate", session.isAuthenticated());
                assertTrue("Unexpected session type " + session.getClass().getName(), session instanceof TestSession);
                assertEquals("Unexpected strict KEX usage", withStrictKex, ((TestSession) session).usesStrictKex());
                try (ChannelShell channel = session.createShellChannel()) {
                    channel.setOut(System.out);
                    channel.setErr(System.err);
                    channel.setStreaming(StreamingChannel.Streaming.Sync);
                    PipedOutputStream pos = new PipedOutputStream();
                    PipedInputStream pis = new PipedInputStream(pos);
                    channel.setIn(pis);
                    assertTrue("Could not open session", channel.open().await(DEFAULT_TIMEOUT));
                    LOG.info("writing some data...");
                    pos.write("\n\n".getBytes(StandardCharsets.UTF_8));
                    assertTrue("Channel should be open", channel.isOpen());
                    assertTrue(session.reExchangeKeys().verify(CONNECT_TIMEOUT).isDone());
                    assertTrue("Channel should be open", channel.isOpen());
                    LOG.info("writing some data...");
                    pos.write("\n\n".getBytes(StandardCharsets.UTF_8));
                    assertTrue("Channel should be open", channel.isOpen());
                    channel.close(true);
                }
            }
        } finally {
            sshdContainer.stop();
        }
    }

    // Subclass ClientSessionImpl to get access to the strictKex flag.

    private static class TestSessionFactory extends SessionFactory {

        TestSessionFactory(ClientFactoryManager client) {
            super(client);
        }

        @Override
        protected ClientSessionImpl doCreateSession(IoSession ioSession) throws Exception {
            return new TestSession(getClient(), ioSession);
        }
    }

    private static class TestSession extends ClientSessionImpl {

        TestSession(ClientFactoryManager client, IoSession ioSession) throws Exception {
            super(client, ioSession);
        }

        boolean usesStrictKex() {
            return strictKex;
        }
    }
}
