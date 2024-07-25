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
package org.apache.sshd.common.forward;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.forward.ForwardedTcpipFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test setup: run a gRPC server on localhost; run an Apache MINA sshd server on localhost. Run an OpenSSH client in a
 * container, set up to remote forward a port on the SSH server to the gRPC server. Then connect to the gRPC server via
 * this SSH tunnel (i.e., connect to the chosen port on localhost). This is going to tunnel the request into the
 * container, where the SSH client will connect to the gRPC server. We send a simple HTTP 1.1 GET / request. The gRPC
 * server doesn't understand that, sends back an error message and closes the connection.
 * <p>
 * This connection closure is propagated via an EOF through the tunnel, and on the other end must be propagated by
 * half-closing the socket (shutting down its output), otherwise the client connected to the forwarded port on localhost
 * will hang.
 * </p>
 * <p>
 * The test is re-run with different ways to specify the remote port forwarding, including wildcard addresses. The port
 * is always zero, letting the server choose any unused port. With a fixed port number, the test might fail if that
 * fixed port was already used in the CI environment.
 * </p>
 *
 * @see <a href="https://issues.apache.org/jira/browse/SSHD-1055">SSHD-1055</a>
 * @see <a href="https://issues.apache.org/jira/browse/SSHD-1269">SSHD-1269</a>
 */
@Tag("ContainerTestCase")
public class PortForwardingWithOpenSshTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(PortForwardingWithOpenSshTest.class);

    // We re-use a key from the ClientOpenSSHCertificatesTest.
    private static final String TEST_KEYS = "org/apache/sshd/client/opensshcerts/user";

    @TempDir
    File tmp;

    private Server gRpc;
    private int gRpcPort;

    private SshServer sshd;
    private int sshPort;

    private CountDownLatch forwardingSetup;
    private int forwardedPort;

    private String portToForward;

    public void initPortForwardingWithOpenSshTest(String portToForward) {
        this.portToForward = portToForward;
    }

    /**
     * Uses different ways to specify the remote port forwarding.
     *
     * @return the remote port specifications to use
     * @see    <a href="https://issues.apache.org/jira/browse/SSHD-1269">SSHD-1269</a>
     */
    public static String[] portSpecifications() {
        return new String[] { "127.0.0.1:0", "0.0.0.0:0", "0", "localhost:0" };
    }

    @BeforeEach
    void startServers() throws Exception {
        // gRPC server
        gRpc = ServerBuilder.forPort(0).build();
        CountDownLatch gRpcStarted = new CountDownLatch(1);
        Thread gRpcRunner = new Thread(() -> {
            try {
                gRpc.start();
                gRpcPort = gRpc.getPort();
                gRpcStarted.countDown();
                gRpc.awaitTermination();
            } catch (Exception e) {
                // Nothing
            }
        });
        gRpcRunner.start();
        gRpcStarted.await();
        LOG.info("gRPC running on port {}", gRpcPort);
        // sshd server
        forwardingSetup = new CountDownLatch(1);
        sshd = CoreTestSupportUtils.setupTestServer(PortForwardingWithOpenSshTest.class);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.setForwarderFactory(new DefaultForwarderFactory() {
            @Override
            public Forwarder create(ConnectionService service) {
                Forwarder forwarder = new DefaultForwarder(service) {
                    @Override
                    public SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
                        SshdSocketAddress result = super.localPortForwardingRequested(local);
                        forwardedPort = result == null ? -1 : result.getPort();
                        forwardingSetup.countDown();
                        return result;
                    }
                };
                forwarder.addPortForwardingEventListenerManager(this);
                return forwarder;
            }
        });
        sshd.setChannelFactories(
                Arrays.asList(ChannelSessionFactory.INSTANCE, DirectTcpipFactory.INSTANCE, ForwardedTcpipFactory.INSTANCE));
        sshd.start();
        sshPort = sshd.getPort();
    }

    @AfterEach
    void teardownServers() throws Exception {
        try {
            gRpc.shutdownNow();
        } finally {
            sshd.stop();
        }
    }

    @MethodSource("portSpecifications")
    @ParameterizedTest(name = "{0}")
    public void forwardingWithConnectionClose(String portToForward) throws Exception {
        initPortForwardingWithOpenSshTest(portToForward);
        // Write the entrypoint file. From within the test container, the host running the container and our two servers
        // is accessible as "host.testcontainers.internal".
        File entryPoint = File.createTempFile("junit", null, tmp);
        String lines = "#!/bin/sh\n" //
                       + "\n" //
                       + "chmod 0600 /root/.ssh/*\n" //
                       + "/usr/bin/ssh -o 'ExitOnForwardFailure yes' -o 'StrictHostKeyChecking off' -vvv -p " + sshPort //
                       + " -x -N -T -R " + portToForward + ":host.testcontainers.internal:" + gRpcPort //
                       + " bob@host.testcontainers.internal\n";
        Files.write(entryPoint.toPath(), lines.getBytes(StandardCharsets.US_ASCII));
        // Create the container
        @SuppressWarnings("resource")
        GenericContainer<?> sshdContainer = new GenericContainer<>(
                new ImageFromDockerfile().withDockerfileFromBuilder(builder -> builder.from("alpine:3.16") //
                        .run("apk --update add openssh openssh-server") // Installs OpenSSH 9.0
                        .run("mkdir -p /root/.ssh") // Create the SSH config directory
                        .entryPoint("/entrypoint.sh") //
                        .build())) //
                .withCopyFileToContainer(MountableFile.forClasspathResource(TEST_KEYS + "/user01_ed25519"),
                        "/root/.ssh/id_ed25519")
                .withCopyFileToContainer(MountableFile.forClasspathResource(TEST_KEYS + "/user01_ed25519.pub"),
                        "/root/.ssh/id_ed25519.pub")
                // Spotbugs doesn't like 0777, so use hex
                .withCopyFileToContainer(MountableFile.forHostPath(entryPoint.getPath(), 0x1ff),
                        "/entrypoint.sh")
                .withAccessToHost(true) //
                .waitingFor(Wait.forLogMessage(".*forwarding_success.*\n", 1))
                .withLogConsumer(new Slf4jLogConsumer(LOG));
        try {
            Testcontainers.exposeHostPorts(sshPort, gRpcPort);
            sshdContainer.start();
            forwardingSetup.await();
            assertTrue(forwardedPort > 0, "Server should listen on port");
            LOG.info("sshd server listening for forwarding on port {}", forwardedPort);
            // Connect to the forwarded port. We should end up connecting to the gRPC server, which will balk
            // because it expects HTTP 2, and disconnect.
            List<String> content = new ArrayList<>();
            try (Socket socket = new Socket("127.0.0.1", forwardedPort)) {
                try (OutputStream out = socket.getOutputStream(); InputStream in = socket.getInputStream()) {
                    String command = "GET / HTTP 1.1\r\n" //
                                     + "Connection: keep-alive\r\n" //
                                     + "Host: 127.0.0.1\r\n" //
                                     + "\r\n";
                    out.write(command.getBytes(StandardCharsets.US_ASCII));
                    byte[] buf = new byte[1024];
                    for (int n = 0; n >= 0;) {
                        n = in.read(buf, 0, buf.length);
                        if (n > 0) {
                            String data = new String(buf, 0, n, StandardCharsets.ISO_8859_1);
                            content.add(data);
                        }
                    }
                }
            }
            assertFalse(content.isEmpty(), "Expected data");
            String last = content.get(content.size() - 1);
            assertTrue(last.endsWith(
                    "HTTP/2 client preface string missing or corrupt. Hex dump for received bytes: 474554202f204854545020312e310d0a436f6e6e65637469"),
                    "Unexpected data: " + last);
        } finally {
            sshdContainer.stop();
        }
    }
}
