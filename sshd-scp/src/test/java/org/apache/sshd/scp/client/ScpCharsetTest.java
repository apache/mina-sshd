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
package org.apache.sshd.scp.client;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.scp.ScpModuleProperties;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests transferring a file named "äöü.txt" via SCP from a container that uses ISO-8859-15 as locale. The UTF-8 and
 * IOS-8859-15 encodings of these characters are different, so the file should not be found when the command is sent as
 * UTF-8, but should be found when sent as ISO-8859-1.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Tag("ContainerTestCase")
@Testcontainers
public class ScpCharsetTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ScpCharsetTest.class);

    private static final String TEST_RESOURCES = "org/apache/sshd/scp/client";

    @Container
    GenericContainer<?> sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
            // Alpine would be smaller and start faster, but it has no locales.
            .withDockerfileFromBuilder(builder -> builder.from("ubuntu:20.04") //
                    .run("apt-get update && apt-get install -y locales openssh-server") //
                    .run("mkdir -p /run/sshd") // sshd need a privilege separation directory
                    .run("locale-gen en_US.ISO-8859-15") // Add a non-UTF-8 locale
                    .run("useradd -ms /bin/bash bob") // Add a user
                    .run("mkdir -p /home/bob/.ssh") // Create the SSH config directory
                    .entryPoint("/entrypoint.sh") // Prepare environment, set locale, and launch
                    .build())) //
            .withCopyFileToContainer(MountableFile.forClasspathResource(TEST_RESOURCES + "/bob_key.pub"),
                    "/home/bob/.ssh/authorized_keys")
            // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_RESOURCES + "/entrypoint.sh", 0x1ff),
                    "/entrypoint.sh")
            .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1)).withExposedPorts(22) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    @TempDir
    File tmp;

    public ScpCharsetTest() {
        super();
    }

    @Test
    void isoLatin1() throws Exception {
        FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(TEST_RESOURCES + "/bob_key");
        SshClient client = setupTestClient();
        client.setKeyIdentityProvider(keyPairProvider);
        try {
            client.start();

            Integer actualPort = sshdContainer.getMappedPort(22);
            String actualHost = sshdContainer.getHost();
            try (ClientSession session = client.connect("bob", actualHost, actualPort).verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);
                ScpClientCreator.instance();
                ScpClient scpClient = ScpClientCreator.instance().createScpClient(session);
                File file1 = new File(tmp, "file1.txt");
                scpClient.download("file1.txt", file1.getAbsolutePath());
                assertEquals("test1\n",
                        new String(Files.readAllBytes(file1.toPath()), StandardCharsets.UTF_8),
                        "Unexpected content in file1.txt -> file1.txt");
                File file2 = new File(tmp, "file2.txt");
                // Somehow there's only a WARNING in the log? Maybe the exit code is handled wrongly... (1 is taken as a
                // warning, but for exit codes, probably any non-zero value is an error?) In any case this should fail;
                // we should not have a "file2" afterwards.
                try {
                    scpClient.download("äöü.txt", file2.getAbsolutePath());
                    assertFalse(file2.exists(), "No file2.txt expected");
                } catch (NoSuchFileException | FileNotFoundException | ScpException e) {
                    LOG.info("Expected failure for UTF-8 äöü: {}", e.toString());
                }
                // But this should work: (The container uses ISO-8859-15, but the only difference is the Euro sign.)
                ScpModuleProperties.SCP_OUTGOING_ENCODING.set(session, StandardCharsets.ISO_8859_1);
                scpClient.download("äöü.txt", file2.getAbsolutePath());
                assertEquals("test2\n",
                        new String(Files.readAllBytes(file2.toPath()), StandardCharsets.UTF_8),
                        "Unexpected content in file äöü.txt -> file2.txt");
            }
        } finally {
            client.stop();
        }
    }
}
