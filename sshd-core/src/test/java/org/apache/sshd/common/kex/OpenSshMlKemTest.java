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
package org.apache.sshd.common.kex;

import java.security.Security;
import java.util.Collections;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Test ciphers against OpenSSH. Force resetting ciphers every time to verify that they are res-initialized correctly.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Tag("ContainerTestCase")
@Testcontainers
class OpenSshMlKemTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSshMlKemTest.class);

    // Re-use an already defined key
    private static final String TEST_RESOURCES = "org/apache/sshd/common/kex/extensions/client";

    @Container
    GenericContainer<?> sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfileFromBuilder(builder -> builder.from("alpine:3.21") //
                    .run("apk --update add openssh-server") // Installs OpenSSH 9.9
                    // Enable deprecated ciphers
                    .run("ssh-keygen -A") // Generate multiple host keys
                    .run("adduser -D bob") // Add a user
                    .run("echo 'bob:passwordBob' | chpasswd") // Give it a password to unlock the user
                    .run("mkdir -p /home/bob/.ssh") // Create the SSH config directory
                    .entryPoint("/entrypoint.sh") // Sets bob as owner of anything under /home/bob and launches sshd
                    .build())) //
            .withCopyFileToContainer(MountableFile.forClasspathResource(TEST_RESOURCES + "/bob_key.pub"),
                    "/home/bob/.ssh/authorized_keys")
            // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_RESOURCES + "/entrypoint.sh", 0x1ff),
                    "/entrypoint.sh")
            .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1)).withExposedPorts(22) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    @BeforeAll
    static void registerBouncyCastleProviderIfNecessary() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void mlkem768x25519() throws Exception {
        Assumptions.assumeTrue(BuiltinDHFactories.mlkem768x25519.isSupported());
        FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(TEST_RESOURCES + "/bob_key");
        SshClient client = setupTestClient();
        client.setKeyIdentityProvider(keyPairProvider);
        client.setKeyExchangeFactories(
                Collections.singletonList(ClientBuilder.DH2KEX.apply(BuiltinDHFactories.mlkem768x25519)));
        client.start();

        Integer actualPort = sshdContainer.getMappedPort(22);
        String actualHost = sshdContainer.getHost();
        try (ClientSession session = client.connect("bob", actualHost, actualPort).verify(CONNECT_TIMEOUT).getSession()) {
            AuthFuture authed = session.auth().verify(AUTH_TIMEOUT);
            assertTrue(authed.isDone() && authed.isSuccess());
        } finally {
            client.stop();
        }
    }
}
