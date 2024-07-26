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
package org.apache.sshd.client.auth.pubkey;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.kex.extension.DefaultClientKexExtensionHandler;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.ContainerTestCase;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Category(ContainerTestCase.class)
public class HostBoundPubKeyAuthTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(HostBoundPubKeyAuthTest.class);

    // We re-use the keys (not the certificates) from the ClientOpenSSHCertificatesTest.
    private static final String TEST_KEYS = "org/apache/sshd/client/opensshcerts/user";

    private static final String TEST_RESOURCES = "org/apache/sshd/client/auth/pubkey";

    private static final Pattern EXPECTED_LOG_ENTRY = //
            Pattern.compile("\n.*debug2: userauth_pubkey: valid user bob attempting public key.*"
                            + "\r?\n.*debug3: userauth_pubkey: publickey-hostbound-v00@openssh.com have");

    @Rule
    public GenericContainer<?> sshdContainer = new GenericContainer<>(
            new ImageFromDockerfile().withDockerfileFromBuilder(builder -> builder.from("alpine:3.16")
                    .run("apk --update add openssh-server") // Installs OpenSSH 9.0
                    .run("ssh-keygen -A") // Generate multiple host keys
                    .run("adduser -D bob") // Add a user
                    .run("echo 'bob:passwordBob' | chpasswd") // Give it a password to unlock the user
                    .run("mkdir -p /home/bob/.ssh") // Create the SSH config directory
                    .entryPoint("/entrypoint.sh") // Sets bob as owner of anything under /home/bob and launches sshd
                    .build())) //
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_KEYS + "/user01_authorized_keys"),
                    "/home/bob/.ssh/authorized_keys")
            // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_RESOURCES + "/entrypoint.sh", 0x1ff),
                    "/entrypoint.sh")
            .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1))
            .withExposedPorts(22) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    private final String privateKeyName;

    public HostBoundPubKeyAuthTest(String privateKeyName) {
        this.privateKeyName = privateKeyName;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<? extends String> privateKeyParams() {
        return Arrays.asList( //
                "user01_rsa_sha2_512_2048", //
                "user01_rsa_sha2_512_4096", //
                "user01_ed25519", //
                "user01_ecdsa_256", //
                "user01_ecdsa_384", //
                "user01_ecdsa_521");
    }

    private String getPrivateKeyResource() {
        return TEST_KEYS + '/' + privateKeyName;
    }

    private void checkLog(String logs) {
        Matcher m = EXPECTED_LOG_ENTRY.matcher(logs);
        assertTrue("Expected server log message not found", m.find());
    }

    @Test
    public void testPubkeyAuth() throws Exception {
        FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(getPrivateKeyResource());
        SshClient client = setupTestClient();
        client.setKeyIdentityProvider(keyPairProvider);
        client.start();

        Integer actualPort = sshdContainer.getMappedPort(22);
        String actualHost = sshdContainer.getHost();
        try (ClientSession session = client.connect("bob", actualHost, actualPort).verify(CONNECT_TIMEOUT).getSession()) {
            session.auth().verify(AUTH_TIMEOUT);
            assertEquals(Integer.valueOf(0), session.getAttribute(DefaultClientKexExtensionHandler.HOSTBOUND_AUTHENTICATION));
            checkLog(sshdContainer.getLogs());
        } finally {
            client.stop();
        }
    }
}
