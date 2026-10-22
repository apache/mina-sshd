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
package org.apache.sshd.client.kex;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.AbstractContainerTestBase;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;

/**
 * Tests pure ML-DSA host keys and user keys against the OQS-OpenSSH image built from {@code docker/oqs-openssh}.
 *
 * <p>
 * The image offers only pure ML-KEM key exchanges by default. Until MINA SSHD supports them, the container is started
 * with the hybrid {@code mlkem768x25519-sha256}, which is built into the OQS-OpenSSH binary.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
class OqsOpenSshMlDsaTest extends AbstractContainerTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(OqsOpenSshMlDsaTest.class);

    @Container
    static GenericContainer<?> sshdContainer = new GenericContainer<>(DockerImageName.parse(OQS_OPENSSH_IMAGE))
            .withCommand("-o", "KexAlgorithms=mlkem768x25519-sha256")
            .withExposedPorts(22)
            .waitingFor(Wait.forLogMessage(".*Server listening on.*port 22.*\\n", 1))
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void hostKeyAndPublicKeyAuthentication(MLDSAParameterSets params) throws Exception {
        Assumptions.assumeTrue(BuiltinDHFactories.mlkem768x25519.isSupported(), "mlkem768x25519 is not supported");
        BuiltinSignatures signature = BuiltinSignatures.fromFactoryName(params.getSshName());
        Assumptions.assumeTrue(signature != null && signature.isSupported(), params.getSshName() + " is not supported");

        // The host key as the server itself reports it.
        String hostKeyFile = "/etc/ssh/ssh_host_mldsa" + params.getSshName().substring("ssh-mldsa-".length()) + "_key.pub";
        String expectedHostKey = sshdContainer.execInContainer("cat", hostKeyFile).getStdout().trim();
        PublicKey expected = PublicKeyEntry.parsePublicKeyEntry(expectedHostKey).resolvePublicKey(null, null, null);

        // The user key is generated in memory and installed in the container.
        KeyPair userKey = SecurityUtils.getKeyPairGenerator(params.getJceName()).generateKeyPair();
        String authorizedKey = PublicKeyEntry.toString(userKey.getPublic());
        installAuthorizedKey(authorizedKey);

        AtomicReference<PublicKey> seen = new AtomicReference<>();
        SshClient client = setupTestClient();
        client.setKeyExchangeFactories(
                Collections.singletonList(ClientBuilder.DH2KEX.apply(BuiltinDHFactories.mlkem768x25519)));
        client.setSignatureFactories(Collections.singletonList(signature));
        client.setServerKeyVerifier((session, address, key) -> {
            seen.set(key);
            return true;
        });
        client.start();
        try (ClientSession session = client
                .connect("test", sshdContainer.getHost(), sshdContainer.getMappedPort(22))
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPublicKeyIdentity(userKey);
            session.auth().verify(AUTH_TIMEOUT);
            assertTrue(session.isAuthenticated(), "Not authenticated with " + params.getSshName());
        } finally {
            client.stop();
        }
        assertEquals(expected, seen.get(), "Host key mismatch for " + params.getSshName());
    }

    private static void installAuthorizedKey(String line) throws Exception {
        String script = "mkdir -p /home/test/.ssh && cat > /home/test/.ssh/authorized_keys"
                        + " && chown -R test /home/test/.ssh && chmod 700 /home/test/.ssh"
                        + " && chmod 600 /home/test/.ssh/authorized_keys";
        byte[] data = (line + "\n").getBytes(StandardCharsets.UTF_8);
        String encoded = java.util.Base64.getEncoder().encodeToString(data);
        org.testcontainers.containers.Container.ExecResult result
                = sshdContainer.execInContainer("sh", "-c", "echo " + encoded + " | base64 -d | (" + script + ")");
        assertEquals(0, result.getExitCode(), result.getStderr());
    }
}
