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

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;

import org.apache.sshd.AbstractContainerTestBase;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.ContainerFetchException;
import org.testcontainers.containers.ContainerLaunchException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Tests interoperability with the prebuilt OQS-OpenSSH image.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
class OqsOpenSshInteropTest extends AbstractContainerTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(OqsOpenSshInteropTest.class);

    // Use the SHA of the multi-arch image
    private static final String OQS_OPENSSH_IMAGE
            = "ghcr.io/apache/mina-sshd-oqs-openssh:dev@sha256:b422cf129003bba8bd712812bb303ad1440fb34de64a219148db581660d8d243";

    @Test
    void hybridConnectivity() throws Exception {
        // Control to verify the container works
        DHFactory factory = BuiltinDHFactories.mlkem768x25519;
        Assumptions.assumeTrue(factory.isSupported(), "Hybrid ML-KEM is not supported by this provider");
        connect(factory);
    }

    @ParameterizedTest
    @ValueSource(strings = { "mlkem512-sha256", "mlkem768-sha256", "mlkem1024-sha384" })
    void pureMlKem768(String kexName) throws Exception {
        DHFactory factory = BuiltinDHFactories.fromFactoryName(kexName);
        assertNotNull(factory, "Factory should exist");
        Assumptions.assumeTrue(factory.isSupported(), "Pure ML-KEM " + kexName + " is not supported by this provider");
        connect(factory);
    }

    private static boolean isImageUnavailable(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof ContainerFetchException || cause instanceof UnknownHostException) {
                return true;
            }
            String message = cause.getMessage();
            if (message != null) {
                message = message.toLowerCase(Locale.ROOT);
                if (message.contains("manifest unknown") || message.contains("pull access denied")
                        || message.contains("unauthorized") || message.contains("authentication required")) {
                    return true;
                }
            }
        }
        return false;
    }

    private void connect(DHFactory factory) throws Exception {
        Assumptions.assumeTrue(BuiltinSignatures.ed25519.isSupported(), "Ed25519 host keys are not supported");
        // Start manually so unsupported algorithms skip before pulling or starting the image.
        try (GenericContainer<?> server = new GenericContainer<>(DockerImageName.parse(OQS_OPENSSH_IMAGE))
                .withExposedPorts(22)
                .withEnv("TEST_PASSWORD", "test")
                // The image defaults to pure KEX only. Override it for the hybrid connectivity test.
                .withCommand("-o", "KexAlgorithms=" + factory.getName() /* , "-o", "LogLevel=DEBUG3" */)
                .waitingFor(Wait.forLogMessage(".*Server listening on.*port 22.*\\n", 1))
                .withStartupTimeout(Duration.ofMinutes(2))
                .withLogConsumer(new Slf4jLogConsumer(LOG))) {
            try {
                server.start();
            } catch (ContainerLaunchException | ContainerFetchException e) {
                if (!isImageUnavailable(e)) {
                    throw e;
                }
                Assumptions.abort("OQS-OpenSSH image not available: " + e.getMessage());
            }
            SshClient client = setupTestClient();
            client.setKeyExchangeFactories(Collections.singletonList(ClientBuilder.DH2KEX.apply(factory)));
            client.setSignatureFactories(Collections.singletonList(BuiltinSignatures.ed25519));
            client.start();
            try (ClientSession session = client.connect("test", server.getHost(), server.getMappedPort(22))
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity("test");
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated(), "Password authentication failed");
                assertEquals(factory.getName(), session.getNegotiatedKexParameter(KexProposalOption.ALGORITHMS));
                assertEquals("CONNECTED_OK", session.executeRemoteCommand("echo CONNECTED_OK", DEFAULT_TIMEOUT).trim());
            } finally {
                client.stop();
            }
        }
    }
}
