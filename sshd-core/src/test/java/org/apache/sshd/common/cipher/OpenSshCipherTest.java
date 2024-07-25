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
package org.apache.sshd.common.cipher;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test ciphers against OpenSSH. Force resetting ciphers every time to verify that they are res-initialized correctly.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Tag("ContainerTestCase")
@Testcontainers
public class OpenSshCipherTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSshCipherTest.class);

    // Re-use an already defined key
    private static final String TEST_RESOURCES = "org/apache/sshd/common/kex/extensions/client";

    @Container
    GenericContainer<?> sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfileFromBuilder(builder -> builder.from("alpine:3.19") //
                    .run("apk --update add openssh-server") // Installs OpenSSH
                    // Enable deprecated ciphers
                    .run("echo 'Ciphers +aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc' >> /etc/ssh/sshd_config")
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

    private String providerName;

    private BuiltinCiphers builtIn;

    public void initOpenSshCipherTest(String providerName, BuiltinCiphers factory, String name) {
        this.providerName = providerName;
        this.builtIn = factory;
        if ("BC".equals(providerName)) {
            registerBouncyCastleProviderIfNecessary();
        }
    }

    @BeforeEach
    void changeCipher() {
        BaseCipher.factory = t -> javax.crypto.Cipher.getInstance(t, providerName);
        BaseCipher.alwaysReInit = true;
    }

    @AfterEach
    void resetCipher() {
        BaseCipher.factory = SecurityUtils::getCipher;
        BaseCipher.alwaysReInit = false;
    }

    private static void registerBouncyCastleProviderIfNecessary() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static void addCipher(BuiltinCiphers cipherFactory, List<Object[]> items) {
        items.add(new Object[] { "SunJCE", cipherFactory, cipherFactory.getName() });
        items.add(new Object[] { "BC", cipherFactory, cipherFactory.getName() });
    }

    @SuppressWarnings("deprecation")
    public static List<Object[]> getParameters() {
        List<Object[]> items = new ArrayList<>();
        addCipher(BuiltinCiphers.tripledescbc, items);
        addCipher(BuiltinCiphers.aes128cbc, items);
        addCipher(BuiltinCiphers.aes128ctr, items);
        addCipher(BuiltinCiphers.aes128gcm, items);
        addCipher(BuiltinCiphers.aes192cbc, items);
        addCipher(BuiltinCiphers.aes192ctr, items);
        addCipher(BuiltinCiphers.aes256cbc, items);
        addCipher(BuiltinCiphers.aes256ctr, items);
        addCipher(BuiltinCiphers.aes256gcm, items);
        addCipher(BuiltinCiphers.cc20p1305_openssh, items);
        return items;
    }

    @MethodSource("getParameters")
    @ParameterizedTest(name = "{2} - {0}")
    public void connection(String providerName, BuiltinCiphers factory, String name) throws Exception {
        initOpenSshCipherTest(providerName, factory, name);
        FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(TEST_RESOURCES + "/bob_key");
        SshClient client = setupTestClient();
        client.setKeyIdentityProvider(keyPairProvider);
        client.setCipherFactories(Collections.singletonList(builtIn));
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
