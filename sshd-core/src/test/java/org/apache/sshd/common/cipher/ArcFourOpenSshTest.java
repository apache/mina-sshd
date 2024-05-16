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
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.ContainerTestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/**
 * Test RC4 ciphers against OpenSSH 7.4.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@RunWith(Parameterized.class)
@Category(ContainerTestCase.class)
public class ArcFourOpenSshTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ArcFourOpenSshTest.class);

    // Re-use an already defined key
    private static final String TEST_RESOURCES = "org/apache/sshd/common/kex/extensions/client";

    @Rule
    public GenericContainer<?> sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfileFromBuilder(builder -> builder //
                    // Use old CentOS to get an OpenSSH that supports arcfour
                    .from("centos:7.9.2009") //
                    .run("yum install -y openssh-server") // Installs OpenSSH 7.4
                    // Enable deprecated ciphers
                    .run("echo 'Ciphers +arcfour128,arcfour256' >> /etc/ssh/sshd_config")
                    .run("echo 'MACs +hmac-md5,hmac-md5-96,hmac-sha1,hmac-sha1-96' >> /etc/ssh/sshd_config")
                    .run("/usr/sbin/sshd-keygen") // Generate multiple host keys
                    .run("adduser bob") // Add a user
                    .run("echo \\\"123qweASD\\\" | passwd bob --stdin") // Give it a password to unlock the user
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

    private final BuiltinCiphers builtIn;

    private final BuiltinMacs mac;

    public ArcFourOpenSshTest(String providerName, BuiltinCiphers factory, String name, BuiltinMacs mac, String macName) {
        this.builtIn = factory;
        this.mac = mac;
        if ("BC".equals(providerName)) {
            registerBouncyCastleProviderIfNecessary();
        }
    }

    private static void registerBouncyCastleProviderIfNecessary() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static void addCipher(BuiltinCiphers cipherFactory, List<Object[]> items) {
        for (BuiltinMacs mac : BuiltinMacs.VALUES) {
            items.add(new Object[] { "SunJCE", cipherFactory, cipherFactory.getName(), mac, mac.getName() });
            items.add(new Object[] { "BC", cipherFactory, cipherFactory.getName(), mac, mac.getName() });
        }
    }

    @SuppressWarnings("deprecation")
    @Parameters(name = "{2} - {4} - {0}")
    public static List<Object[]> getParameters() {
        List<Object[]> items = new ArrayList<>();
        addCipher(BuiltinCiphers.arcfour128, items);
        addCipher(BuiltinCiphers.arcfour256, items);
        return items;
    }

    @Test
    public void testConnection() throws Exception {
        FileKeyPairProvider keyPairProvider = CommonTestSupportUtils.createTestKeyPairProvider(TEST_RESOURCES + "/bob_key");
        SshClient client = setupTestClient();
        client.setKeyIdentityProvider(keyPairProvider);
        client.setCipherFactories(Collections.singletonList(builtIn));
        client.setMacFactories(Collections.singletonList(mac));
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
