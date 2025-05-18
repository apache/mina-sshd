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

package org.apache.sshd.client.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
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

@Testcontainers(disabledWithoutDocker = true)
public class ClientOpenSSHCertificatesTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ClientOpenSSHCertificatesTest.class);

    private static final String TEST_KEYS = "org/apache/sshd/testkeys/";

    private static final String TEST_RESOURCES = "org/apache/sshd/docker";

    /**
     * This will build a new Docker image once per test class instance <br/>
     * <br/>
     * The {@link ImageFromDockerfile#withFileFromClasspath} calls will build up an in-memory tar filesystem that is
     * sent to the docker daemon for image building from assets on the classpath, making this all JVM classpath
     * friendly. <br/>
     * <br/>
     * The Docker image built will run a sshd instance managed by supervisord that has:
     *
     * <ul>
     * <li>Two users: user01, user02 with:
     * <ul>
     * <li>Passwords "password01" and "password02"</li>
     * <li>An authorized_keys file with a pub key for the included suite of keypairs (all current variants)</li>
     * </ul>
     * </li>
     * <li>A CA public key configured in sshd_config for the TrustedUserCAKeys option (for client cert publickey
     * auth)</li>
     * <li>Two available host keypairs host01 and host02 (selected by env var SSH_HOST_KEY)</li>
     * </ul>
     **/
    @Container
    static GenericContainer<?> sshdContainer = new GenericContainer<>(
            new ImageFromDockerfile().withDockerfileFromBuilder(builder -> builder.from("alpine:3.19") //
                    .run("apk --update add openssh openssh-server") // Install
                    .run("rm -rf /var/cache/apk/*") // Clear cache
                    .run("addgroup customusers") // Give our users a group
                    .run("adduser -D user01 -G customusers") // Create a user
                    .run("adduser -D user02 -G customusers") // Create another one
                    .run("passwd -u user01") // Unlock, but...
                    .run("passwd -u user02") // ... don't set passwords
                    .run("mkdir -p /keys/user/user01") // Directories for...
                    .run("mkdir -p /keys/user/user02") // ... the authorized keys
                    .run("echo 'user01:password01' | chpasswd") // Passwords for...
                    .run("echo 'user02:password02' | chpasswd") // ...both users
                    .entryPoint("/entrypoint.sh") //
                    .build())) //
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_RESOURCES + "/sshd_config"), "/etc/ssh/sshd_config")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_KEYS + "/user/user01_authorized_keys"),
                    "/keys/user/user01/authorized_keys")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_KEYS + "/user/user02_authorized_keys"),
                    "/keys/user/user02/authorized_keys")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_KEYS + "/host/host01"), "/keys/host/host01")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(
                            TEST_KEYS + "/host/host01" + PublicKeyEntry.PUBKEY_FILE_SUFFIX),
                    "/keys/host/host01" + PublicKeyEntry.PUBKEY_FILE_SUFFIX)
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_KEYS + "/host/host02"), "/keys/host/host02")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(
                            TEST_KEYS + "/host/host02" + PublicKeyEntry.PUBKEY_FILE_SUFFIX),
                    "/keys/host/host02" + PublicKeyEntry.PUBKEY_FILE_SUFFIX)
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(
                            TEST_KEYS + "/ca/ca" + PublicKeyEntry.PUBKEY_FILE_SUFFIX),
                    "/ca" + PublicKeyEntry.PUBKEY_FILE_SUFFIX)
            // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource(TEST_RESOURCES + "/sshd_certs.sh", 0x1ff),
                    "/entrypoint.sh")
            // must be set to "/keys/host/host01" or "/keys/host/host02"
            .withEnv("SSH_HOST_KEY", "/keys/host/host01") //
            .waitingFor(Wait.forLogMessage(".*Server listening on.*port 22.*\\n", 1))//
            .withExposedPorts(22) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    private String privateKeyName;

    public void initClientOpenSSHCertificatesTest(String keyName) {
        privateKeyName = keyName;
    }

    @BeforeAll
    static void ensureBC() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }

    public static Iterable<? extends String> privateKeyParams() {
        return Arrays.asList(
                "user01_rsa_sha2_256_2048",
                "user01_rsa_sha2_512_2048",
                "user01_rsa_sha2_256_4096",
                "user01_rsa_sha2_512_4096",
                "user01_ed25519",
                "user01_ecdsa_256",
                "user01_ecdsa_384",
                "user01_ecdsa_521");
    }

    private String getPrivateKeyResource() {
        return TEST_KEYS + "user/" + privateKeyName;
    }

    private String getCertificateResource() {
        return getPrivateKeyResource() + "-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
    }

    @MethodSource("privateKeyParams")
    @ParameterizedTest(name = "key: {0}, cert: {0}-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX)
    public void clientCertAuth(String keyName) throws Exception {

        initClientOpenSSHCertificatesTest(keyName);

        try (InputStream certInputStream
                = Thread.currentThread().getContextClassLoader().getResourceAsStream(getCertificateResource())) {

            final byte[] certBytes = IoUtils.toByteArray(certInputStream);
            final String certLine = GenericUtils.replaceWhitespaceAndTrim(new String(certBytes, StandardCharsets.UTF_8));

            final PublicKeyEntry certPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(certLine);
            final PublicKey certPublicKey = certPublicKeyEntry.resolvePublicKey(null, null, null);

            final FileKeyPairProvider keyPairProvider
                    = CommonTestSupportUtils.createTestKeyPairProvider(getPrivateKeyResource());

            final KeyPair keypair = keyPairProvider.loadKeys(null).iterator().next();

            final PrivateKey privateKey = keypair.getPrivate();

            final SshClient client = setupTestClient();

            client.setKeyIdentityProvider(new KeyIdentityProvider() {
                @Override
                public Iterable<KeyPair> loadKeys(SessionContext session) throws IOException, GeneralSecurityException {

                    // build a keypair with the PrivateKey and the certificate as the PublicKey
                    final KeyPair certKeypair = new KeyPair(certPublicKey, privateKey);

                    final List<KeyPair> list = new ArrayList<>();
                    list.add(certKeypair);

                    return list;
                }
            });

            client.start();

            final Integer actualPort = sshdContainer.getMappedPort(22);
            final String actualHost = sshdContainer.getHost();

            try (ClientSession session = client.connect("user01", actualHost, actualPort).verify(CONNECT_TIMEOUT)
                    .getSession()) {
                session.auth().verify(AUTH_TIMEOUT);
            } catch (Exception e) {
                System.err.println("Container logs:");
                System.err.print(sshdContainer.getLogs());
                throw e;
            } finally {
                client.stop();
            }

        }

    }

}
