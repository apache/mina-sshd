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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureSkECDSA;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

public class SkPubKeyAuthTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(SkPubKeyAuthTest.class);

    private static final String TEST_RESOURCES = "org/apache/sshd/docker";

    private boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    @Test
    void pubkeyAuthOpenSsh() throws Exception {
        Assumptions.assumeTrue(isDockerAvailable(), "Docker not available");
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair ecKeyPair = generator.generateKeyPair();
        ECPublicKey ecPubKey = ValidateUtils.checkInstanceOf(ecKeyPair.getPublic(), ECPublicKey.class,
                "Expected an ECPublicKey");
        SkEcdsaPublicKey fakeSkKey = new SkEcdsaPublicKey("ssh", false, false, ecPubKey);
        KeyPair fakeSkKeyPair = new KeyPair(fakeSkKey, ecKeyPair.getPrivate());
        StringBuilder sb = new StringBuilder("verify-required ");
        PublicKeyEntry.appendPublicKeyEntry(sb, fakeSkKey);
        Path authorizedKeyFile = Files.createTempFile("x", ".x");

        GenericContainer<?> sshdContainer = null;
        try {
            Files.write(authorizedKeyFile, Collections.singleton(sb.toString()));

            sshdContainer = new GenericContainer<>(new ImageFromDockerfile()
                    .withDockerfileFromBuilder(builder -> builder.from("alpine:3.24") //
                            .run("apk --update add openssh-server") //
                            .run("ssh-keygen -A") // Generate multiple host keys
                            .run("adduser -D bob") // Add a user
                            .run("echo 'bob:passwordBob' | chpasswd") // Give it a password to unlock the user
                            .run("mkdir -p /home/bob/.ssh") // Create the SSH config directory
                            .entryPoint("/entrypoint.sh") // Sets bob as owner of anything under /home/bob and launches sshd
                            .build())) //
                    .withCopyFileToContainer(MountableFile.forHostPath(authorizedKeyFile),
                            "/home/bob/.ssh/authorized_keys")
                    // entrypoint must be executable. Spotbugs doesn't like 0777, so use hex
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource(TEST_RESOURCES + "/sshd_bob.sh", 0x1ff),
                            "/entrypoint.sh")
                    .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*\\n", 1))
                    .withExposedPorts(22) //
                    .withLogConsumer(new Slf4jLogConsumer(LOG));
            sshdContainer.start();

            SshClient client = setupTestClient();
            client.setKeyIdentityProvider(KeyPairProvider.wrap(Collections.singleton(fakeSkKeyPair)));
            client.start();
            FakeSkKeySignatureFactory skSigner = new FakeSkKeySignatureFactory(fakeSkKey);
            String skKeyType = skSigner.getName();
            List<NamedFactory<Signature>> signatures = client.getSignatureFactories();
            List<NamedFactory<Signature>> replaced = new ArrayList<>();
            for (NamedFactory<Signature> s : signatures) {
                if (s.getName().equals(skKeyType)) {
                    replaced.add(skSigner);
                } else {
                    replaced.add(s);
                }
            }
            client.setSignatureFactories(replaced);

            Integer actualPort = sshdContainer.getMappedPort(22);
            String actualHost = sshdContainer.getHost();
            try (ClientSession session = client.connect("bob", actualHost, actualPort).verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated());
            } finally {
                client.stop();
            }
        } finally {
            if (sshdContainer != null) {
                sshdContainer.stop();
            }
            File f = authorizedKeyFile.toFile();
            if (!f.delete()) {
                f.deleteOnExit();
            }
        }
    }

    @Test
    void pubkeyAuth() throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator("EC");
        generator.initialize(256);
        KeyPair ecKeyPair = generator.generateKeyPair();
        ECPublicKey ecPubKey = ValidateUtils.checkInstanceOf(ecKeyPair.getPublic(), ECPublicKey.class,
                "Expected an ECPublicKey");
        SkEcdsaPublicKey fakeSkKey = new SkEcdsaPublicKey("ssh", false, false, ecPubKey);
        KeyPair fakeSkKeyPair = new KeyPair(fakeSkKey, ecKeyPair.getPrivate());
        StringBuilder sb = new StringBuilder("verify-required ");
        PublicKeyEntry.appendPublicKeyEntry(sb, fakeSkKey);
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(sb.toString());

        SshServer server = CoreTestSupportUtils.setupTestServer(this.getClass());
        server.setPublickeyAuthenticator(PublickeyAuthenticator.fromAuthorizedEntries("test", null,
                Collections.singleton(entry), PublicKeyEntryResolver.FAILING));
        server.start();

        try {
            SshClient client = setupTestClient();
            client.setKeyIdentityProvider(KeyPairProvider.wrap(Collections.singleton(fakeSkKeyPair)));
            client.start();
            FakeSkKeySignatureFactory skSigner = new FakeSkKeySignatureFactory(fakeSkKey);
            String skKeyType = skSigner.getName();
            List<NamedFactory<Signature>> signatures = client.getSignatureFactories();
            List<NamedFactory<Signature>> replaced = new ArrayList<>();
            for (NamedFactory<Signature> s : signatures) {
                if (s.getName().equals(skKeyType)) {
                    replaced.add(skSigner);
                } else {
                    replaced.add(s);
                }
            }
            client.setSignatureFactories(replaced);

            try (ClientSession session = client.connect("bob", TEST_LOCALHOST, server.getPort()).verify(CONNECT_TIMEOUT)
                    .getSession()) {
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated());
            } finally {
                client.stop();
            }
        } finally {
            server.stop();
        }
    }

    private static class FakeSkKeySignatureFactory implements NamedFactory<Signature> {

        private final SkEcdsaPublicKey pub;

        FakeSkKeySignatureFactory(SkEcdsaPublicKey pub) {
            this.pub = pub;
        }

        @Override
        public Signature create() {
            return new SignatureSkECDSA() {

                private PrivateKey priv;

                @Override
                public void initSigner(SessionContext session, PrivateKey key) {
                    this.priv = key;
                    try {
                        this.challengeDigest = SecurityUtils.getMessageDigest("SHA-256");
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException(e);
                    }
                }

                @Override
                public byte[] sign(SessionContext session) {
                    try {
                        byte[] sigBlobHash = challengeDigest.digest();

                        byte[] appHash = challengeDigest.digest(pub.getAppName().getBytes(StandardCharsets.UTF_8));

                        Signature signer = BuiltinSignatures.nistp256.create();
                        signer.initSigner(null, priv);
                        signer.update(null, appHash);
                        byte[] uint = new byte[4];
                        uint[0] = 5; // touch & verified
                        signer.update(null, uint, 0, 1);
                        BufferUtils.putUInt(42, uint); // Counter
                        signer.update(null, uint);
                        signer.update(null, sigBlobHash);
                        byte[] rawSignature = signer.sign(null);

                        ByteArrayBuffer skSignature = new ByteArrayBuffer();
                        skSignature.putBytes(rawSignature);
                        skSignature.putByte((byte) 5);
                        skSignature.putUInt(42); // Counter
                        return skSignature.getCompactData();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            };
        }

        @Override
        public String getName() {
            return pub.getKeyType();
        }

    }
}
