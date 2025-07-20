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
package org.apache.sshd.sftp.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers(disabledWithoutDocker = true)
class OpenSshTest extends JUnitTestSupport {

    private static final String RESOURCES = "/" + OpenSshTest.class.getPackage().getName().replace('.', '/');

    @Container
    static GenericContainer<?> server = new GenericContainer<>("atmoz/sftp:alpine") //
            .withEnv("SFTP_USERS", "foo::::upload")
            // Set it up for pubkey auth
            .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/rsa_key.pub"),
                    "/home/foo/.ssh/keys/id_rsa.pub")
            // Give it static known host keys!
            .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/ed25519_key", 0x180),
                    "/etc/ssh/ssh_host_ed25519_key")
            .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/rsa_key", 0x180),
                    "/etc/ssh/ssh_host_rsa_key")
            .withExposedPorts(22);

    private SshClient client;

    @BeforeEach
    void setUp() throws Exception {
        client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier((s, a, k) -> true);
        // Load the user key
        try (InputStream in = this.getClass().getResourceAsStream(RESOURCES + "/rsa_key")) {
            Iterable<KeyPair> clientKeys = SecurityUtils.loadKeyPairIdentities(null, null, in, null);
            client.setKeyIdentityProvider(s -> clientKeys);
        }
        client.start();
    }

    @AfterEach
    void teardown() {
        if (client != null) {
            client.stop();
        }
    }

    @Test // GH-774
    void copyByReadWrite() throws Exception {
        // Size matters; with only 1MB GH-774 is not reproducible. Probably the size needs to be larger than the channel
        // window (2MB by default).
        byte[] expected = new byte[8 * 1024 * 1024];

        Factory<? extends Random> factory = client.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);

        try (ClientSession sshSession = client.connect("foo", server.getHost(), server.getMappedPort(22)).verify()
                .getClientSession()) {
            sshSession.auth().verify(2000);
            try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(sshSession)) {
                // Copy some data onto the server
                try (InputStream in = new ByteArrayInputStream(expected);
                     OutputStream out = sftp.write("upload/file.bin", SftpClient.OpenMode.Create,
                             SftpClient.OpenMode.Write)) {
                    IoUtils.copy(in, out);
                }
                try (InputStream in = sftp.read("upload/file.bin");
                     OutputStream out = sftp.write("upload/file.new", SftpClient.OpenMode.Create,
                             SftpClient.OpenMode.Write)) {
                    IoUtils.copy(in, out);
                }
                byte[] actual;
                try (InputStream in = sftp.read("upload/file.new");
                     ByteArrayOutputStream buf = new ByteArrayOutputStream(expected.length)) {
                    byte[] data = new byte[4096];
                    for (int n = 0; n >= 0;) {
                        n = in.read(data, 0, data.length);
                        if (n > 0) {
                            buf.write(data, 0, n);
                        }
                    }
                    actual = buf.toByteArray();
                }
                assertArrayEquals(expected, actual);
            }
        }
    }

}
