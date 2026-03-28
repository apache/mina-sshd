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

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers(disabledWithoutDocker = true)
class ProFtpdTest extends JUnitTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(ProFtpdTest.class);

    private static final String RESOURCES = "/" + ProFtpdTest.class.getPackage().getName().replace('.', '/');

    @Container
    static GenericContainer<?> server = new GenericContainer<>(
            new ImageFromDockerfile().withDockerfileFromBuilder(builder -> builder
                    // latest as of 2026-03-27
                    .from("instantlinux/proftpd@sha256:3de65108bc60548c575eb3dd8289500d9bfd42358c662ecfcbff93ced732e230")
                    // Get SFTP logs on stderr
                    .run("sed -i -e 's:^WtmpLog:AllowLogSymLinks on\\nSystemLog /dev/stderr\\nSFTPLog /dev/stderr\\nWtmpLog:' /etc/proftpd/proftpd.conf") //
                    .build())) //
            .withEnv("PASV_ADDRESS", "127.0.0.1") //
            .withEnv("FTPUSER_NAME", "test") //
            .withEnv("SFTP_ENABLE", "on") //
            // Set it up for password auth
            .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/proftpd.pwd"),
                    "/run/secrets/ftp-user-password-secret")
            .withExposedPorts(2222) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    private SshClient client;

    @BeforeEach
    void setUp() throws Exception {
        client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier((s, a, k) -> true);
        client.start();
    }

    @AfterEach
    void teardown() {
        if (client != null) {
            client.stop();
        }
    }

    @Test // GH-891
    void ignoreMesssage() throws Exception {
        CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.set(client, 20L);
        CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.set(client, 0);
        CoreModuleProperties.IGNORE_MESSAGE_SIZE.set(client, 16);
        byte[] expected = new byte[8 * 1024 * 1024];

        Factory<? extends Random> factory = client.getRandomFactory();
        Random rnd = factory.create();
        rnd.fill(expected);

        try (ClientSession sshSession = client.connect("test", server.getHost(), server.getMappedPort(2222)).verify()
                .getClientSession()) {
            sshSession.addPasswordIdentity("test");
            sshSession.auth().verify(2000);
            try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(sshSession)) {
                // Copy some data onto the server
                try (InputStream in = new ByteArrayInputStream(expected);
                     OutputStream out = sftp.write("/home/test/file.bin", SftpClient.OpenMode.Create,
                             SftpClient.OpenMode.Write)) {
                    IoUtils.copy(in, out);
                }
                byte[] actual;
                try (InputStream in = sftp.read("/home/test/file.bin");
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
