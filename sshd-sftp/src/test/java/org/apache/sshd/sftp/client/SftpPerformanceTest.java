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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import eu.rekawek.toxiproxy.model.ToxicDirection;
import eu.rekawek.toxiproxy.model.toxic.Latency;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.ToxiproxyContainer;
import org.testcontainers.containers.ToxiproxyContainer.ContainerProxy;

@Ignore("Special class used for development only - not really a test just useful to run as such")
public class SftpPerformanceTest {

    public static final String USERNAME = "foo";
    public static final String PASSWORD = "pass";

    // Create a common docker network so that containers can communicate
    @Rule
    public Network network = Network.newNetwork();

    // the target container - this could be anything
    @Rule
    public GenericContainer<?> sftp = new GenericContainer<>("atmoz/sftp")
            .withEnv("SFTP_USERS", USERNAME + ":" + PASSWORD)
            .withNetwork(network)
            .withFileSystemBind("target", "/home/foo")
            .withExposedPorts(22);

    // Toxiproxy container, which will be used as a TCP proxy
    @Rule
    public ToxiproxyContainer toxiproxy = new ToxiproxyContainer()
            .withNetwork(network);

    public SftpPerformanceTest() {
        super();
    }

    @Test
    public void testUploadLatency() throws IOException {
        final ContainerProxy proxy = toxiproxy.getProxy(sftp, 22);
        for (int latency : Arrays.asList(0, 1, 5, 10, 50, 100, 500)) {
            Latency toxic = proxy.toxics().latency("latency", ToxicDirection.DOWNSTREAM, latency);
            for (int megabytes : Arrays.asList(1, 5, 10, 50, 100)) {
                try (SshClient client = createSshClient()) {
                    long orgTime;
                    long newTime;
                    try (ClientSession session = createClientSession(client, proxy)) {
                        orgTime = uploadPrevious(session, megabytes);
                    }
                    try (ClientSession session = createClientSession(client, proxy)) {
                        newTime = uploadOptimized(session, megabytes);
                    }
                    System.out.println(String.format("%3d MB / %3d ms latency: %7d down to %5d ms, gain = %d%%",
                            megabytes, latency, orgTime, newTime,
                            (int) (100 * (orgTime - newTime) / orgTime)));
                }
            }
            toxic.remove();
        }
    }

    @Test
    public void testDownloadLatency() throws IOException {
        final ContainerProxy proxy = toxiproxy.getProxy(sftp, 22);
        for (int latency : Arrays.asList(0, 1, 5, 10, 50, 100, 500)) {
            Latency toxic = proxy.toxics().latency("latency", ToxicDirection.DOWNSTREAM, latency);
            for (int megabytes : Arrays.asList(1, 5, 10, 50, 100)) {
                try (SshClient client = createSshClient()) {
                    long orgTime;
                    long newTime;
                    try (ClientSession session = createClientSession(client, proxy)) {
                        newTime = downloadOptimized(session, megabytes);
                    }
                    try (ClientSession session = createClientSession(client, proxy)) {
                        orgTime = downloadPrevious(session, megabytes);
                    }
                    System.out.println(String.format("%3d MB / %3d ms latency: %7d down to %5d ms, gain = %d%%",
                            megabytes, latency, orgTime, newTime,
                            (int) (100 * (orgTime - newTime) / orgTime)));
                }
            }
            toxic.remove();
        }
    }

    public ClientSession createClientSession(SshClient client, ContainerProxy proxy) throws IOException {
        final String ipAddressViaToxiproxy = proxy.getContainerIpAddress();
        final int portViaToxiproxy = proxy.getProxyPort();

        ClientSession session = client.connect(USERNAME, ipAddressViaToxiproxy, portViaToxiproxy).verify().getClientSession();
        session.addPasswordIdentity(PASSWORD);
        session.auth().verify();
        return session;
    }

    public SshClient createSshClient() {
        SshClient client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
        client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        client.start();
        return client;
    }

    public long uploadPrevious(ClientSession session, int mb) throws IOException {
        long t0 = System.currentTimeMillis();
        try (SftpClient client = SftpClientFactory.instance().createSftpClient(session)) {
            try (OutputStream os = new BufferedOutputStream(
                    new SftpOutputStreamWithChannel(
                            client, 32768, "out.txt",
                            Arrays.asList(OpenMode.Write,
                                    OpenMode.Create,
                                    OpenMode.Truncate)),
                    32768)) {
                byte[] bytes = "123456789abcdef\n".getBytes();
                for (int i = 0; i < 1024 * 1024 * mb / bytes.length; i++) {
                    os.write(bytes);
                }
            }
        }
        long t1 = System.currentTimeMillis();
        return t1 - t0;
    }

    public long uploadOptimized(ClientSession session, int mb) throws IOException {
        long t0 = System.currentTimeMillis();
        try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
            Path p = fs.getPath("out.txt");
            try (OutputStream os = new BufferedOutputStream(
                    Files.newOutputStream(p, StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING),
                    32768)) {
                byte[] bytes = "123456789abcdef\n".getBytes();
                for (int i = 0; i < 1024 * 1024 * mb / bytes.length; i++) {
                    os.write(bytes);
                }
            }
        }
        long t1 = System.currentTimeMillis();
        return t1 - t0;
    }

    public long downloadPrevious(ClientSession session, int mb) throws IOException {
        Path f = Paths.get("target/out.txt");
        byte[] bytes = "123456789abcdef\n".getBytes();
        try (BufferedOutputStream bos = new BufferedOutputStream(
                Files.newOutputStream(f, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE))) {
            for (int i = 0; i < 1024 * 1024 * mb / bytes.length; i++) {
                bos.write(bytes);
            }
        }
        long t0 = System.currentTimeMillis();
        try (SftpClient client = SftpClientFactory.instance().createSftpClient(session)) {
            try (InputStream os = new BufferedInputStream(
                    new SftpInputStreamWithChannel(
                            client, 32768, "out.txt",
                            Arrays.asList(OpenMode.Read)),
                    32768)) {
                byte[] data = new byte[8192];
                for (int i = 0; i < 1024 * 1024 * mb / data.length; i++) {
                    int l = os.read(data);
                    if (l < 0) {
                        break;
                    }
                }
            }
        }
        long t1 = System.currentTimeMillis();
        return t1 - t0;
    }

    public long downloadOptimized(ClientSession session, int mb) throws IOException {
        Path f = Paths.get("target/out.txt");
        byte[] bytes = "123456789abcdef\n".getBytes();
        try (BufferedOutputStream bos = new BufferedOutputStream(
                Files.newOutputStream(f, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE))) {
            for (int i = 0; i < 1024 * 1024 * mb / bytes.length; i++) {
                bos.write(bytes);
            }
        }
        long t0 = System.currentTimeMillis();
        try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
            Path p = fs.getPath("out.txt");
            try (InputStream os = new BufferedInputStream(
                    Files.newInputStream(p, StandardOpenOption.READ), 32768)) {
                byte[] data = new byte[8192];
                for (int i = 0; i < 1024 * 1024 * mb / data.length; i++) {
                    int l = os.read(data);
                    if (l < 0) {
                        break;
                    }
                }
            }
        }
        long t1 = System.currentTimeMillis();
        return t1 - t0;
    }

}
