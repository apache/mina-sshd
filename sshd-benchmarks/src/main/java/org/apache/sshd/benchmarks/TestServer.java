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
package org.apache.sshd.benchmarks;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

public enum TestServer {

    INSTANCE;

    private static final String RESOURCES = "/" + TestServer.class.getPackage().getName().replace('.', '/');

    private static final long FILE_SIZE = 20L * 1024 * 1024;

    private GenericContainer<?> sftpHost;
    private String user;
    private String hostname;
    private int port;
    private Path initialFile;
    private Path keyFile;

    private static void generateFile(Path p, long size) throws IOException {
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(p))) {
            for (long i = 0; i < size; i++) {
                out.write((int) (i & 0xFFL));
            }
        }
    }

    public void start(String user, String hostname, int port, Path userKey) throws IOException {
        boolean container = (user == null || user.isEmpty()) //
                || (hostname == null || hostname.isEmpty()) //
                || port < 1024 && port != 22 //
                || port > 65535 //
                || userKey == null //
                || !Files.isRegularFile(userKey);
        if (container) {
            @SuppressWarnings("resource")
            GenericContainer<?> sftp = new GenericContainer<>("atmoz/sftp:alpine") //
                    .withEnv("SFTP_USERS", "foo::::upload")
                    // Set it up for pubkey auth
                    .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/rsa_key.pub"),
                            "/home/foo/.ssh/keys/id_rsa.pub")
                    // Give it static known host keys!
                    .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/ed25519_key", 0x180),
                            "/etc/ssh/ssh_host_ed25519_key")
                    .withCopyFileToContainer(MountableFile.forClasspathResource(RESOURCES + "/rsa_key", 0x180),
                            "/etc/ssh/ssh_host_rsa_key")
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource(RESOURCES + "/disable_force_command.sh", 0x1ff),
                            "/etc/sftp.d/disable_force_command.sh")
                    .withExposedPorts(22);
            sftpHost = sftp;
            sftpHost.start();
            this.user = "foo";
            this.hostname = "localhost";
            this.port = sftpHost.getMappedPort(22);
            keyFile = Files.createTempFile("sftpperf", ".key");
            try (InputStream in = getClass().getResourceAsStream(RESOURCES + "/rsa_key")) {
                Files.copy(in, keyFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } else {
            this.user = user;
            this.hostname = hostname;
            this.port = port;
            keyFile = userKey;
        }
        initialFile = Files.createTempFile("sftpperf", ".bin");
        generateFile(initialFile, FILE_SIZE);
        initialFile = initialFile.toAbsolutePath();
        keyFile = keyFile.toAbsolutePath();
    }

    public String getHost() {
        return hostname;
    }

    public String getUser() {
        return user;
    }

    public int getPort() {
        return port;
    }

    public Path getFile() {
        return initialFile;
    }

    public Path getPrivateKey() {
        return keyFile;
    }

    public void stop() {
        try {
            File f = initialFile.toFile();
            if (!f.delete() && f.exists()) {
                f.deleteOnExit();
            }
        } finally {
            if (sftpHost != null) {
                sftpHost.close(); // Synonym with stop()
            }
        }
    }
}
