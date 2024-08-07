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
package org.apache.sshd.benchmarks.sftp.upload;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.impl.SftpOutputStreamAsync;
import org.openjdk.jmh.annotations.Benchmark;

public final class SshBenchmark {

    private SshBenchmark() {
        super();
    }

    public static class SftpUploadBenchmark extends CommonState {

        private SshClient sshClient;
        private ClientSession sshSession;
        private SftpClient sftpClient;
        private SftpFileSystem sftpFs;

        public SftpUploadBenchmark() {
            super();
        }

        @Override
        protected void prepare() throws Exception {
            // Create a client, session and SftpClient
            sshClient = createClient();
        }

        private SshClient createClient() throws Exception {
            SshClient client = SshClient.setUpDefaultClient();
            if ("jsch".equals(settings)) {
                // Same as JSch default
                client.setCipherFactoriesNames("aes128-ctr");
                client.setMacFactoriesNames("hmac-sha2-256-etm@openssh.com");
            }
            client.setServerKeyVerifier((s, a, k) -> true);
            // Load the user key
            try (InputStream in = Files.newInputStream(Paths.get(sftpKey), StandardOpenOption.READ)) {
                Iterable<KeyPair> clientKeys = SecurityUtils.loadKeyPairIdentities(null, null, in, null);
                client.setKeyIdentityProvider(s -> clientKeys);
            }
            client.start();
            return client;
        }

        @Override
        protected void endTests() throws Exception {
            if (sshClient != null) {
                sshClient.close(false);
            }
        }

        @Override
        protected void setupSession() throws Exception {
            sshSession = sshClient.connect(sftpUser, sftpHost, Integer.parseInt(sftpPort)).verify().getClientSession();
            sshSession.auth().verify(2000);
            sftpClient = SftpClientFactory.instance().createSftpClient(sshSession);
            sftpFs = SftpClientFactory.instance().createSftpFileSystem(sshSession);
            Thread.sleep(1000);
        }

        @Override
        protected void downloadTo(Path file) throws IOException {
            try (InputStream in = sftpClient.read("/home/" + sftpUser + "/upload/testfile.bin")) {
                Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);
            }
        }

        @Override
        protected void closeSession() throws IOException {
            sftpClient.remove("/home/" + sftpUser + "/upload/testfile.bin");
            if (sshSession != null) {
                sshSession.close(false);
                sshSession = null;
            }
        }

        @Benchmark
        public void sftpClientPut() throws IOException {
            sftpClient.put(testData, "/home/" + sftpUser + "/upload/testfile.bin", SftpClient.OpenMode.Create,
                    SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write);
        }

        @Benchmark
        public void sftpClientWrite() throws IOException {
            try (OutputStream out = sftpClient.write("/home/" + sftpUser + "/upload/testfile.bin", SftpClient.OpenMode.Create,
                    SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write)) {
                Files.copy(testData, out);
            }
        }

        @Benchmark
        public void sftpClientTransfer() throws IOException {
            try (SftpOutputStreamAsync out = (SftpOutputStreamAsync) sftpClient.write(
                    "/home/" + sftpUser + "/upload/testfile.bin", SftpClient.OpenMode.Create, SftpClient.OpenMode.Truncate,
                    SftpClient.OpenMode.Write)) {
                try (InputStream localInputStream = Files.newInputStream(testData)) {
                    out.transferFrom(localInputStream);
                }
            }
        }

        @Benchmark
        public void sftpFileSystemWrite() throws IOException {
            Path remoteFile = sftpFs.getPath("/home/" + sftpUser + "/upload", "testfile.bin");
            Files.copy(testData, remoteFile, StandardCopyOption.REPLACE_EXISTING);
        }

        @Benchmark
        public void sftpStream32k() throws IOException {
            try (InputStream localInputStream = Files.newInputStream(testData);
                 OutputStream remoteOutputStream = sftpClient.write("/home/" + sftpUser + "/upload/testfile.bin")) {
                IoUtils.copy(localInputStream, remoteOutputStream, 32 * 1024);
            }
        }

        @Benchmark
        public void sftpTransferFrom() throws IOException {
            SftpModuleProperties.COPY_BUF_SIZE.set(sshSession, 32 * 1024);
            try (FileChannel readableChannel = FileChannel.open(testData, StandardOpenOption.READ);
                 FileChannel writeableChannel = sftpClient.openRemoteFileChannel(
                         "/home/" + sftpUser + "/upload/testfile.bin", SftpClient.OpenMode.Create,
                         SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write)) {
                long position = 0;
                long toWrite = readableChannel.size();
                do {
                    long transferred = writeableChannel.transferFrom(readableChannel, position, toWrite);
                    position += transferred;
                    toWrite -= transferred;
                } while (toWrite > 0);
            }
        }
    }

}
