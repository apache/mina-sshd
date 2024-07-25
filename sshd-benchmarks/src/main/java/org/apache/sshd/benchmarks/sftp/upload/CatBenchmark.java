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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.StreamingChannel.Streaming;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.TearDown;

public final class CatBenchmark {

    private CatBenchmark() {
        super();
    }

    public static class SftpUploadBenchmark extends CommonState {

        private SshClient sshClient;
        private ClientSession sshSession;
        private ChannelExec exec;
        private SftpClient sftpClient;

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

        @Setup(Level.Invocation)
        public void createChannel() throws Exception {
            exec = sshSession.createExecChannel("cat > upload/testfile.bin");
            exec.setStreaming(Streaming.Async);
            exec.open().verify();
        }

        @TearDown(Level.Invocation)
        public void closeChannel() throws IOException {
            exec.close(false);
        }

        @Benchmark
        public void catUpload() throws Exception {
            try (InputStream localInputStream = Files.newInputStream(testData)) {
                IoOutputStream out = exec.getAsyncIn();
                byte[] buffer = new byte[32 * 1024];
                int offset = 0;
                int length = buffer.length;
                for (;;) {
                    int n = localInputStream.read(buffer, offset, length);
                    if (n < 0) {
                        break;
                    }
                    offset += n;
                    length -= n;
                    if (length == 0) {
                        out.writeBuffer(new ByteArrayBuffer(buffer)).verify(5000);
                        offset = 0;
                        length = buffer.length;
                    }
                }
                if (offset > 0) {
                    out.writeBuffer(new ByteArrayBuffer(buffer, 0, offset)).verify(5000);
                }
                out.close(false);
            }
        }
    }

}
