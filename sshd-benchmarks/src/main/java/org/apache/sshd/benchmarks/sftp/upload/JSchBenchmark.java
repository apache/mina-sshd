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
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
// import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import org.openjdk.jmh.annotations.Benchmark;

public final class JSchBenchmark {

    private JSchBenchmark() {
        super();
    }

    public static class SftpUploadBenchmark extends CommonState {

        private JSch sshClient;
        private Session sshSession;
        private ChannelSftp sftpClient;

        public SftpUploadBenchmark() {
            super();
        }

        @Override
        protected void prepare() throws Exception {
            sshClient = createClient();
        }

        private JSch createClient() throws Exception {
            if ("jsch".equals(settings)) {
                JSch.setConfig("cipher.c2s", "aes128-ctr");
            } else {
                JSch.setConfig("cipher.c2s", "chacha20-poly1305@openssh.com"); // Needs BC
            }
            JSch client = new JSch();
            client.addIdentity(sftpKey);
            return client;
        }

        @Override
        public void setupSession() throws Exception {
            sshSession = sshClient.getSession(sftpUser, sftpHost, Integer.parseInt(sftpPort));
            sshSession.setConfig("StrictHostKeyChecking", "no");
            sshSession.connect();
            sftpClient = (ChannelSftp) sshSession.openChannel("sftp");
            sftpClient.connect();
            Thread.sleep(1000);
        }

        @Override
        protected void downloadTo(Path localPath) throws IOException {
            try (OutputStream out = Files.newOutputStream(localPath)) {
                sftpClient.get("/home/" + sftpUser + "/upload/testfile.bin", out);
            } catch (SftpException e) {
                throw new IOException("Download failed", e);
            }
        }

        @Override
        protected void closeSession() throws Exception {
            if (sftpClient != null) {
                sftpClient.disconnect();
                sftpClient = null;
            }
            if (sshSession != null) {
                sshSession.disconnect();
                sshSession = null;
            }
        }

        @Benchmark
        public void sftpClientWrite() throws Exception {
            sftpClient.put(initialFile, "/home/" + sftpUser + "/upload/testfile.bin");
        }

    }

}
