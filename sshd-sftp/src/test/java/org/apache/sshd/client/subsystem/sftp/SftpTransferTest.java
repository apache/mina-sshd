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
package org.apache.sshd.client.subsystem.sftp;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.fs.SftpFileSystem;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SftpTransferTest extends AbstractSftpClientTestSupport {

    private static final int BUFFER_SIZE = 8192;

    public SftpTransferTest() throws IOException {
        super();
    }

    @Test
    public void testTransferIntegrity() throws IOException {
        try (ClientSession session = createClientSession();
             SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {

            Path localRoot = detectTargetFolder().resolve("sftp");
            Path remoteRoot = fs.getDefaultDir().resolve("target/sftp");

            Path local0 = localRoot.resolve("files-0.txt");
            Path remote0 = remoteRoot.resolve("files-1.txt");
            Path local1 = localRoot.resolve("files-2.txt");
            Path remote1 = remoteRoot.resolve("files-3.txt");
            Path local2 = localRoot.resolve("files-4.txt");
            Files.deleteIfExists(local0);
            Files.deleteIfExists(remote0);
            Files.deleteIfExists(local1);
            Files.deleteIfExists(remote1);
            Files.deleteIfExists(local2);

            Files.createDirectories(localRoot);
            String data = getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")\n";
            try (BufferedWriter bos = Files.newBufferedWriter(local0)) {
                long count = 0;
                while (count < 1024 * 1024 * 10) { // 10 MB
                    bos.append(data);
                    count += data.length();
                }
            }

            Files.copy(local0, remote0);
            Files.copy(remote0, local1);
            Files.copy(local1, remote1);
            Files.copy(remote1, local2);

            assertTrue("File integrity problem", sameContent(local0, local2));
        }
    }

    private ClientSession createClientSession() throws IOException {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(7L, TimeUnit.SECONDS).getSession();
        try {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);
            return session;
        } catch (IOException e) {
            session.close();
            throw e;
        }
    }

    private boolean sameContent(Path path, Path path2) throws IOException {
        byte[] buffer1 = new byte[BUFFER_SIZE];
        byte[] buffer2 = new byte[BUFFER_SIZE];
        try (InputStream in1 = Files.newInputStream(path);
             InputStream in2 = Files.newInputStream(path2)) {
            while (true) {
                int nRead1 = readNBytes(in1, buffer1);
                int nRead2 = readNBytes(in2, buffer2);
                if (nRead1 != nRead2) {
                    return false;
                } else if (nRead1 == BUFFER_SIZE) {
                    if (!Arrays.equals(buffer1, buffer2)) {
                        return false;
                    }
                } else {
                    for (int i = 0; i < nRead1; i++) {
                        if (buffer1[i] != buffer2[i]) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }
    }

    private int readNBytes(InputStream is, byte[] b) throws IOException {
        int n = 0;
        int len = b.length;
        while (n < len) {
            int count = is.read(b, n, len - n);
            if (count < 0) {
                break;
            }
            n += count;
        }
        return n;
    }

}
