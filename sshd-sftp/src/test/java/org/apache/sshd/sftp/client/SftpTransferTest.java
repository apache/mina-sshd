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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Date;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
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
        for (int i = 0; i < 10; i++) {
            doTestTransferIntegrity(0);
        }
    }

    @Test
    public void testTransferIntegrityWithBufferLargerThanPacket() throws IOException {
        for (int i = 0; i < 10; i++) {
            doTestTransferIntegrity(65536);
        }
    }

    protected void doTestTransferIntegrity(int bufferSize) throws IOException {
        Path localRoot = detectTargetFolder().resolve("sftp");
        Files.createDirectories(localRoot);

        Path local0 = localRoot.resolve("files-0.txt");
        Files.deleteIfExists(local0);

        String data = getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")" + System.lineSeparator();
        try (BufferedWriter bos = Files.newBufferedWriter(local0)) {
            long count = 0L;
            while (count < 1024L * 1024L * 10L) { // 10 MB
                String s = String.format("%8x %s", count, data);
                bos.append(s);
                count += s.length();
            }
        }

        try (ClientSession session = createAuthenticatedClientSession();
             SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
            if (bufferSize > 0) {
                fs.setReadBufferSize(bufferSize);
                fs.setWriteBufferSize(bufferSize);
            }

            Path remoteRoot = fs.getDefaultDir().resolve("target/sftp");
            Path remote0 = remoteRoot.resolve("files-1.txt");
            Files.deleteIfExists(remote0);

            Path local1 = localRoot.resolve("files-2.txt");
            Files.deleteIfExists(local1);

            Path remote1 = remoteRoot.resolve("files-3.txt");
            Files.deleteIfExists(remote1);

            Path local2 = localRoot.resolve("files-4.txt");
            Files.deleteIfExists(local2);

            Files.copy(local0, remote0);
            Files.copy(remote0, local1);
            Files.copy(local1, remote1);
            Files.copy(remote1, local2);

            assertSameContent(local0, local2);
        }
    }

    private static void assertSameContent(Path path, Path path2) throws IOException {
        long l1 = Files.size(path);
        long l2 = Files.size(path2);
        if (l1 != l2) {
            fail("Size differ: " + l1 + " / " + l2);
        }
        byte[] buffer1 = new byte[BUFFER_SIZE];
        byte[] buffer2 = new byte[BUFFER_SIZE];
        int index = 0;
        try (InputStream in1 = Files.newInputStream(path);
             InputStream in2 = Files.newInputStream(path2)) {

            while (true) {
                int nRead1 = readNBytes(in1, buffer1);
                int nRead2 = readNBytes(in2, buffer2);
                if (nRead1 != nRead2) {
                    fail("Unable to read bytes");
                }
                if (nRead1 == BUFFER_SIZE && Arrays.equals(buffer1, buffer2)) {
                    index += BUFFER_SIZE;
                    continue;
                }
                for (int i = 0; i < Math.min(nRead1, nRead2); i++) {
                    if (buffer1[i] != buffer2[i]) {
                        fail("Content differ at index " + (index + i));
                    }
                }
                break;
            }
        }
    }

    private static int readNBytes(InputStream is, byte[] b) throws IOException {
        int n = 0;
        int len = b.length;
        while (n < len) {
            int count = is.read(b, n, len - n);
            if (count < 0) {
                return n;
            }
            n += count;
        }
        return n;
    }
}
