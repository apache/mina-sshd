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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.FileHandle;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.jupiter.api.Test;

class SftpClientTest extends AbstractSftpClientTestSupport {

    SftpClientTest() {
        super();
    }

    @Test
    void requestCompletionCleansUpOnSuccessAndFailure() throws Exception {
        SftpSubsystemFactory factory = (SftpSubsystemFactory) sshd.getSubsystemFactories().get(0);
        ThreadLocal<Integer> currentRequest = new ThreadLocal<>();
        AtomicInteger completed = new AtomicInteger();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch finished = new CountDownLatch(3);
        SftpEventListener listener = new SftpEventListener() {
            @Override
            public void received(ServerSession session, int type, int id) throws IOException {
                if (type == SftpConstants.SSH_FXP_STAT || type == SftpConstants.SSH_FXP_LSTAT) {
                    currentRequest.set(id);
                    if (completed.get() == 2) {
                        throw new IOException("rejected request");
                    }
                }
            }

            @Override
            public void completed(ServerSession session, int type, int id) {
                if (type == SftpConstants.SSH_FXP_STAT || type == SftpConstants.SSH_FXP_LSTAT) {
                    try {
                        if (!Integer.valueOf(id).equals(currentRequest.get())) {
                            failure.set(new AssertionError("Completion ran without the request's thread-local state"));
                        }
                    } finally {
                        currentRequest.remove();
                        completed.incrementAndGet();
                        finished.countDown();
                    }
                }
            }
        };
        factory.addSftpEventListener(listener);
        try (SftpClient sftp = createSingleSessionClient()) {
            sftp.stat(".");
            assertThrows(IOException.class, () -> sftp.stat("file-that-does-not-exist-for-request-completion"));
            assertThrows(IOException.class, () -> sftp.stat("."));
            assertTrue(finished.await(10, TimeUnit.SECONDS), "Completion callbacks did not run");
            assertNull(failure.get(), "Thread-local request context mismatch");
            assertEquals(3, completed.get());
        } finally {
            factory.removeSftpEventListener(listener);
        }
    }

    @Test
    void writeExactBufferSize() throws Exception {
        SftpSubsystemFactory sftpFactory = null;
        for (SubsystemFactory f : sshd.getSubsystemFactories()) {
            if (f instanceof SftpSubsystemFactory) {
                sftpFactory = (SftpSubsystemFactory) f;
                break;
            }
        }
        assertNotNull(sftpFactory);

        AtomicInteger zeroWrite = new AtomicInteger();
        SftpEventListener listener = new SftpEventListener() {

            @Override
            public void writing(
                    ServerSession session, String remoteHandle, FileHandle localHandle, long offset, byte[] data,
                    int dataOffset, int dataLen) throws IOException {
                if (dataLen == 0) {
                    zeroWrite.incrementAndGet();
                }
            }
        };

        sftpFactory.addSftpEventListener(listener);

        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path inputFile = targetPath.resolve("input.bin");
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.bin");
        int packetSize = 32 * 1024;
        int handleSize = SftpModuleProperties.FILE_HANDLE_SIZE.getRequired(sshd).intValue();
        int payloadSize = packetSize - 30 - handleSize;
        byte[] expected = new byte[payloadSize];

        ThreadLocalRandom.current().nextBytes(expected);
        try (SftpClient sftp = createSingleSessionClient()) {
            Files.write(inputFile, expected);
            String file = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
            try (InputStream in = Files.newInputStream(inputFile); OutputStream out = sftp.write(file)) {
                IoUtils.copy(in, out, 32 * 1024);
                out.flush(); // This flush caused a zero-bytes write; see GH-861
                // Note: the implicit flush on out.close() did not produce such a zero-bytes write.
            }
            byte[] transferred = Files.readAllBytes(testFile);
            assertArrayEquals(expected, transferred);
        } finally {
            Files.deleteIfExists(inputFile);
            sftpFactory.removeSftpEventListener(listener);
        }
        assertEquals(0, zeroWrite.get(), "Unexpected SSH_FXP_WRITE with zero data bytes");
    }

}
