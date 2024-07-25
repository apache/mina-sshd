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
package org.apache.sshd.sftp.server;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.fs.SftpPath;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Multi-thread tests for {@link SftpFileSystem}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpServerTest extends BaseTestSupport {

    private SshServer server;

    private SshClient client;

    private AtomicInteger numberOfSubsystems = new AtomicInteger();

    private CountDownLatch serverHasNoSftpSubsystem;

    public SftpServerTest() {
        super();
    }

    @BeforeEach
    void setup() throws Exception {
        server = CoreTestSupportUtils.setupTestFullSupportServer(SftpServerTest.class);
        serverHasNoSftpSubsystem = new CountDownLatch(1);
        SftpSubsystemFactory factory = new SftpSubsystemFactory();
        factory.addSftpEventListener(new SftpEventListener() {
            @Override
            public void initialized(ServerSession session, int version) throws IOException {
                numberOfSubsystems.incrementAndGet();
            }

            @Override
            public void destroying(ServerSession session) throws IOException {
                if (numberOfSubsystems.decrementAndGet() == 0) {
                    serverHasNoSftpSubsystem.countDown();
                }
            }

        });
        server.setSubsystemFactories(Collections.singletonList(factory));
        Path targetPath = detectTargetFolder();
        server.setFileSystemFactory(new VirtualFileSystemFactory(targetPath.getParent()));
        server.start();

        client = CoreTestSupportUtils.setupTestClient(SftpServerTest.class);
        client.start();
    }

    @AfterEach
    void shutdown() throws Exception {
        if (client != null) {
            client.stop();
        }
        if (server != null) {
            server.stop(true);
        }
    }

    private String download(Path remote) throws Exception {
        AtomicReference<String> actual = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                try (InputStream input = new BufferedInputStream(Files.newInputStream(remote))) {
                    IoUtils.copy(input, downloaded);
                }
                actual.set(downloaded.toString(StandardCharsets.UTF_8.name()));
            } catch (IOException e) {
                actual.set(e.toString());
            }
        });
        worker.start();
        worker.join(TimeUnit.SECONDS.toMillis(3));
        assertFalse(worker.isAlive(), "Thread should have terminated");
        return actual.get();
    }

    @Test
    void sequentialThreads() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);
        String expected = getCurrentTestName();
        Files.write(testFile, expected.getBytes(StandardCharsets.UTF_8));
        String fileName = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (ClientSession session = createAuthenticatedClientSession(client, server.getPort())) {
            try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
                Path remote = fs.getPath(fileName);
                assertTrue(remote instanceof SftpPath, "Should be an SftpPath");
                String actual = download(remote);
                assertEquals(expected, actual, "Mismatched content");
                // And again
                actual = download(remote);
                assertEquals(expected, actual, "Mismatched content");
                // And again
                actual = download(remote);
                assertEquals(expected, actual, "Mismatched content");
                // Yes, we had three threads, but no concurrency at all. There should be only a single server-side
                // SftpSubsystem.
                assertEquals(1, numberOfSubsystems.get(), "Unexpected number of SftpSubsystems");
            }
            assertTrue(session.isOpen(), "Session should still be open");
            assertTrue(serverHasNoSftpSubsystem.await(3, TimeUnit.SECONDS), "Server did not close SftpSubsystem");
            assertEquals(0, numberOfSubsystems.get(), "SftpSubsystem count should be zero");
        }
    }

    @Test
    void concurrentThreads() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);
        String expected = getCurrentTestName();
        Files.write(testFile, expected.getBytes(StandardCharsets.UTF_8));
        String fileName = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (ClientSession session = createAuthenticatedClientSession(client, server.getPort())) {
            try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
                Path remote = fs.getPath(fileName);
                assertTrue(remote instanceof SftpPath, "Should be an SftpPath");
                AtomicReference<String> actual1 = new AtomicReference<>();
                CountDownLatch secondThreadIsReady = new CountDownLatch(1);
                Thread worker1 = new Thread(() -> {
                    try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                        try (InputStream input = Files.newInputStream(remote)) {
                            // This is of course a stupid way to copy something, but for this test we need a loop.
                            for (boolean first = true;; first = false) {
                                int b = input.read();
                                if (first) {
                                    secondThreadIsReady.await();
                                }
                                if (b < 0) {
                                    break;
                                }
                                downloaded.write(b);
                            }
                        }
                        actual1.set(downloaded.toString(StandardCharsets.UTF_8.name()));
                    } catch (Exception e) {
                        actual1.set(e.toString());
                    }
                });
                AtomicReference<String> actual2 = new AtomicReference<>();
                AtomicInteger numberOfChannels = new AtomicInteger();
                Thread worker2 = new Thread(() -> {
                    try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                        try (InputStream input = Files.newInputStream(remote)) {
                            // This is of course a stupid way to copy something, but for this test we need a loop.
                            for (boolean first = true;; first = false) {
                                int b = input.read();
                                if (first) {
                                    numberOfChannels.set(numberOfSubsystems.get());
                                    secondThreadIsReady.countDown();
                                }
                                if (b < 0) {
                                    break;
                                }
                                downloaded.write(b);
                            }
                        }
                        actual2.set(downloaded.toString(StandardCharsets.UTF_8.name()));
                    } catch (Exception e) {
                        actual2.set(e.toString());
                    }
                });
                worker1.start();
                worker2.start();
                worker1.join(TimeUnit.SECONDS.toMillis(3));
                worker2.join(TimeUnit.SECONDS.toMillis(3));
                assertFalse(worker1.isAlive(), "Worker 1 should have finished");
                assertFalse(worker2.isAlive(), "Worker 2 should have finished");
                assertEquals(expected, actual1.get(), "Mismatched content");
                assertEquals(expected, actual2.get(), "Mismatched content");
                assertEquals(2, numberOfChannels.get(), "Unexpected number of SftpSubsystems");
            }
            assertTrue(session.isOpen(), "Session should still be open");
            assertTrue(serverHasNoSftpSubsystem.await(3, TimeUnit.SECONDS), "Server did not close SftpSubsystem");
            assertEquals(0, numberOfSubsystems.get(), "SftpSubsystem count");
        }
    }

    @Test
    void handOffStream() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);
        String expected = getCurrentTestName();
        Files.write(testFile, expected.getBytes(StandardCharsets.UTF_8));
        String fileName = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, testFile);
        try (ClientSession session = createAuthenticatedClientSession(client, server.getPort())) {
            try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
                Path remote = fs.getPath(fileName);
                assertTrue(remote instanceof SftpPath, "Should be an SftpPath");
                InputStream is = Files.newInputStream(remote);
                AtomicReference<String> actual = new AtomicReference<>();
                Thread worker = new Thread(() -> {
                    try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                        try (InputStream input = new BufferedInputStream(is)) {
                            IoUtils.copy(input, downloaded);
                        }
                        actual.set(downloaded.toString(StandardCharsets.UTF_8.name()));
                    } catch (IOException e) {
                        actual.set(e.toString());
                    }
                });
                worker.start();
                worker.join(TimeUnit.SECONDS.toMillis(3));
                assertFalse(worker.isAlive(), "Worker should have terminated");
                assertEquals(expected, actual.get(), "Mismatched content");
            }
        }
    }

    @Test
    void directoryStream() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);
        Path testFile = assertHierarchyTargetFolderExists(lclSftp).resolve("file.txt");
        Files.deleteIfExists(testFile);
        String expected = getCurrentTestName();
        Files.write(testFile, expected.getBytes(StandardCharsets.UTF_8));
        String dirName = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        try (ClientSession session = createAuthenticatedClientSession(client, server.getPort())) {
            try (SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session)) {
                Path remote = fs.getPath(dirName);
                assertTrue(remote instanceof SftpPath, "Should be an SftpPath");
                int numberOfFiles = 0;
                try (DirectoryStream<Path> dir = Files.newDirectoryStream(remote)) {
                    // Pretend we did something with the directory listing.
                    for (Path p : dir) {
                        if (p != null) {
                            numberOfFiles++;
                        }
                    }
                }
                assertEquals(1, numberOfFiles, "Unexpected number of files"); // We don't get . and ..
            }
        }
    }

}
