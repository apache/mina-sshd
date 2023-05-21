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
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.fs.SftpPath;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Multi-thread tests for {@link SftpFileSystem}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpServerTest extends BaseTestSupport {

    private SshServer server;

    private SshClient client;

    private int numberOfSubsystems;

    private CountDownLatch serverHasNoSftpSubsystem;

    public SftpServerTest() {
        super();
    }

    @Before
    public void setup() throws Exception {
        server = CoreTestSupportUtils.setupTestFullSupportServer(SftpServerTest.class);
        serverHasNoSftpSubsystem = new CountDownLatch(1);
        SftpSubsystemFactory factory = new SftpSubsystemFactory();
        factory.addSftpEventListener(new SftpEventListener() {
            @Override
            public void initialized(ServerSession session, int version) throws IOException {
                numberOfSubsystems++;
            }

            @Override
            public void destroying(ServerSession session) throws IOException {
                numberOfSubsystems--;
                if (numberOfSubsystems == 0) {
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

    @After
    public void shutdown() throws Exception {
        if (client != null) {
            // client.stop();
        }
        if (server != null) {
            server.stop(true);
        }
    }

    private String download(Path remote) throws Exception {
        String[] actual = { null };
        Thread worker = new Thread(() -> {
            try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                try (InputStream input = new BufferedInputStream(Files.newInputStream(remote))) {
                    IoUtils.copy(input, downloaded);
                }
                actual[0] = downloaded.toString(StandardCharsets.UTF_8.name());
            } catch (IOException e) {
                actual[0] = e.toString();
            }
        });
        worker.start();
        worker.join(TimeUnit.SECONDS.toMillis(3));
        return actual[0];
    }

    @Test
    public void testSequentialThreads() throws Exception {
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
                assertTrue("Should be an SftpPath", remote instanceof SftpPath);
                String actual = download(remote);
                assertEquals("Mismatched content", expected, actual);
                // And again
                actual = download(remote);
                assertEquals("Mismatched content", expected, actual);
                // And again
                actual = download(remote);
                assertEquals("Mismatched content", expected, actual);
                // Yes, we had three threads, but no concurrency at all. There should be only a single server-side
                // SftpSubsystem.
                assertEquals("Unexpected number of SftpSubsystems", 1, numberOfSubsystems);
            }
            assertTrue("Session should still be open", session.isOpen());
            assertTrue("Server did not close SftpSubsystem", serverHasNoSftpSubsystem.await(3, TimeUnit.SECONDS));
            assertEquals("SftpSubsystem count should be zero", 0, numberOfSubsystems);
        }
    }

    @Test
    public void testConcurrentThreads() throws Exception {
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
                assertTrue("Should be an SftpPath", remote instanceof SftpPath);
                String[] actual1 = { null };
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
                        actual1[0] = downloaded.toString(StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        actual1[0] = e.toString();
                    }
                });
                String[] actual2 = { null };
                int[] numberOfChannels = { -1 };
                Thread worker2 = new Thread(() -> {
                    try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                        try (InputStream input = Files.newInputStream(remote)) {
                            // This is of course a stupid way to copy something, but for this test we need a loop.
                            for (boolean first = true;; first = false) {
                                int b = input.read();
                                if (first) {
                                    numberOfChannels[0] = numberOfSubsystems;
                                    secondThreadIsReady.countDown();
                                }
                                if (b < 0) {
                                    break;
                                }
                                downloaded.write(b);
                            }
                        }
                        actual2[0] = downloaded.toString(StandardCharsets.UTF_8.name());
                    } catch (Exception e) {
                        actual2[0] = e.toString();
                    }
                });
                worker1.start();
                worker2.start();
                worker1.join(TimeUnit.SECONDS.toMillis(3));
                worker2.join(TimeUnit.SECONDS.toMillis(3));
                assertEquals("Mismatched content", expected, actual1[0]);
                assertEquals("Mismatched content", expected, actual2[0]);
                assertEquals("Unexpected number of SftpSubsystems", 2, numberOfChannels[0]);
            }
            assertTrue("Session should still be open", session.isOpen());
            assertTrue("Server did not close SftpSubsystem", serverHasNoSftpSubsystem.await(3, TimeUnit.SECONDS));
            assertEquals("SftpSubsystem count", 0, numberOfSubsystems);
        }
    }

    @Test
    public void testHandOffStream() throws Exception {
        // This test shows that it is not possible to correctly handle these ThreadLocals. There are cases where
        // perfectly valid code creates the wrapper in one thread but closes it in another. In this case, closing the
        // wrapper cannot remove the ThreadLocal: it'll try to do so on a different thread, where either there is no
        // ThreadLocal, or (perhaps even worse) there might be one containing a different wrapper.
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
                assertTrue("Should be an SftpPath", remote instanceof SftpPath);
                InputStream is = Files.newInputStream(remote);
                String[] actual = { null };
                Thread worker = new Thread(() -> {
                    try (ByteArrayOutputStream downloaded = new ByteArrayOutputStream()) {
                        try (InputStream input = new BufferedInputStream(is)) {
                            IoUtils.copy(input, downloaded);
                        }
                        actual[0] = downloaded.toString(StandardCharsets.UTF_8.name());
                    } catch (IOException e) {
                        actual[0] = e.toString();
                    }
                });
                worker.start();
                worker.join(TimeUnit.SECONDS.toMillis(3));
                assertEquals("Mismatched content", expected, actual[0]);
                // It's rather hard to test ThreadLocals because even just calling get() will create it the thread's
                // ThreadLocalMap. I don't want to do reflection on JDK classes, so the best we can do is check that we
                // have a null value. There's no way to check that the ThreadLocalMap has no entry at all for any
                // wrapper.
                //
                // The test succeeds if either SftpFileSystem does not have the ThreadLocal, or its value is null.
                // It should be null because is was closed. In reality it isn't with the SftpFileSystem implementation
                // of Apache MINA 2.10.0, or even with the state at commit 18f4346a0.
                try {
                    Field f = fs.getClass().getDeclaredField("wrappers");
                    f.setAccessible(true);
                    ThreadLocal<?> item = (ThreadLocal<?>) f.get(fs);
                    Object content = item.get();
                    if (content instanceof SftpClient) {
                        // We expect null. But if we have an SftpClient here, it should at least be closed because the
                        // input stream 'is' was closed. Which is, of course, also bad. The ThreadLocal should never
                        // contain a closed SftpClient. But such is the nature of this memory leak.
                        assertFalse(((SftpClient) content).isOpen());
                    }
                    assertNull("ThreadLocal", content);
                } catch (NoSuchFieldException e) {
                    // It's OK
                }
            }
        }
    }

    @Test
    public void testDirectoryStream() throws Exception {
        // This test shows that it is not possible to correctly handle these ThreadLocals. There are cases where
        // perfectly valid code creates the wrapper in one thread but closes it in another. In this case, closing the
        // wrapper cannot remove the ThreadLocal: it'll try to do so on a different thread, where either there is no
        // ThreadLocal, or (perhaps even worse) there might be one containing a different wrapper.
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
                assertTrue("Should be an SftpPath", remote instanceof SftpPath);
                int numberOfFiles = 0;
                try (DirectoryStream<Path> dir = Files.newDirectoryStream(remote)) {
                    // Pretend we did something with the directory listing.
                    for (@SuppressWarnings("unused")
                    Path p : dir) {
                        numberOfFiles++;
                    }
                }
                assertEquals("Unexpected number of files", 1, numberOfFiles); // We don't get . and ..
                try {
                    Field f = fs.getClass().getDeclaredField("wrappers");
                    f.setAccessible(true);
                    ThreadLocal<?> item = (ThreadLocal<?>) f.get(fs);
                    Object content = item.get();
                    assertNull("ThreadLocal", content);
                } catch (NoSuchFieldException e) {
                    // It's OK
                }
            }
        }
    }

}
