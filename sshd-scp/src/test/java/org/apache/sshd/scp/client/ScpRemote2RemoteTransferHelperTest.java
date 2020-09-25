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

package org.apache.sshd.scp.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class ScpRemote2RemoteTransferHelperTest extends AbstractScpTestSupport {
    protected final Logger log;
    private final boolean preserveAttributes;

    public ScpRemote2RemoteTransferHelperTest(boolean preserveAttributes) {
        this.preserveAttributes = preserveAttributes;
        this.log = LoggerFactory.getLogger(getClass());
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        setupClientAndServer(ScpRemote2RemoteTransferHelperTest.class);

        ScpCommandFactory factory = (ScpCommandFactory) sshd.getCommandFactory();
        factory.addEventListener(new ScpTransferEventListener() {
            private final Logger log = LoggerFactory.getLogger(ScpRemote2RemoteTransferHelperTest.class);

            @Override
            public void startFileEvent(
                    Session session, FileOperation op, Path file,
                    long length, Set<PosixFilePermission> perms)
                    throws IOException {
                log.info("startFileEvent({})[{}] {}", session, op, file);
            }

            @Override
            public void endFileEvent(
                    Session session, FileOperation op, Path file,
                    long length, Set<PosixFilePermission> perms, Throwable thrown)
                    throws IOException {
                if (thrown == null) {
                    log.info("endFileEvent({})[{}] {}", session, op, file);
                } else {
                    log.error("endFileEvent({})[{}] {}: {}", session, op, file, thrown);
                }
            }

            @Override
            public void startFolderEvent(
                    Session session, FileOperation op, Path file,
                    Set<PosixFilePermission> perms)
                    throws IOException {
                log.info("startFolderEvent({})[{}] {}", session, op, file);
            }

            @Override
            public void endFolderEvent(
                    Session session, FileOperation op, Path file,
                    Set<PosixFilePermission> perms,
                    Throwable thrown)
                    throws IOException {
                if (thrown == null) {
                    log.info("endFolderEvent({})[{}] {}", session, op, file);
                } else {
                    log.error("endFolderEvent({})[{}] {}: {}", session, op, file, thrown);
                }
            }
        });
    }

    @Parameters(name = "preserveAttributes={0}")
    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList(Boolean.TRUE, Boolean.FALSE));
    }

    @Test
    public void testTransferFiles() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(), "testTransferFiles-" + preserveAttributes);
        CommonTestSupportUtils.deleteRecursive(scpRoot);    // start clean

        Path srcDir = assertHierarchyTargetFolderExists(scpRoot.resolve("srcdir"));
        Path srcFile = srcDir.resolve("source.txt");
        byte[] expectedData
                = CommonTestSupportUtils.writeFile(srcFile, getClass().getName() + "#" + getCurrentTestName() + IoUtils.EOL);
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, srcFile);

        Path dstDir = assertHierarchyTargetFolderExists(scpRoot.resolve("dstdir"));
        Path dstFile = dstDir.resolve("destination.txt");
        String dstPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstFile);

        AtomicLong xferCount = new AtomicLong();
        try (ClientSession srcSession = createAuthenticatedClientSession(getCurrentTestName() + "-src");
             ClientSession dstSession = createAuthenticatedClientSession(getCurrentTestName() + "-dst")) {
            ScpRemote2RemoteTransferHelper helper = new ScpRemote2RemoteTransferHelper(
                    srcSession, dstSession, new ScpRemote2RemoteTransferListener() {
                        @Override
                        public void startDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details)
                                throws IOException {
                            assertEquals("Mismatched start xfer source path", srcPath, source);
                            assertEquals("Mismatched start xfer destination path", dstPath, destination);
                        }

                        @Override
                        public void endDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details,
                                long xferSize, Throwable thrown)
                                throws IOException {
                            assertEquals("Mismatched end xfer source path", srcPath, source);
                            assertEquals("Mismatched end xfer destination path", dstPath, destination);

                            long prev = xferCount.getAndSet(xferSize);
                            assertEquals("Mismatched 1st end file xfer size", 0L, prev);
                        }

                        @Override
                        public void startDirectDirectoryTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveDirCommandDetails details)
                                throws IOException {
                            fail("Unexpected start directory transfer: " + source + " => " + destination);
                        }

                        @Override
                        public void endDirectDirectoryTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveDirCommandDetails details,
                                Throwable thrown)
                                throws IOException {
                            fail("Unexpected end directory transfer: " + source + " => " + destination);
                        }
                    });
            helper.transferFile(srcPath, dstPath, preserveAttributes);
        }
        assertEquals("Mismatched transfer size", expectedData.length, xferCount.getAndSet(0L));

        byte[] actualData = Files.readAllBytes(dstFile);
        assertArrayEquals("Mismatched transfer contents", expectedData, actualData);
    }

    @Test
    public void testTransferDirectoriesRecursively() throws Exception {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        Path scpRoot = CommonTestSupportUtils.resolve(targetPath,
                ScpHelper.SCP_COMMAND_PREFIX, getClass().getSimpleName(),
                "testTransferDirectories-" + preserveAttributes);
        CommonTestSupportUtils.deleteRecursive(scpRoot);    // start clean

        Path srcDir = assertHierarchyTargetFolderExists(scpRoot.resolve("srcdir"));
        Path curDir = assertHierarchyTargetFolderExists(srcDir.resolve("root"));
        String srcPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, curDir);
        for (int depth = 0; depth <= 3; depth++) {
            curDir = assertHierarchyTargetFolderExists(curDir);

            Path curFile = curDir.resolve(depth + ".txt");
            CommonTestSupportUtils.writeFile(
                    curFile, getClass().getName() + "#" + getCurrentTestName() + "@" + depth + IoUtils.EOL);
            curDir = curDir.resolve("0" + Integer.toHexString(depth));
        }

        Path dstDir = assertHierarchyTargetFolderExists(scpRoot.resolve("dstdir"));
        String dstPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstDir);
        try (ClientSession srcSession = createAuthenticatedClientSession(getCurrentTestName() + "-src");
             ClientSession dstSession = createAuthenticatedClientSession(getCurrentTestName() + "-dst")) {
            ScpRemote2RemoteTransferHelper helper = new ScpRemote2RemoteTransferHelper(
                    srcSession, dstSession,
                    new ScpRemote2RemoteTransferListener() {
                        private final String logHint = getCurrentTestName();

                        @Override
                        public void startDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveFileCommandDetails details)
                                throws IOException {
                            log.info("{}: startDirectFileTransfer - {} => {}",
                                    logHint, source, destination);
                        }

                        @Override
                        public void startDirectDirectoryTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveDirCommandDetails details)
                                throws IOException {
                            log.info("{}: startDirectDirectoryTransfer -  {} => {}",
                                    logHint, source, destination);
                        }

                        @Override
                        public void endDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveFileCommandDetails details,
                                long xferSize, Throwable thrown)
                                throws IOException {
                            log.info("{}: endDirectFileTransfer - {} => {}: size={}, thrown={}",
                                    logHint, source, destination, xferSize,
                                    (thrown == null) ? null : thrown.getClass().getSimpleName());
                        }

                        @Override
                        public void endDirectDirectoryTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp,
                                ScpReceiveDirCommandDetails details,
                                Throwable thrown)
                                throws IOException {
                            log.info("{}: endDirectDirectoryTransfer {} => {}: thrown={}",
                                    logHint, source, destination, (thrown == null) ? null : thrown.getClass().getSimpleName());
                        }
                    });
            helper.transferDirectory(srcPath, dstPath, preserveAttributes);
        }

        validateXferDirContents(srcDir, dstDir);
    }

    private static void validateXferDirContents(Path srcPath, Path dstPath) throws Exception {
        try (DirectoryStream<Path> srcDir = Files.newDirectoryStream(srcPath)) {
            for (Path srcFile : srcDir) {
                String name = srcFile.getFileName().toString();
                Path dstFile = dstPath.resolve(name);
                if (Files.isDirectory(srcFile)) {
                    validateXferDirContents(srcFile, dstFile);
                } else {
                    byte[] srcData = Files.readAllBytes(srcFile);
                    byte[] dstData = Files.readAllBytes(dstFile);
                    assertEquals(name + "[DATA]",
                            new String(srcData, StandardCharsets.UTF_8),
                            new String(dstData, StandardCharsets.UTF_8));
                }
            }
        }

        try (DirectoryStream<Path> dstDir = Files.newDirectoryStream(dstPath)) {
            for (Path dstFile : dstDir) {
                String name = dstFile.getFileName().toString();
                Path srcFile = srcPath.resolve(name);
                if (Files.isDirectory(dstFile)) {
                    assertTrue(name + ": unmatched destination folder", Files.isDirectory(srcFile));
                } else {
                    assertTrue(name + ": unmatched destination file", Files.exists(srcFile));
                }
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[preserveAttributes=" + preserveAttributes + "]";
    }
}
