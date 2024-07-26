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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class ScpRemote2RemoteTransferHelperTest extends AbstractScpTestSupport {
    protected Logger log;
    private boolean preserveAttributes;

    public void initScpRemote2RemoteTransferHelperTest(boolean preserveAttributes) {
        this.preserveAttributes = preserveAttributes;
        this.log = LoggerFactory.getLogger(getClass());
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
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

    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList(Boolean.TRUE, Boolean.FALSE));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "preserveAttributes={0}")
    public void transferFiles(boolean preserveAttributes) throws Exception {
        initScpRemote2RemoteTransferHelperTest(preserveAttributes);
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
                            assertEquals(srcPath, source, "Mismatched start xfer source path");
                            assertEquals(dstPath, destination, "Mismatched start xfer destination path");
                        }

                        @Override
                        public void endDirectFileTransfer(
                                ClientSession srcSession, String source,
                                ClientSession dstSession, String destination,
                                ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details,
                                long xferSize, Throwable thrown)
                                throws IOException {
                            assertEquals(srcPath, source, "Mismatched end xfer source path");
                            assertEquals(dstPath, destination, "Mismatched end xfer destination path");

                            long prev = xferCount.getAndSet(xferSize);
                            assertEquals(0L, prev, "Mismatched 1st end file xfer size");
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
        assertEquals(expectedData.length, xferCount.getAndSet(0L), "Mismatched transfer size");

        byte[] actualData = Files.readAllBytes(dstFile);
        assertArrayEquals(expectedData, actualData, "Mismatched transfer contents");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "preserveAttributes={0}")
    public void transferDirectoriesRecursively(boolean preserveAttributes) throws Exception {
        initScpRemote2RemoteTransferHelperTest(preserveAttributes);
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
                    assertEquals(new String(srcData, StandardCharsets.UTF_8),
                            new String(dstData, StandardCharsets.UTF_8),
                            name + "[DATA]");
                }
            }
        }

        try (DirectoryStream<Path> dstDir = Files.newDirectoryStream(dstPath)) {
            for (Path dstFile : dstDir) {
                String name = dstFile.getFileName().toString();
                Path srcFile = srcPath.resolve(name);
                if (Files.isDirectory(dstFile)) {
                    assertTrue(Files.isDirectory(srcFile), name + ": unmatched destination folder");
                } else {
                    assertTrue(Files.exists(srcFile), name + ": unmatched destination file");
                }
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[preserveAttributes=" + preserveAttributes + "]";
    }
}
