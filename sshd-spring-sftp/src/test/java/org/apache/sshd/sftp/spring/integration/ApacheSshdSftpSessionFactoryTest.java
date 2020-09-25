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
package org.apache.sshd.sftp.spring.integration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.jcraft.jsch.ChannelSftp.LsEntry;
import com.jcraft.jsch.SftpATTRS;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.PathUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.integration.file.remote.session.Session;
import org.springframework.integration.file.remote.session.SessionFactory;
import org.springframework.integration.sftp.session.DefaultSftpSessionFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ApacheSshdSftpSessionFactoryTest extends BaseTestSupport {
    private static final Comparator<LsEntry> BY_CASE_INSENSITIVE_FILENAME = new Comparator<LsEntry>() {
        @Override
        public int compare(LsEntry o1, LsEntry o2) {
            if (o1 == o2) {
                return 0;
            } else if (o1 == null) {
                return 1;
            } else if (o2 == null) {
                return -1;
            } else {
                return GenericUtils.safeCompare(o1.getFilename(), o2.getFilename(), false);
            }
        }
    };

    private static final Predicate<String> SYNTHETIC_DIR_ENTRY_NAME = n -> ".".equals(n) || "..".equals(n);

    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    private final FileSystemFactory fileSystemFactory;

    public ApacheSshdSftpSessionFactoryTest() {
        Path targetPath = detectTargetFolder();
        Path parentPath = targetPath.getParent();
        fileSystemFactory = new VirtualFileSystemFactory(parentPath);
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        JSchLogger.init();
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(ApacheSshdSftpSessionFactoryTest.class);
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(ApacheSshdSftpSessionFactoryTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @Before
    public void setUp() throws Exception {
        sshd.setFileSystemFactory(fileSystemFactory); // just making sure
    }

    @Test
    public void testOpenCloseStateReport() throws Exception {
        SessionFactory<SftpClient.DirEntry> sshdFactory = getSshdSessionFactory();
        try (Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
            assertTrue("Session not reported as open", sshdSession.isOpen());
            sshdSession.close();
            assertFalse("Session not reported as closed", sshdSession.isOpen());
        }
    }

    @Test
    public void testSharedSessionInstance() throws Exception {
        ApacheSshdSftpSessionFactory sshdFactory = getSshdSessionFactory(true);
        ClientSession sessionInstance;
        try (Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
            SftpClient client = (SftpClient) sshdSession.getClientInstance();
            sessionInstance = client.getClientSession();
            assertSame("Mismatched factory session instance", sshdFactory.getSharedClientSession(), sessionInstance);
        }

        for (int index = 1; index <= Byte.SIZE; index++) {
            try (Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
                SftpClient client = (SftpClient) sshdSession.getClientInstance();
                assertSame("Mismatched session #" + index + " session instance", sessionInstance, client.getClientSession());
            }
        }
    }

    @Test
    public void testWriteRemoteFileContents() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path srcFile = Files.createDirectories(lclSftp).resolve("source.txt");
        List<String> expectedLines
                = Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName());
        Files.deleteIfExists(srcFile);
        Files.write(srcFile, expectedLines, StandardCharsets.UTF_8);

        Path dstFile = srcFile.getParent().resolve("destination.txt");
        Path parentPath = targetPath.getParent();
        String remoteFile = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, dstFile);
        SessionFactory<LsEntry> legacyFactory = getLegacySessionFactory();
        SessionFactory<SftpClient.DirEntry> sshdFactory = getSshdSessionFactory();
        try (Session<LsEntry> legacySession = legacyFactory.getSession();
             Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
            testWriteRemoteFileContents("Legacy", legacySession, srcFile, dstFile, remoteFile, expectedLines);
        }
    }

    private static void testWriteRemoteFileContents(
            String type, Session<?> session, Path srcFile, Path dstFile, String remotePath, List<String> expectedLines)
            throws Exception {
        Files.deleteIfExists(dstFile);

        try (InputStream inputStream = Files.newInputStream(srcFile)) {
            session.write(inputStream, remotePath);
        }
        assertTrue(type + ": destination file not created", Files.exists(dstFile));

        List<String> actualLines = Files.readAllLines(dstFile, StandardCharsets.UTF_8);
        assertListEquals(type, expectedLines, actualLines);
    }

    @Test
    public void testRetrieveRemoteFileContents() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        Path lclFile = Files.createDirectories(lclSftp).resolve("source.txt");
        List<String> expectedLines
                = Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName());
        Files.deleteIfExists(lclFile);
        Files.write(lclFile, expectedLines, StandardCharsets.UTF_8);

        Path parentPath = targetPath.getParent();
        String remoteFile = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);
        SessionFactory<LsEntry> legacyFactory = getLegacySessionFactory();
        SessionFactory<SftpClient.DirEntry> sshdFactory = getSshdSessionFactory();
        try (Session<LsEntry> legacySession = legacyFactory.getSession();
             Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
            for (boolean directStream : new boolean[] { true, false }) {
                List<String> legacyLines = readRemoteFileLines(legacySession, remoteFile, directStream);
                assertListEquals("Pure legacy lines - direct=" + directStream, expectedLines, legacyLines);

                List<String> sshdLines = readRemoteFileLines(sshdSession, remoteFile, directStream);
                assertListEquals("Legacy vs. SSHD lines - direct=" + directStream, legacyLines, sshdLines);
            }
        }
    }

    private static List<String> readRemoteFileLines(Session<?> session, String remoteFile, boolean directStream)
            throws Exception {
        if (directStream) {
            try (InputStream rawStream = session.readRaw(remoteFile)) {
                try {
                    return IoUtils.readAllLines(rawStream);
                } finally {
                    session.finalizeRaw();
                }
            }
        } else {
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream(Byte.MAX_VALUE)) {
                session.read(remoteFile, baos);

                try (ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray())) {
                    return IoUtils.readAllLines(bais);
                }
            }
        }
    }

    @Test
    public void testListContents() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp); // start clean

        List<Path> subFolders = new ArrayList<>();
        for (int index = 1; index <= Byte.SIZE; index++) {
            Path dir = Files.createDirectories(lclSftp.resolve("dir" + index));
            subFolders.add(dir);
        }
        Collections.sort(subFolders, PathUtils.BY_CASE_INSENSITIVE_FILENAME);

        List<Path> subFiles = new ArrayList<>();
        for (int index = 1; index <= Byte.SIZE; index++) {
            Path file = Files.write(lclSftp.resolve("file" + index + ".txt"),
                    (getClass().getSimpleName() + "#" + getCurrentTestName() + "-" + index).getBytes(StandardCharsets.UTF_8));
            subFiles.add(file);
        }
        Collections.sort(subFiles, PathUtils.BY_CASE_INSENSITIVE_FILENAME);

        Path parentPath = targetPath.getParent();
        String remotePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclSftp);
        SessionFactory<LsEntry> legacyFactory = getLegacySessionFactory();
        SessionFactory<SftpClient.DirEntry> sshdFactory = getSshdSessionFactory();
        try (Session<LsEntry> legacySession = legacyFactory.getSession();
             Session<SftpClient.DirEntry> sshdSession = sshdFactory.getSession()) {
            SftpClient.DirEntry[] sshdEntries = sshdSession.list(remotePath);
            List<SftpClient.DirEntry> sshdFiles = new ArrayList<>();
            List<SftpClient.DirEntry> sshdDirs = new ArrayList<>();
            for (SftpClient.DirEntry de : sshdEntries) {
                String filename = de.getFilename();
                if (SYNTHETIC_DIR_ENTRY_NAME.test(filename)) {
                    continue;
                }

                Attributes attrs = de.getAttributes();
                if (attrs.isDirectory()) {
                    sshdDirs.add(de);
                } else if (attrs.isRegularFile()) {
                    sshdFiles.add(de);
                }
            }

            Collections.sort(sshdDirs, SftpClient.DirEntry.BY_CASE_INSENSITIVE_FILENAME);
            assertLocalEntriesEqual(subFolders, sshdDirs, true);
            Collections.sort(sshdFiles, SftpClient.DirEntry.BY_CASE_INSENSITIVE_FILENAME);
            assertLocalEntriesEqual(subFiles, sshdFiles, false);

            LsEntry[] legacyEntries = legacySession.list(remotePath);
            List<LsEntry> legacyFiles = new ArrayList<>();
            List<LsEntry> legacyDirs = new ArrayList<>();
            for (LsEntry lse : legacyEntries) {
                String filename = lse.getFilename();
                if (SYNTHETIC_DIR_ENTRY_NAME.test(filename)) {
                    continue;
                }

                SftpATTRS attrs = lse.getAttrs();
                if (attrs.isDir()) {
                    legacyDirs.add(lse);
                } else if (attrs.isReg()) {
                    legacyFiles.add(lse);
                }
            }

            Collections.sort(legacyDirs, BY_CASE_INSENSITIVE_FILENAME);
            assertRemoteEntriesEqual(legacyDirs, sshdDirs, true);
            Collections.sort(legacyFiles, BY_CASE_INSENSITIVE_FILENAME);
            assertRemoteEntriesEqual(legacyFiles, sshdFiles, false);

            List<String> sshdNames = Stream.of(sshdSession.listNames(remotePath))
                    .filter(SYNTHETIC_DIR_ENTRY_NAME.negate())
                    .collect(Collectors.toList());
            Collections.sort(sshdNames, String.CASE_INSENSITIVE_ORDER);

            List<String> localNames = subFiles.stream()
                    .map(Path::getFileName)
                    .map(Objects::toString)
                    .collect(Collectors.toList());
            Collections.sort(localNames, String.CASE_INSENSITIVE_ORDER);
            assertListEquals("Local names mismatch", localNames, sshdNames);

            List<String> legacyNames = Stream.of(legacySession.listNames(remotePath))
                    .filter(SYNTHETIC_DIR_ENTRY_NAME.negate())
                    .collect(Collectors.toList());
            Collections.sort(legacyNames, String.CASE_INSENSITIVE_ORDER);
            assertListEquals("Remote names mismatch", legacyNames, sshdNames);
        }
    }

    private static void assertLocalEntriesEqual(List<Path> expected, List<SftpClient.DirEntry> actual, boolean dirs) {
        assertEquals("Mismatched dir=" + dirs + " entries count", expected.size(), actual.size());
        for (int index = 0; index < expected.size(); index++) {
            Path path = expected.get(index);
            SftpClient.DirEntry de = actual.get(index);
            assertEquals("Mismatched filename at dirs=" + dirs + " index=" + index, Objects.toString(path.getFileName(), null),
                    de.getFilename());

            Attributes deAttrs = de.getAttributes();
            assertEquals("Mismatched SSHD directory indicator for " + path, dirs, deAttrs.isDirectory());
        }
    }

    private static void assertRemoteEntriesEqual(List<LsEntry> expected, List<SftpClient.DirEntry> actual, boolean dirs) {
        assertEquals("Mismatched dir=" + dirs + " entries count", expected.size(), actual.size());
        for (int index = 0; index < expected.size(); index++) {
            LsEntry lse = expected.get(index);
            SftpClient.DirEntry de = actual.get(index);
            assertEquals("Mismatched filename at dirs=" + dirs + " index=" + index, lse.getFilename(), de.getFilename());

            SftpATTRS lsAttrs = lse.getAttrs();
            Attributes deAttrs = de.getAttributes();
            assertEquals("Mismatched legacy directory indicator for " + lse.getFilename(), dirs, lsAttrs.isDir());
            assertEquals("Mismatched SSHD directory indicator for " + de.getFilename(), dirs, deAttrs.isDirectory());
        }
    }

    protected SessionFactory<LsEntry> getLegacySessionFactory() {
        DefaultSftpSessionFactory factory = new DefaultSftpSessionFactory();
        factory.setHost(TEST_LOCALHOST);
        factory.setPort(port);
        factory.setUser(getCurrentTestName());
        factory.setPassword(getCurrentTestName());
        factory.setTimeout(30 * 1000);
        factory.setEnableDaemonThread(true);
        factory.setAllowUnknownKeys(true);
        return factory;
    }

    protected ApacheSshdSftpSessionFactory getSshdSessionFactory() throws Exception {
        return getSshdSessionFactory(false);
    }

    protected ApacheSshdSftpSessionFactory getSshdSessionFactory(boolean sharedSession) throws Exception {
        ApacheSshdSftpSessionFactory factory = new ApacheSshdSftpSessionFactory(sharedSession);
        factory.setHost(TEST_LOCALHOST);
        factory.setPort(port);
        factory.setUsername(getCurrentTestName());
        factory.setPassword(getCurrentTestName());
        factory.setSshClient(client);
        factory.setConnectTimeout(TimeUnit.SECONDS.toMillis(7L));
        factory.setAuthenticationTimeout(TimeUnit.SECONDS.toMillis(11L));
        factory.afterPropertiesSet();
        return factory;
    }
}
