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
package org.apache.sshd.sftp.client.fs;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.MapBuilder;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.MatcherAssert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount")
public class SftpFileSystemTest extends AbstractSftpFilesSystemSupport {

    private static final Logger LOG = LoggerFactory.getLogger(SftpFileSystemTest.class);

    public SftpFileSystemTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test
    public void testFileSystem() throws Exception {
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            testFileSystem(fs, ((SftpFileSystem) fs).getVersion());
        }
    }

    @Test
    public void testFileSystemWriteAppend() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            Path localFile = clientFolder.resolve("file.txt");
            Files.write(localFile, "Hello".getBytes(StandardCharsets.UTF_8));
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localFile);
            Path remoteFile = fs.getPath(remFilePath);
            assertHierarchyTargetFolderExists(remoteFile.getParent());
            byte[] buf = new byte[32000];
            for (int i = 0; i < buf.length; i++) {
                buf[i] = (byte) i;
            }
            try (OutputStream out = Files.newOutputStream(remoteFile, StandardOpenOption.APPEND, StandardOpenOption.WRITE,
                    StandardOpenOption.CREATE)) {
                out.write(buf);
                out.write(buf);
            }
            byte[] data = Files.readAllBytes(remoteFile);
            assertEquals("Unexpected length", 64005, data.length);
            assertArrayEquals("Hello".getBytes(StandardCharsets.UTF_8), Arrays.copyOf(data, 5));
            for (int i = 5; i < buf.length; i++) {
                assertEquals("Mismatched data at " + i, (byte) (i - 5), data[i]);
                assertEquals("Mismatched data at " + (i + buf.length), (byte) (i - 5), data[i + buf.length]);
            }
        }
    }

    @Test // See GH-325
    public void testDeleteLink() throws Exception {
        // This test creates symbolic links.
        Assume.assumeFalse(OsUtils.isWin32());
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        List<Path> toRemove = new ArrayList<>();
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            Path localFile = clientFolder.resolve("file.txt");
            Files.write(localFile, "Hello".getBytes(StandardCharsets.UTF_8));
            toRemove.add(localFile);
            Path existingSymlink = clientFolder.resolve("existing.txt");
            Files.createSymbolicLink(existingSymlink, localFile);
            toRemove.add(existingSymlink);

            String remExistingLink = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, existingSymlink);
            Path remoteExistingLink = fs.getPath(remExistingLink);
            assertHierarchyTargetFolderExists(remoteExistingLink.getParent());
            assertTrue(Files.exists(remoteExistingLink));
            assertTrue(Files.exists(remoteExistingLink, LinkOption.NOFOLLOW_LINKS));
            assertTrue(Files.isSymbolicLink(remoteExistingLink));
            Files.delete(remoteExistingLink);
            assertTrue(Files.exists(localFile));
            assertFalse(Files.exists(existingSymlink, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.exists(remoteExistingLink, LinkOption.NOFOLLOW_LINKS));
        } finally {
            for (Path p : toRemove) {
                Files.deleteIfExists(p);
            }
        }
    }

    @Test // See GH-325
    public void testDeleteNonexistingLink() throws Exception {
        // This test creates symbolic links.
        Assume.assumeFalse(OsUtils.isWin32());
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        List<Path> toRemove = new ArrayList<>();
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            Path nonExistingSymlink = clientFolder.resolve("nonexisting.txt");
            Files.createSymbolicLink(nonExistingSymlink, clientFolder.resolve("gone.txt"));
            toRemove.add(nonExistingSymlink);

            String remNonExistingLink = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, nonExistingSymlink);
            Path remoteNonExistingLink = fs.getPath(remNonExistingLink);
            assertFalse(Files.exists(remoteNonExistingLink));
            assertTrue(Files.exists(remoteNonExistingLink, LinkOption.NOFOLLOW_LINKS));
            assertTrue(Files.isSymbolicLink(remoteNonExistingLink));
            Files.delete(remoteNonExistingLink);
            assertFalse(Files.exists(nonExistingSymlink, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.exists(remoteNonExistingLink, LinkOption.NOFOLLOW_LINKS));
        } finally {
            for (Path p : toRemove) {
                Files.deleteIfExists(p);
            }
        }
    }

    @Test // See GH-325
    public void testDeleteDirectoryLink() throws Exception {
        // This test creates symbolic links.
        Assume.assumeFalse(OsUtils.isWin32());
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        List<Path> toRemove = new ArrayList<>();
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            Path directory = clientFolder.resolve("subdir");
            Files.createDirectory(directory);
            toRemove.add(directory);
            Path directorySymlink = clientFolder.resolve("dirlink");
            Files.createSymbolicLink(directorySymlink, directory);
            toRemove.add(directorySymlink);

            String remDirectoryLink = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, directorySymlink);
            Path remoteDirectoryLink = fs.getPath(remDirectoryLink);
            assertTrue(Files.isDirectory(remoteDirectoryLink));
            assertTrue(Files.exists(remoteDirectoryLink, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.isDirectory(remoteDirectoryLink, LinkOption.NOFOLLOW_LINKS));
            assertTrue(Files.isSymbolicLink(remoteDirectoryLink));
            Files.delete(remoteDirectoryLink);
            assertTrue(Files.isDirectory(directory));
            assertFalse(Files.exists(directorySymlink, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.exists(remoteDirectoryLink, LinkOption.NOFOLLOW_LINKS));
        } finally {
            for (Path p : toRemove) {
                Files.deleteIfExists(p);
            }
        }
    }

    @Test // See GH-325
    public void testDeleteNonexistingFile() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);

            String doesNotExist = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath,
                    clientFolder.resolve("neverExisted.txt"));
            Path neverExisted = fs.getPath(doesNotExist);
            assertFalse(Files.exists(neverExisted));
            assertFalse(Files.deleteIfExists(neverExisted));
            assertThrows(NoSuchFileException.class, () -> Files.delete(neverExisted));
        }
    }

    private Map<String, Object> defaultOptions() {
        return MapBuilder.<String, Object> builder()
                .put(SftpModuleProperties.READ_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE)
                .put(SftpModuleProperties.WRITE_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE).build();
    }

    private SshServer createIntermediaryServer(FileSystem fileSystem) throws IOException {
        SshServer sshd = CoreTestSupportUtils.setupTestFullSupportServer(AbstractSftpClientTestSupport.class);
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.setFileSystemFactory(new FileSystemFactory() {

            @Override
            public Path getUserHomeDir(SessionContext session) throws IOException {
                return null;
            }

            @Override
            public FileSystem createFileSystem(SessionContext session) throws IOException {
                return fileSystem;
            }
        });
        sshd.start();
        return sshd;
    }

    @Test // see SSHD-1217
    public void testFileSystemListDirIndirect() throws Exception {
        // Instrument the upstream server to verify what gets called there
        SftpSubsystemFactory factory = (SftpSubsystemFactory) NamedResource.findByName(SftpConstants.SFTP_SUBSYSTEM_NAME,
                String.CASE_INSENSITIVE_ORDER, sshd.getSubsystemFactories());
        AtomicInteger statCount = new AtomicInteger();
        AtomicInteger readDirCount = new AtomicInteger();
        factory.addSftpEventListener(new SftpEventListener() {
            @Override
            public void received(ServerSession session, int type, int id) throws IOException {
                switch (type) {
                    case SftpConstants.SSH_FXP_STAT:
                    case SftpConstants.SSH_FXP_LSTAT:
                        statCount.getAndIncrement();
                        break;
                    case SftpConstants.SSH_FXP_READDIR:
                        readDirCount.getAndIncrement();
                        break;
                    default:
                        break;
                }
            }
        });
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        FileSystem secondHop = FileSystems.newFileSystem(createDefaultFileSystemURI(), defaultOptions());
        assertTrue("Not an SftpFileSystem", secondHop instanceof SftpFileSystem);
        SshServer intermediary = createIntermediaryServer(secondHop);

        try (FileSystem fs = FileSystems.newFileSystem(
                createFileSystemURI(getCurrentTestName(), intermediary.getPort(), Collections.emptyMap()), defaultOptions())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);

            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            // Create files
            final int numberOfFiles = 2000;
            for (int i = 1; i <= numberOfFiles; i++) {
                Path localFile = clientFolder.resolve("file" + i + ".txt");
                Files.createFile(localFile);
            }
            String remDirPath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder);
            Path remoteDir = fs.getPath(remDirPath);
            assertHierarchyTargetFolderExists(remoteDir);
            // Clear counters; verifying the remote dir calls (L)STAT
            statCount.set(0);
            assertEquals("READ_DIR should not have been called yet", 0, readDirCount.get());

            SftpPath sftpPath = (SftpPath) remoteDir;

            // Actual test starts here
            int i = 0;
            long start = System.currentTimeMillis();
            try (SftpClient client = sftpPath.getFileSystem().getClient();
                 CloseableHandle dir = client.openDir(remDirPath)) {
                for (SftpClient.DirEntry entry : client.listDir(dir)) {
                    i++;
                    assertNotNull(entry);
                }
            }
            LOG.info(
                    "{}: directory listing with {} files from intermediary server took {}ms, got {} entries; upstream READDIR called {} times, (L)STAT called {} times",
                    getCurrentTestName(), numberOfFiles, System.currentTimeMillis() - start, i, readDirCount, statCount);
            assertEquals(numberOfFiles + 2, i); // . and ..
            assertTrue("Upstream server not called", readDirCount.get() > 0);
            // The current implementation stats 3 times: once to detect whether the directory exists, is a directory,
            // and is readable; once again for the "." entry, and the parent directory once for "..".
            MatcherAssert.assertThat(
                    "Files.getAttributes() should have been called at most a few times for the directory itself",
                    statCount.get(), new BaseMatcher<Integer>() {

                        @Override
                        public boolean matches(Object item) {
                            return item instanceof Integer && ((Integer) item).intValue() < 4;
                        }

                        @Override
                        public void describeTo(Description description) {
                            description.appendText("smaller than 4");
                        }
                    });

            // Repeat this a few times to get slightly more reliable timings
            final int maxRepeats = 10;
            long directTime = 0;
            long indirectTime = 0;
            for (int attempt = 0; attempt < maxRepeats; attempt++) {
                // Now try the same directly at the upstream server
                statCount.set(0);
                readDirCount.set(0);
                i = 0;
                start = System.currentTimeMillis();
                try (SftpClient client = ((SftpFileSystem) secondHop).getClient();
                     CloseableHandle dir = client.openDir(remDirPath)) {
                    for (SftpClient.DirEntry entry : client.listDir(dir)) {
                        i++;
                        assertNotNull(entry);
                    }
                }
                long elapsed = System.currentTimeMillis() - start;
                directTime += elapsed;
                assertTrue("Upstream server not called", readDirCount.get() > 0);
                assertEquals("(L)STAT should not have been called on upstream server", 0, statCount.get());
                LOG.info(
                        "{}: directory listing with {} files from upstream server took {}ms, got {} entries: READDIR called {} times, (L)STAT called {} times",
                        getCurrentTestName(), numberOfFiles, elapsed, i, readDirCount, statCount);

                statCount.set(0);
                readDirCount.set(0);
                i = 0;
                start = System.currentTimeMillis();
                try (SftpClient client = sftpPath.getFileSystem().getClient();
                     CloseableHandle dir = client.openDir(remDirPath)) {
                    for (SftpClient.DirEntry entry : client.listDir(dir)) {
                        i++;
                        assertNotNull(entry);
                    }
                }
                elapsed = System.currentTimeMillis() - start;
                indirectTime += elapsed;
                assertTrue("Upstream server not called", readDirCount.get() > 0);
                LOG.info(
                        "{}: directory listing with {} files from intermediary server took {}ms, got {} entries: READDIR called {} times, (L)STAT called {} times",
                        getCurrentTestName(), numberOfFiles, elapsed, i, readDirCount, statCount);
            }
            LOG.info("{}: average directory listing times: direct {}ms; indirect {}ms", getCurrentTestName(),
                    directTime / maxRepeats, indirectTime / maxRepeats);
        } finally {
            if (secondHop != null) {
                secondHop.close();
            }
            if (intermediary != null) {
                intermediary.stop(true);
            }
        }
    }

    @Test // SSHD-1220
    public void testAttributeCache() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(),
                getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(),
                MapBuilder.<String, Object> builder()
                        .put(SftpModuleProperties.READ_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE)
                        .put(SftpModuleProperties.WRITE_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE).build())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            assertHierarchyTargetFolderExists(clientFolder);
            Path localFile = clientFolder.resolve("file.txt");
            Files.write(localFile, "Hello".getBytes(StandardCharsets.UTF_8));
            Path localFile2 = clientFolder.resolve("file2.txt");
            Files.write(localFile2, "World".getBytes(StandardCharsets.UTF_8));
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, localFile);
            Path remoteFile = fs.getPath(remFilePath);
            assertHierarchyTargetFolderExists(remoteFile.getParent());
            int n = 0;
            try (DirectoryStream<Path> directory = Files.newDirectoryStream(remoteFile.getParent())) {
                for (Path p : directory) {
                    n++;
                    assertTrue("Expected an SftpPath", p instanceof SftpPath);
                    SftpClient.Attributes cached = ((SftpPath) p).getAttributes();
                    assertNotNull("Path should have cached attributes", cached);
                    assertEquals("Unexpected size reported", 5, cached.getSize());
                    // Now modify the file and fetch attributes again
                    Files.write(p, "Bye".getBytes(StandardCharsets.UTF_8));
                    BasicFileAttributes attributes = Files.readAttributes(p, BasicFileAttributes.class);
                    assertNotEquals("Sizes should be different", attributes.size(), cached.getSize());
                    assertEquals("Unexpected size after modification", 3, attributes.size());
                    assertNull("Path should not have cached attributes anymore", ((SftpPath) p).getAttributes());
                }
            }
            assertEquals("Unexpected number of files", 2, n);
            // And again
            List<Path> obtained = new ArrayList<>(2);
            try (DirectoryStream<Path> directory = Files.newDirectoryStream(remoteFile.getParent())) {
                for (Path p : directory) {
                    assertTrue("Expected an SftpPath", p instanceof SftpPath);
                    SftpClient.Attributes cached = ((SftpPath) p).getAttributes();
                    assertNotNull("Path should have cached attributes", cached);
                    assertEquals("Unexpected size reported", 3, cached.getSize());
                    obtained.add(p);
                }
            }
            assertEquals("Unexpected number of files", 2, obtained.size());
            // Now modify the files and fetch attributes again
            for (Path p : obtained) {
                Files.write(p, "Again".getBytes(StandardCharsets.UTF_8));
                BasicFileAttributes attributes = Files.readAttributes(p, BasicFileAttributes.class);
                // If this fails because the size is 3, we mistakenly got data from previously cached SFTP attributes
                assertEquals("Unexpected file size reported via attributes", 5, attributes.size());
            }
        }
    }

    @Test // see SSHD-578
    public void testFileSystemURIParameters() throws Exception {
        Map<String, Object> params = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        params.put("test-class-name", getClass().getSimpleName());
        params.put("test-pkg-name", getClass().getPackage().getName());
        params.put("test-name", getCurrentTestName());

        int expectedVersion = (SftpSubsystemEnvironment.LOWER_SFTP_IMPL + SftpSubsystemEnvironment.HIGHER_SFTP_IMPL) / 2;
        params.put(SftpFileSystemProvider.VERSION_PARAM, expectedVersion);
        try (SftpFileSystem fs = (SftpFileSystem) FileSystems.newFileSystem(createDefaultFileSystemURI(params),
                Collections.<String, Object> emptyMap())) {
            try (SftpClient sftpClient = fs.getClient()) {
                assertEquals("Mismatched negotiated version", expectedVersion, sftpClient.getVersion());

                Session session = sftpClient.getClientSession();
                params.forEach((key, expected) -> {
                    if (SftpFileSystemProvider.VERSION_PARAM.equalsIgnoreCase(key)) {
                        return;
                    }

                    Object actual = session.getObject(key);
                    assertEquals("Mismatched value for param '" + key + "'", expected, actual);
                });
            }
        }
    }

    @Test
    public void testAttributes() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath,
                SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName(), getCurrentTestName());
        CommonTestSupportUtils.deleteRecursive(lclSftp);

        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(),
                MapBuilder.<String, Object> builder()
                        .put(SftpModuleProperties.READ_BUFFER_SIZE.getName(), SftpClient.MIN_READ_BUFFER_SIZE)
                        .put(SftpModuleProperties.WRITE_BUFFER_SIZE.getName(), SftpClient.MIN_WRITE_BUFFER_SIZE)
                        .build())) {

            Path parentPath = targetPath.getParent();
            Path clientFolder = lclSftp.resolve("client");
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, clientFolder.resolve("file.txt"));
            Path file = fs.getPath(remFilePath);
            assertHierarchyTargetFolderExists(file.getParent());
            Files.write(file, (getCurrentTestName() + "\n").getBytes(StandardCharsets.UTF_8));

            Map<String, Object> attrs = Files.readAttributes(file, "posix:*");
            assertNotNull("No attributes read for " + file, attrs);

            Files.setAttribute(file, "basic:size", 2L);
            Files.setAttribute(file, "posix:permissions", PosixFilePermissions.fromString("rwxr-----"));
            Files.setAttribute(file, "basic:lastModifiedTime", FileTime.fromMillis(100000L));

            FileSystem fileSystem = file.getFileSystem();
            try {
                UserPrincipalLookupService userLookupService = fileSystem.getUserPrincipalLookupService();
                GroupPrincipal group = userLookupService.lookupPrincipalByGroupName("everyone");
                Files.setAttribute(file, "posix:group", group);
            } catch (UserPrincipalNotFoundException e) {
                // Also, according to the Javadoc:
                // "Where an implementation does not support any notion of
                // group then this method always throws UserPrincipalNotFoundException."
                // Therefore we are lenient with this exception for Windows
                if (OsUtils.isWin32()) {
                    System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void testRootFileSystem() throws IOException {
        Path targetPath = detectTargetFolder();
        Path rootNative = targetPath.resolve("root").toAbsolutePath();
        CommonTestSupportUtils.deleteRecursive(rootNative);
        assertHierarchyTargetFolderExists(rootNative);

        try (FileSystem fs = FileSystems.newFileSystem(URI.create("root:" + rootNative.toUri().toString() + "!/"), null)) {
            Path dir = assertHierarchyTargetFolderExists(fs.getPath("test/foo"));
            outputDebugMessage("Created %s", dir);
        }
    }

    @Test // see SSHD-697
    public void testFileChannel() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath,
                SftpConstants.SFTP_SUBSYSTEM_NAME, getClass().getSimpleName());
        Files.createDirectories(lclSftp);

        Path lclFile = lclSftp.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        byte[] expected
                = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")").getBytes(StandardCharsets.UTF_8);
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            Path parentPath = targetPath.getParent();
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);
            Path file = fs.getPath(remFilePath);

            FileSystemProvider provider = fs.provider();
            try (FileChannel fc = provider.newFileChannel(file,
                    EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE))) {
                int writeLen = fc.write(ByteBuffer.wrap(expected));
                assertEquals("Mismatched written length", expected.length, writeLen);

                FileChannel fcPos = fc.position(0L);
                assertSame("Mismatched positioned file channel", fc, fcPos);

                byte[] actual = new byte[expected.length];
                int readLen = fc.read(ByteBuffer.wrap(actual));
                assertEquals("Mismatched read len", writeLen, readLen);
                assertArrayEquals("Mismatched read data", expected, actual);
            }
        }

        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
    }

    @Test
    public void testFileCopy() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME,
                getClass().getSimpleName());
        Files.createDirectories(lclSftp);

        Path lclFile = lclSftp.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        Path lclFile2 = lclSftp.resolve(getCurrentTestName() + ".txt2");
        Files.deleteIfExists(lclFile2);
        byte[] expected = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")")
                .getBytes(StandardCharsets.UTF_8);
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            Path parentPath = targetPath.getParent();
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);
            Path file = fs.getPath(remFilePath);

            FileSystemProvider provider = fs.provider();
            try (FileChannel fc = provider.newFileChannel(file,
                    EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE))) {
                int writeLen = fc.write(ByteBuffer.wrap(expected));
                assertEquals("Mismatched written length", expected.length, writeLen);

                FileChannel fcPos = fc.position(0L);
                assertSame("Mismatched positioned file channel", fc, fcPos);

                byte[] actual = new byte[expected.length];
                int readLen = fc.read(ByteBuffer.wrap(actual));
                assertEquals("Mismatched read len", writeLen, readLen);
                assertArrayEquals("Mismatched read data", expected, actual);
            }
            Path sibling = file.getParent().resolve(file.getFileName().toString() + '2');
            Files.copy(file, sibling);
        }

        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
        actual = Files.readAllBytes(lclFile2);
        assertArrayEquals("Mismatched copied data", expected, actual);
    }

    @Test
    public void testFileWriteRead() throws IOException {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME,
                getClass().getSimpleName());
        Files.createDirectories(lclSftp);

        Path lclFile = lclSftp.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        byte[] expected = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")")
                .getBytes(StandardCharsets.UTF_8);
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            Path parentPath = targetPath.getParent();
            String remFilePath = CommonTestSupportUtils.resolveRelativeRemotePath(parentPath, lclFile);

            try (SftpClient client = ((SftpFileSystem) fs).getClient()) {
                try (OutputStream out = client.write(remFilePath)) {
                    IoUtils.copy(new ByteArrayInputStream(expected), out);
                }
                try (ByteArrayOutputStream out = new ByteArrayOutputStream();
                     InputStream in = client.read(remFilePath)) {
                    IoUtils.copy(in, out);
                    assertArrayEquals("Mismatched persisted data", expected, out.toByteArray());
                }
            }
        }

        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
    }

    @Test
    public void testFileStore() throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap())) {
            Iterable<FileStore> iter = fs.getFileStores();
            assertTrue("Not a list", iter instanceof List<?>);

            List<FileStore> list = (List<FileStore>) iter;
            assertEquals("Mismatched stores count", 1, list.size());

            FileStore store = list.get(0);
            assertEquals("Mismatched type", SftpConstants.SFTP_SUBSYSTEM_NAME, store.type());
            assertFalse("Read-only ?", store.isReadOnly());

            for (String name : fs.supportedFileAttributeViews()) {
                assertTrue("Unsupported view name: " + name, store.supportsFileAttributeView(name));
            }

            for (Class<? extends FileAttributeView> type : SftpFileSystemProvider.UNIVERSAL_SUPPORTED_VIEWS) {
                assertTrue("Unsupported view type: " + type.getSimpleName(), store.supportsFileAttributeView(type));
            }
        }
    }

    @Test
    public void testMultipleFileStoresOnSameProvider() throws IOException {
        SftpFileSystemProvider provider = new SftpFileSystemProvider(client);
        Collection<SftpFileSystem> fsList = new LinkedList<>();
        try {
            Collection<String> idSet = new HashSet<>();
            Map<String, Object> empty = Collections.emptyMap();
            for (int index = 0; index < 4; index++) {
                String credentials = getCurrentTestName() + "-user-" + index;
                SftpFileSystem expected = provider.newFileSystem(createFileSystemURI(credentials, empty), empty);
                fsList.add(expected);

                String id = expected.getId();
                assertTrue("Non unique file system id: " + id, idSet.add(id));

                SftpFileSystem actual = provider.getFileSystem(id);
                assertSame("Mismatched cached instances for " + id, expected, actual);
                outputDebugMessage("Created file system id: %s", id);
            }

            for (SftpFileSystem fs : fsList) {
                String id = fs.getId();
                fs.close();
                assertNull("File system not removed from cache: " + id, provider.getFileSystem(id));
            }
        } finally {
            IOException err = null;
            for (FileSystem fs : fsList) {
                try {
                    fs.close();
                } catch (IOException e) {
                    err = ExceptionUtils.accumulateException(err, e);
                }
            }

            if (err != null) {
                throw err;
            }
        }
    }

    @Test
    public void testSftpVersionSelector() throws Exception {
        AtomicInteger selected = new AtomicInteger(-1);
        SftpVersionSelector selector = (session, initial, current, available) -> {
            int value = initial
                    ? current : GenericUtils.stream(available)
                            .mapToInt(Integer::intValue)
                            .filter(v -> v != current)
                            .max()
                            .orElseGet(() -> current);
            selected.set(value);
            return value;
        };

        try (ClientSession session = createAuthenticatedClientSession();
             FileSystem fs = createSftpFileSystem(session, selector)) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            Collection<String> views = fs.supportedFileAttributeViews();
            assertTrue("Universal views (" + SftpFileSystem.UNIVERSAL_SUPPORTED_VIEWS + ") not supported: " + views,
                    views.containsAll(SftpFileSystem.UNIVERSAL_SUPPORTED_VIEWS));
            int expectedVersion = selected.get();
            assertEquals("Mismatched negotiated version", expectedVersion, ((SftpFileSystem) fs).getVersion());
            testFileSystem(fs, expectedVersion);
        }
    }

    @Test
    public void testSessionNotClosed() throws Exception {
        try (ClientSession session = createAuthenticatedClientSession()) {
            List<Channel> channels = new ArrayList<>();
            session.addChannelListener(new ChannelListener() {

                @Override
                public void channelOpenSuccess(Channel channel) {
                    channels.add(channel);
                }

                @Override
                public void channelClosed(Channel channel, Throwable reason) {
                    channels.remove(channel);
                }
            });
            SftpFileSystem fs = SftpClientFactory.instance().createSftpFileSystem(session);
            try {
                testFileSystem(fs, fs.getVersion());
            } finally {
                fs.close();
            }
            assertFalse("File system should not be open", fs.isOpen());
            assertEquals("No open channels expected", "[]", channels.toString());
            assertTrue("Non-owned session should still be open", session.isOpen());
        }
    }

    @Test
    public void testSessionClosed() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME,
                getClass().getSimpleName());
        Files.createDirectories(lclSftp);

        Path lclFile = lclSftp.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        byte[] expected = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")")
                .getBytes(StandardCharsets.UTF_8);
        ClientSession session;
        FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap());
        try {
            assertTrue("Should be an SftpFileSystem", fs instanceof SftpFileSystem);
            Path remotePath = fs.getPath(CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), lclFile));
            Files.write(remotePath, expected);
            session = ((SftpFileSystem) fs).getClientSession();
        } finally {
            fs.close();
        }
        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
        assertFalse("File system should not be open", fs.isOpen());
        assertFalse("Owned session should not be open", session.isOpen());
    }

    @Test
    public void testSessionRecreate() throws Exception {
        Path targetPath = detectTargetFolder();
        Path lclSftp = CommonTestSupportUtils.resolve(targetPath, SftpConstants.SFTP_SUBSYSTEM_NAME,
                getClass().getSimpleName());
        Files.createDirectories(lclSftp);

        Path lclFile = lclSftp.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(lclFile);
        byte[] expected = (getClass().getName() + "#" + getCurrentTestName() + "(" + new Date() + ")")
                .getBytes(StandardCharsets.UTF_8);
        ClientSession session;
        FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(), Collections.emptyMap());
        try {
            assertTrue("Should be an SftpFileSystem", fs instanceof SftpFileSystem);
            Path remotePath = fs.getPath(CommonTestSupportUtils.resolveRelativeRemotePath(targetPath.getParent(), lclFile));
            Files.write(remotePath, "foo".getBytes(StandardCharsets.US_ASCII));
            session = ((SftpFileSystem) fs).getClientSession();
            session.close();
            Files.write(remotePath, expected);
            ClientSession session2 = ((SftpFileSystem) fs).getClientSession();
            assertNotNull("Expected a session", session2);
            assertNotSame("Expected different sessions", session, session2);
            session = session2;
            assertTrue("Second session should still be open", session.isOpen());
            assertTrue("Recreated session should be owned by the file system",
                    session.getAttribute(SftpFileSystem.OWNED_SESSION));
        } finally {
            fs.close();
        }
        byte[] actual = Files.readAllBytes(lclFile);
        assertArrayEquals("Mismatched persisted data", expected, actual);
        assertFalse("File system should not be open", fs.isOpen());
        assertFalse("Owned session should not be open", session.isOpen());
    }

    @Test
    public void testFileSystemProviderServiceEntry() throws IOException {
        Path configFile = CommonTestSupportUtils.resolve(detectSourcesFolder(),
                MAIN_SUBFOLDER, "filtered-resources", "META-INF", "services", FileSystemProvider.class.getName());
        assertTrue("Missing " + configFile, Files.exists(configFile));

        boolean found = false;
        try (InputStream stream = Files.newInputStream(configFile);
             Reader r = new InputStreamReader(stream, StandardCharsets.UTF_8);
             BufferedReader b = new BufferedReader(r)) {

            for (String line = b.readLine(); line != null; line = b.readLine()) {
                line = line.trim();
                if (GenericUtils.isEmpty(line) || (line.charAt(0) == '#')) {
                    continue;
                }

                assertFalse("Multiple configurations: " + line, found);
                assertEquals("Mismatched configuration", SftpFileSystemProvider.class.getName(), line);
                found = true;
            }
        }

        assertTrue("No configuration found", found);
    }
}
