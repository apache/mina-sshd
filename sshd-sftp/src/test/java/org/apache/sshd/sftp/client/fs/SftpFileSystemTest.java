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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.nio.file.spi.FileSystemProvider;
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
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.MapBuilder;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount")
public class SftpFileSystemTest extends AbstractSftpFilesSystemSupport {
    public SftpFileSystemTest() throws IOException {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setupServer();
    }

    @Test
    public void testFileSystem() throws Exception {
        try (FileSystem fs = FileSystems.newFileSystem(createDefaultFileSystemURI(),
                MapBuilder.<String, Object> builder()
                        .put(SftpModuleProperties.READ_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE)
                        .put(SftpModuleProperties.WRITE_BUFFER_SIZE.getName(), IoUtils.DEFAULT_COPY_SIZE)
                        .build())) {
            assertTrue("Not an SftpFileSystem", fs instanceof SftpFileSystem);
            testFileSystem(fs, ((SftpFileSystem) fs).getVersion());
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
                    err = GenericUtils.accumulateException(err, e);
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
